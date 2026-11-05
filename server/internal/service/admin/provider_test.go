// provider_test.go：admin Provider 写族 service 层单测。fake store /
// fake invalidator 进程内隔离（不连 DB / Redis），注册表用真实两域渠道
//（wechat_mp / smtp / aliyun_sms 经 _ import 触发自注册，§15.3）+ 一个测试
// 专用消息厂商（TestProvider 断言 Send 入参）。覆盖以下用例清单：
// key 字符集拒绝、required 缺失拒绝、未知键处置、create 唯一键冲突、
// update 改 key 拒绝 + 缺省键保留、delete/enabled 不存在 404、sort 批量
// 落库、types 两域并集、test 非 sms/email 拒绝、写后 Invalidate 被调。
package admin_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	adminsvc "authloft/internal/service/admin"
	// 注册表数据源（§15.3）：两域真实注册项驱动 schema 键集与 types 断言。
	_ "authloft/internal/provider/email/smtp"
	_ "authloft/internal/provider/oauth/wechat_mp"
	_ "authloft/internal/provider/sms/aliyun_sms"
)

// —— 测试专用消息厂商（TestProvider 的同步 Send 断言）——

const testAdminSenderType = "admin_test_sender"

var testAdminSender = &fakeSender{}

type fakeSender struct {
	mu     sync.Mutex
	calls  int
	lastTo string
	lastTp string
	params map[string]string
}

func (f *fakeSender) Send(_ context.Context, to, tpl string, params map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastTo, f.lastTp, f.params = to, tpl, params
	return nil
}

func init() {
	provider.RegisterSender(testAdminSenderType, provider.SenderMeta{
		Type: testAdminSenderType, DisplayName: "测试厂商", Category: provider.CategoryEmail,
		Fields: []provider.FieldMeta{{Key: "host", Label: "服务器", Type: "text", Section: "endpoint", Required: true}},
	}, func(*provider.Provider) (provider.Sender, error) { return testAdminSender, nil })
}

// —— fake ProviderStore / fake ProviderInvalidator ——

// fakeStore adminsvc.ProviderStore 的 fake：行按 key 存取，写操作入参全留档。
type fakeStore struct {
	mu          sync.Mutex
	rows        map[string]*model.Provider
	findErr     map[string]error
	createErr   error
	updateErr   error
	sortErr     error
	created     []*model.Provider
	updated     []*model.Provider
	deletedIDs  []int64
	enabledOf   map[int64]int8
	sortUpdates []repo.ProviderSortUpdate
}

func newFakeStore(rows ...*model.Provider) *fakeStore {
	f := &fakeStore{rows: map[string]*model.Provider{}, findErr: map[string]error{}, enabledOf: map[int64]int8{}}
	for _, r := range rows {
		f.rows[r.ProviderKey] = r
	}
	return f
}

func (f *fakeStore) FindByKey(_ context.Context, key string) (*model.Provider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.findErr[key]; ok {
		return nil, err
	}
	row, ok := f.rows[key]
	if !ok {
		return nil, fmt.Errorf("provider repo: find by key: %w", gorm.ErrRecordNotFound)
	}
	return row, nil
}

func (f *fakeStore) Create(_ context.Context, p *model.Provider) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, p)
	return nil
}

func (f *fakeStore) Update(_ context.Context, p *model.Provider) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return f.updateErr
	}
	f.updated = append(f.updated, p)
	return nil
}

func (f *fakeStore) Delete(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletedIDs = append(f.deletedIDs, id)
	return nil
}

func (f *fakeStore) SetEnabled(_ context.Context, id int64, enabled int8) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabledOf[id] = enabled
	return nil
}

func (f *fakeStore) UpdateSortOrders(_ context.Context, updates []repo.ProviderSortUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sortErr != nil {
		return f.sortErr
	}
	f.sortUpdates = append(f.sortUpdates, updates...)
	return nil
}

// fakeInvalidator adminsvc.ProviderInvalidator 的 fake：失效 key 留档断言。
type fakeInvalidator struct {
	mu   sync.Mutex
	keys []string
	err  error
}

func (f *fakeInvalidator) Invalidate(_ context.Context, providerKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.keys = append(f.keys, providerKey)
	return nil
}

func (f *fakeInvalidator) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keys...)
}

// structBody 便捷构造 {"k": "v"} 与标量混合的 Struct 提交体。
func structBody(t *testing.T, kv map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(kv)
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	return s
}

// wechatMpCreateBody 合法的 wechat_mp 新建提交体（§5.3 键集：表列 + oauth
// 追加字段）。
func wechatMpCreateBody(t *testing.T, overrides map[string]any) *structpb.Struct {
	t.Helper()
	body := map[string]any{
		"type":          "wechat_mp",
		"provider_key":  "wx_new",
		"category":      "oauth",
		"display_name":  "微信小程序",
		"client_id":     "wx-appid",
		"client_secret": "wx-secret",
		"is_enabled":    false, // 列级 bool → is_enabled=0
		"sort_order":    30.0,
	}
	for k, v := range overrides {
		if v == nil {
			delete(body, k)
		} else {
			body[k] = v
		}
	}
	return structBody(t, body)
}

// TestCreateProviderValidation 新建校验矩阵（key 字符集拒绝 /
// required 缺失拒绝 / 未知键处置）：空体、缺 type、未注册 type、缺
// provider_key、字符集非法、缺 display_name、required Ext 字段缺失或空串、
// 未知键、category 与注册表不一致，一律 ErrInvalidRequest，且不触碰 store。
func TestCreateProviderValidation(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
	}{
		{"空提交体", nil},
		{"缺 type", map[string]any{"provider_key": "k1", "display_name": "n"}},
		{"未注册 type", map[string]any{"type": "no_such", "provider_key": "k1", "display_name": "n"}},
		{"缺 provider_key", map[string]any{"type": "wechat_mp", "display_name": "n", "client_id": "a", "client_secret": "b"}},
		{"key 字符集大写", map[string]any{"type": "wechat_mp", "provider_key": "BadKey", "display_name": "n", "client_id": "a", "client_secret": "b"}},
		{"key 字符集连字符", map[string]any{"type": "wechat_mp", "provider_key": "bad-key", "display_name": "n", "client_id": "a", "client_secret": "b"}},
		{"key 类型错", map[string]any{"type": "wechat_mp", "provider_key": 123, "display_name": "n", "client_id": "a", "client_secret": "b"}},
		{"缺 display_name", map[string]any{"type": "wechat_mp", "provider_key": "k1", "client_id": "a", "client_secret": "b"}},
		{"required client_id 缺失", map[string]any{"type": "wechat_mp", "provider_key": "k1", "display_name": "n", "client_secret": "b"}},
		{"required client_id 空串", map[string]any{"type": "wechat_mp", "provider_key": "k1", "display_name": "n", "client_id": "", "client_secret": "b"}},
		{"未知键拒绝", map[string]any{"type": "wechat_mp", "provider_key": "k1", "display_name": "n", "client_id": "a", "client_secret": "b", "foo": "bar"}},
		{"category 与注册表不一致", map[string]any{"type": "wechat_mp", "provider_key": "k1", "category": "sms", "display_name": "n", "client_id": "a", "client_secret": "b"}},
		{"列类型不符（checkbox 收字符串）", map[string]any{"type": "wechat_mp", "provider_key": "k1", "display_name": "n", "client_id": "a", "client_secret": "b", "auto_bind": "yes"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			inv := &fakeInvalidator{}
			svc := adminsvc.NewService(store, inv)
			var body *structpb.Struct
			if tc.body != nil {
				body = structBody(t, tc.body)
			}
			if err := svc.CreateProvider(context.Background(), body); !errors.Is(err, adminsvc.ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest", err)
			}
			if len(store.created) != 0 || len(inv.snapshot()) != 0 {
				t.Fatalf("非法请求不得触库 / 失效: created=%d invalidated=%v", len(store.created), inv.snapshot())
			}
		})
	}
}

// TestCreateProviderSuccess 合法新建：行组装（表列 + category 由注册表决定）
// 与 Ext（Marshal → Parse round-trip）逐项落位；显式 is_enabled=false 触发
// default tag 修正（Create 后补一次 Update 落禁用零值）；写后失效恰一次
//（写后 Invalidate 被调）。
func TestCreateProviderSuccess(t *testing.T) {
	store := newFakeStore()
	inv := &fakeInvalidator{}
	svc := adminsvc.NewService(store, inv)

	if err := svc.CreateProvider(context.Background(), wechatMpCreateBody(t, nil)); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	if len(store.created) != 1 {
		t.Fatalf("created = %d, want 1", len(store.created))
	}
	row := store.created[0]
	if row.ProviderKey != "wx_new" || row.Type != "wechat_mp" || row.Category != "oauth" {
		t.Errorf("键 / 类型 / 类别 = (%q, %q, %q)", row.ProviderKey, row.Type, row.Category)
	}
	if row.DisplayName != "微信小程序" || row.SortOrder != 30 {
		t.Errorf("display_name/sort_order = (%q, %d)", row.DisplayName, row.SortOrder)
	}
	// checkbox false → 列 0（列级 bool 映射）。
	if row.IsEnabled != 0 || row.EnableSignin != 0 || row.EnableSignup != 0 {
		t.Errorf("bool 列映射 = (enabled=%d signin=%d signup=%d), want (0,0,0)（提交意图）", row.IsEnabled, row.EnableSignin, row.EnableSignup)
	}
	// 显式 false 提交触发 default tag 修正：Create 后补一次 Update 落禁用零值
	//（repo.Create 契约下 default:1 列的零值会被 tag 值覆盖，须整行重写）。
	if len(store.updated) != 1 {
		t.Fatalf("default tag 修正应补一次 Update: updated = %d, want 1", len(store.updated))
	}
	if fixed := store.updated[0]; fixed.ProviderKey != "wx_new" || fixed.IsEnabled != 0 {
		t.Errorf("修正后行 = (key=%q is_enabled=%d), want (wx_new, 0)", fixed.ProviderKey, fixed.IsEnabled)
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		t.Fatalf("ParseProviderExt: %v", err)
	}
	if ext.GetClientId() != "wx-appid" || ext.GetClientSecret() != "wx-secret" {
		t.Errorf("ext 凭证 = (%q, %q)", ext.GetClientId(), ext.GetClientSecret())
	}
	if keys := inv.snapshot(); len(keys) != 1 || keys[0] != "wx_new" {
		t.Errorf("invalidate = %v, want [wx_new]", keys)
	}
}

// TestCreateProviderNoExplicitCheckboxDefault 全不提交 default:1 checkbox 时
// 不触发修正 Update（落库走 DDL 默认 1，repo.Create 回填），一次 Create 即止。
func TestCreateProviderNoExplicitCheckboxDefault(t *testing.T) {
	store := newFakeStore()
	inv := &fakeInvalidator{}
	svc := adminsvc.NewService(store, inv)

	body := wechatMpCreateBody(t, map[string]any{"is_enabled": nil}) // 移除显式 is_enabled
	if err := svc.CreateProvider(context.Background(), body); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	if len(store.created) != 1 || len(store.updated) != 0 {
		t.Fatalf("created/updated = (%d, %d), want (1, 0)（缺省键不触发修正）", len(store.created), len(store.updated))
	}
	if keys := inv.snapshot(); len(keys) != 1 || keys[0] != "wx_new" {
		t.Errorf("invalidate = %v, want [wx_new]", keys)
	}
}

// TestCreateProviderDuplicateKey uk_provider_key 冲突（create
// 唯一键冲突错误码）→ ErrDuplicateKey，且不失效（行未落库）。
func TestCreateProviderDuplicateKey(t *testing.T) {
	store := newFakeStore()
	store.createErr = fmt.Errorf("provider repo: create: %w: boom", repo.ErrProviderDuplicate)
	inv := &fakeInvalidator{}
	svc := adminsvc.NewService(store, inv)

	if err := svc.CreateProvider(context.Background(), wechatMpCreateBody(t, nil)); !errors.Is(err, adminsvc.ErrDuplicateKey) {
		t.Fatalf("err = %v, want ErrDuplicateKey", err)
	}
	if keys := inv.snapshot(); len(keys) != 0 {
		t.Errorf("冲突不得失效缓存: %v", keys)
	}
}

// wantRowOf service 测试共用行：wechat_mp、含 Ext client_id 原值。
func wantRowOf(t *testing.T) *model.Provider {
	t.Helper()
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{ClientId: "orig-id", ClientSecret: "orig-secret"})
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	return &model.Provider{
		ID: 7, ProviderKey: "wx_exist", DisplayName: "原名", Category: "oauth", Type: "wechat_mp",
		EnableSignin: 1, EnableSignup: 1, IsEnabled: 1, UiGroup: "social", SortOrder: 10,
		AutoBindFields: "email,phone", Remark: "原备注", Ext: ext,
	}
}

// TestUpdateProviderValidation 编辑校验（update 改 key 拒绝）：缺
// provider_key、定位失败、定位键与行现键不一致（防御式「创建后不可改」分支）、
// type / category 提交值与现值不一致、未知键。
func TestUpdateProviderValidation(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(*fakeStore)
		body   map[string]any
		wantID string // 想要的错误类型：invalid / notfound
	}{
		{"缺 provider_key", nil,
			map[string]any{"display_name": "新名"}, "invalid"},
		{"定位键字符集非法", nil,
			map[string]any{"provider_key": "Bad-Key", "display_name": "新名"}, "invalid"},
		{"目标行不存在", nil,
			map[string]any{"provider_key": "missing", "display_name": "新名"}, "notfound"},
		{"改 key：定位键与行现键不一致", func(f *fakeStore) {
			// 防御分支构造：FindByKey 按定位返回行，但行的现 key 与定位不同
			//（生产 FindByKey 语义下不可达，留作列级定位 / 脏数据防御）。
			row := wantRowOf(t)
			row.ProviderKey = "other_key"
			f.rows["wx_exist"] = row
		},
			map[string]any{"provider_key": "wx_exist", "display_name": "新名"}, "invalid"},
		{"改 type", nil,
			map[string]any{"provider_key": "wx_exist", "type": "smtp"}, "invalid"},
		{"改 category", nil,
			map[string]any{"provider_key": "wx_exist", "category": "sms"}, "invalid"},
		{"未知键", nil,
			map[string]any{"provider_key": "wx_exist", "foo": "bar"}, "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore(wantRowOf(t))
			if tc.setup != nil {
				tc.setup(store)
			}
			inv := &fakeInvalidator{}
			svc := adminsvc.NewService(store, inv)
			if err := svc.UpdateProvider(context.Background(), structBody(t, tc.body)); tc.wantID == "invalid" && !errors.Is(err, adminsvc.ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest", err)
			} else if tc.wantID == "notfound" && !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("err = %v, want gorm.ErrRecordNotFound", err)
			}
			if len(store.updated) != 0 || len(inv.snapshot()) != 0 {
				t.Fatalf("非法请求不得落库 / 失效: updated=%d invalidated=%v", len(store.updated), inv.snapshot())
			}
		})
	}
}

// TestUpdateProviderPatchSuccess 缺省键保留原值（PATCH over schema
// 键集——docs 未明说，按默认口径处理）：仅提交 display_name 时
// 其余表列与 Ext 原值不动；提交 Ext 键合并进原 Ext。
func TestUpdateProviderPatchSuccess(t *testing.T) {
	orig := wantRowOf(t)
	store := newFakeStore(orig)
	inv := &fakeInvalidator{}
	svc := adminsvc.NewService(store, inv)

	// 仅改 display_name + 追加 Ext 键：未提交列保留原值。
	body := map[string]any{
		"provider_key": "wx_exist",
		"display_name": "新名",
		"scopes":       "snsapi_login", // Ext 键（oauth meta 声明）
		"auto_bind":    true,
	}
	if err := svc.UpdateProvider(context.Background(), structBody(t, body)); err != nil {
		t.Fatalf("UpdateProvider: %v", err)
	}
	if len(store.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(store.updated))
	}
	row := store.updated[0]
	if row.DisplayName != "新名" {
		t.Errorf("display_name = %q, want 新名", row.DisplayName)
	}
	if row.Type != "wechat_mp" || row.Category != "oauth" || row.UiGroup != "social" ||
		row.SortOrder != 10 || row.Remark != "原备注" || row.EnableSignin != 1 || row.EnableSignup != 1 {
		t.Errorf("缺省键未保留原值: %+v", row)
	}
	if row.AutoBind != 1 || row.AutoBindFields != "email,phone" {
		t.Errorf("auto_bind 映射 = (%d, %q)", row.AutoBind, row.AutoBindFields)
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		t.Fatalf("ParseProviderExt: %v", err)
	}
	if ext.GetClientId() != "orig-id" || ext.GetClientSecret() != "orig-secret" || ext.GetScopes() != "snsapi_login" {
		t.Errorf("Ext 合并 = (client_id=%q secret=%q scopes=%q), want 原值保留 + 新键合并", ext.GetClientId(), ext.GetClientSecret(), ext.GetScopes())
	}
	if keys := inv.snapshot(); len(keys) != 1 || keys[0] != "wx_exist" {
		t.Errorf("invalidate = %v, want [wx_exist]", keys)
	}
}

// TestUpdateProviderTypeSameAsCurrent 提交 type 与现值一致 → 幂等放行（只读键
// 的同值提交不算修改）。
func TestUpdateProviderTypeSameAsCurrent(t *testing.T) {
	store := newFakeStore(wantRowOf(t))
	svc := adminsvc.NewService(store, &fakeInvalidator{})
	body := map[string]any{"provider_key": "wx_exist", "type": "wechat_mp", "category": "oauth", "display_name": "新名"}
	if err := svc.UpdateProvider(context.Background(), structBody(t, body)); err != nil {
		t.Fatalf("同值只读键提交应放行: %v", err)
	}
}

// TestUpdateProviderExtTypeMismatch Ext 键类型不符（checkbox 字段收字符串）
// → invalid_request（protojson 类型校验）。
func TestUpdateProviderExtTypeMismatch(t *testing.T) {
	store := newFakeStore(wantRowOf(t))
	svc := adminsvc.NewService(store, &fakeInvalidator{})
	// wechat_mp Ext 声明集无 bool 键，借表列校验（disable_ssl 是 smtp 的键，
	// 不在 wechat_mp 键集 → 未知键拒绝）；此处用合法键但错型：user_mapping
	// 是 map 字段，提交字符串 → protojson 报错。
	body := map[string]any{"provider_key": "wx_exist", "user_mapping": "not-an-object"}
	if err := svc.UpdateProvider(context.Background(), structBody(t, body)); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Fatalf("err = %v, want ErrInvalidRequest", err)
	}
}

// TestDeleteProvider 删除：成功（Delete(id) + 失效）与不存在 404。
func TestDeleteProvider(t *testing.T) {
	ctx := context.Background()
	t.Run("成功", func(t *testing.T) {
		store := newFakeStore(wantRowOf(t))
		inv := &fakeInvalidator{}
		svc := adminsvc.NewService(store, inv)
		if err := svc.DeleteProvider(ctx, "wx_exist"); err != nil {
			t.Fatalf("DeleteProvider: %v", err)
		}
		if len(store.deletedIDs) != 1 || store.deletedIDs[0] != 7 {
			t.Errorf("deleted = %v, want [7]", store.deletedIDs)
		}
		if keys := inv.snapshot(); len(keys) != 1 || keys[0] != "wx_exist" {
			t.Errorf("invalidate = %v", keys)
		}
	})
	t.Run("不存在 404", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{})
		if err := svc.DeleteProvider(ctx, "missing"); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("err = %v, want gorm.ErrRecordNotFound", err)
		}
	})
	t.Run("空 key", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{})
		if err := svc.DeleteProvider(ctx, ""); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
}

// TestSetProviderEnabled 行内开关：true/false 列级落 1/0 + 失效；不存在 404
//（delete/enabled 不存在 404）。
func TestSetProviderEnabled(t *testing.T) {
	ctx := context.Background()
	t.Run("禁用 false", func(t *testing.T) {
		store := newFakeStore(wantRowOf(t))
		inv := &fakeInvalidator{}
		svc := adminsvc.NewService(store, inv)
		if err := svc.SetProviderEnabled(ctx, "wx_exist", false); err != nil {
			t.Fatalf("SetProviderEnabled: %v", err)
		}
		if v := store.enabledOf[7]; v != 0 {
			t.Errorf("is_enabled = %d, want 0（false → 0）", v)
		}
		if keys := inv.snapshot(); len(keys) != 1 || keys[0] != "wx_exist" {
			t.Errorf("invalidate = %v", keys)
		}
	})
	t.Run("启用 true", func(t *testing.T) {
		store := newFakeStore(wantRowOf(t))
		svc := adminsvc.NewService(store, &fakeInvalidator{})
		if err := svc.SetProviderEnabled(ctx, "wx_exist", true); err != nil {
			t.Fatalf("SetProviderEnabled: %v", err)
		}
		if v := store.enabledOf[7]; v != 1 {
			t.Errorf("is_enabled = %d, want 1", v)
		}
	})
	t.Run("不存在 404", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{})
		if err := svc.SetProviderEnabled(ctx, "missing", true); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("err = %v, want gorm.ErrRecordNotFound", err)
		}
	})
}

// TestSortProviders 批量排序（sort 批量落库）：空 items 拒绝、非法
// key 拒绝、成功批量透传 + 逐 key 失效、含不存在 key 透传 not found。
func TestSortProviders(t *testing.T) {
	ctx := context.Background()
	t.Run("空 items", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{})
		if err := svc.SortProviders(ctx, nil); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("非法 key", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{})
		if err := svc.SortProviders(ctx, []adminsvc.SortItem{{ProviderKey: "Bad-Key", SortOrder: 1}}); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("批量落库 + 逐 key 失效", func(t *testing.T) {
		store := newFakeStore(wantRowOf(t))
		inv := &fakeInvalidator{}
		svc := adminsvc.NewService(store, inv)
		items := []adminsvc.SortItem{
			{ProviderKey: "wx_exist", SortOrder: 30},
			{ProviderKey: "smtp_exist", SortOrder: 10},
		}
		if err := svc.SortProviders(ctx, items); err != nil {
			t.Fatalf("SortProviders: %v", err)
		}
		if len(store.sortUpdates) != 2 ||
			store.sortUpdates[0].ProviderKey != "wx_exist" || store.sortUpdates[0].SortOrder != 30 ||
			store.sortUpdates[1].ProviderKey != "smtp_exist" || store.sortUpdates[1].SortOrder != 10 {
			t.Errorf("批量落库入参 = %+v", store.sortUpdates)
		}
		if keys := inv.snapshot(); len(keys) != 2 || keys[0] != "wx_exist" || keys[1] != "smtp_exist" {
			t.Errorf("逐 key 失效 = %v, want [wx_exist smtp_exist]（按 items 序）", keys)
		}
	})
	t.Run("不存在 key 透传 not found", func(t *testing.T) {
		store := newFakeStore()
		store.sortErr = fmt.Errorf("provider repo: update sort orders: key %q: %w", "missing", gorm.ErrRecordNotFound)
		svc := adminsvc.NewService(store, &fakeInvalidator{})
		err := svc.SortProviders(ctx, []adminsvc.SortItem{{ProviderKey: "missing", SortOrder: 1}})
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("err = %v, want gorm.ErrRecordNotFound", err)
		}
	})
}

// TestProviderTypes 两域并集：oauth 域 wechat_mp + 消息域 smtp /
// aliyun_sms 全部出现，type 稳定升序，category 由注册表决定。
func TestProviderTypes(t *testing.T) {
	svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{})
	got := svc.ProviderTypes()

	byType := map[string]adminsvc.ProviderTypeInfo{}
	for _, info := range got {
		byType[info.Type] = info
	}
	for _, want := range []adminsvc.ProviderTypeInfo{
		{Type: "wechat_mp", Category: "oauth", DisplayName: "微信小程序"},
		{Type: "smtp", Category: "email", DisplayName: "SMTP（通用）"},
		{Type: "aliyun_sms", Category: "sms", DisplayName: "阿里云短信"},
	} {
		g, ok := byType[want.Type]
		if !ok {
			t.Fatalf("types 缺少 %q: %v", want.Type, got)
		}
		if g != want {
			t.Errorf("type %q = %+v, want %+v", want.Type, g, want)
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Type >= got[i].Type {
			t.Errorf("type 未稳定排序: %q >= %q", got[i-1].Type, got[i].Type)
		}
	}
}

// TestTestProvider 发送测试（test 非 sms/email 拒绝）：oauth 类别
// 拒绝、空 target 拒绝、不存在 404、email 厂商同步 Send 收到 (target, "test",
// {"code":"test"})——tpl/params 口径 docs 未细化，按默认处理。
func TestTestProvider(t *testing.T) {
	ctx := context.Background()
	emailRow := &model.Provider{ID: 9, ProviderKey: "smtp_exist", Category: "email", Type: testAdminSenderType, IsEnabled: 1}
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{Host: "smtp.example.com"})
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	emailRow.Ext = ext

	t.Run("非 sms/email 类别拒绝", func(t *testing.T) {
		store := newFakeStore(wantRowOf(t)) // category=oauth
		svc := adminsvc.NewService(store, &fakeInvalidator{})
		if err := svc.TestProvider(ctx, "wx_exist", "alice@example.com"); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest（oauth 类别不可测试发送）", err)
		}
	})
	t.Run("空 target 拒绝", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(emailRow), &fakeInvalidator{})
		if err := svc.TestProvider(ctx, "smtp_exist", ""); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("不存在 404", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{})
		if err := svc.TestProvider(ctx, "missing", "a@b.c"); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("err = %v, want gorm.ErrRecordNotFound", err)
		}
	})
	t.Run("Ext 配置缺失拒绝", func(t *testing.T) {
		// 行 type 未注册为消息厂商（oauth 渠道名 + email 类别脏数据）→
		// NewSender ErrChannelNotConfigured → invalid_request。
		dirty := &model.Provider{ID: 10, ProviderKey: "dirty", Category: "email", Type: "wechat_mp", IsEnabled: 1}
		svc := adminsvc.NewService(newFakeStore(dirty), &fakeInvalidator{})
		if err := svc.TestProvider(ctx, "dirty", "a@b.c"); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest（厂商构造失败 = 配置状态）", err)
		}
	})
	t.Run("同步 Send 收到测试模板入参", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(emailRow), &fakeInvalidator{})
		if err := svc.TestProvider(ctx, "smtp_exist", "alice@example.com"); err != nil {
			t.Fatalf("TestProvider: %v", err)
		}
		testAdminSender.mu.Lock()
		defer testAdminSender.mu.Unlock()
		if testAdminSender.calls == 0 {
			t.Fatal("同步 Send 未被调用（不经 asyncqueue，管理员即时反馈）")
		}
		if testAdminSender.lastTo != "alice@example.com" || testAdminSender.lastTp != "test" ||
			testAdminSender.params["code"] != "test" {
			t.Errorf("Send 入参 = (to=%q tpl=%q params=%v)", testAdminSender.lastTo, testAdminSender.lastTp, testAdminSender.params)
		}
	})
}

// TestNewServiceFailFast 依赖缺失 fail-fast（程序错误）。
func TestNewServiceFailFast(t *testing.T) {
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: NewService must panic", name)
			}
		}()
		fn()
	}
	mustPanic("nil store", func() { adminsvc.NewService(nil, &fakeInvalidator{}) })
	mustPanic("nil invalidator", func() { adminsvc.NewService(newFakeStore(), nil) })
}
