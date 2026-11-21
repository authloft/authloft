// provider_test.go：admin Provider 写族 service 层单测。fake store /
// fake invalidator 进程内隔离（不连 DB / Redis），注册表用真实两域渠道
// （wechat_mp / wechat_mp_scan / smtp / aliyun_sms 经 _ import 触发自注册，
// §15.3）+ 一个测试专用消息厂商（TestProvider 断言 Send 入参）。覆盖以下用例清单：
// key 字符集拒绝、required 缺失拒绝、未知键处置、create 唯一键冲突、
// update 改 key 拒绝 + 缺省键保留、delete/enabled 不存在 404、sort 批量
// 落库、types 两域并集、test 非 sms/email 拒绝、写后 Invalidate 被调、
// proxy 行五字段组合校验与 trim 回写、引用键字符集与呈现范围（键集白名单）、
// TestProvider 引用解析直连 / 代理两路径。
package admin_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"database/sql"
	"google.golang.org/protobuf/types/known/structpb"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/proxyclient"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	adminsvc "authloft/internal/service/admin"
	// 注册表数据源（§15.3）：各域真实注册项驱动 schema 键集与 types 断言；
	// captcha 三家 meta 随工厂化迁入实现子包，blank import 触发 init 自注册
	//（测试二进制无触发即 meta 缺失，CODE_GUIDE §3.3）。
	_ "authloft/internal/provider/auth/wechat_mp"
	_ "authloft/internal/provider/auth/wechat_mp_scan"
	_ "authloft/internal/provider/captcha/hcaptcha"
	_ "authloft/internal/provider/captcha/recaptcha"
	_ "authloft/internal/provider/captcha/turnstile"
	_ "authloft/internal/provider/email/smtp"
	_ "authloft/internal/provider/proxy/basic"
	_ "authloft/internal/provider/sms/aliyun_sms"
	_ "authloft/internal/provider/storage/local"
)

// schemaFieldsOf nil 安全地取 meta.Schema()（Schema 为 func 字段，nil = 无声明）。
func schemaFieldsOf(schema func() []provider.FieldMeta) []provider.FieldMeta {
	if schema == nil {
		return nil
	}
	return schema()
}

// —— 测试专用消息厂商（TestProvider 的同步 Send 断言）——

const testAdminSenderType = "admin_test_sender"

var testAdminSender = &fakeSender{}

type fakeSender struct {
	mu       sync.Mutex
	calls    int
	lastTo   string
	lastTp   string
	params   map[string]string
	lastProv *provider.Provider // 工厂收到的实例（TestProvider 引用解析断言用）
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
	}, func(p *provider.Provider) (provider.Sender, error) {
		testAdminSender.mu.Lock()
		testAdminSender.lastProv = p
		testAdminSender.mu.Unlock()
		return testAdminSender, nil
	})
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
		return nil, fmt.Errorf("provider repo: find by key: %w", sql.ErrNoRows)
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

// wechatMpCreateBody 合法的 wechat_mp 新建提交体（§5.3 keep 集表：表列 +
// app_id / client_secret 凭证键集）。
func wechatMpCreateBody(t *testing.T, overrides map[string]any) *structpb.Struct {
	t.Helper()
	body := map[string]any{
		"type":          "wechat_mp",
		"provider_key":  "wx_new",
		"category":      "auth",
		"display_name":  "微信小程序",
		"app_id":        "wx-appid",
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
		{"缺 provider_key", map[string]any{"type": "wechat_mp", "display_name": "n", "app_id": "a", "client_secret": "b"}},
		{"key 字符集大写", map[string]any{"type": "wechat_mp", "provider_key": "BadKey", "display_name": "n", "app_id": "a", "client_secret": "b"}},
		{"key 字符集连字符", map[string]any{"type": "wechat_mp", "provider_key": "bad-key", "display_name": "n", "app_id": "a", "client_secret": "b"}},
		{"key 类型错", map[string]any{"type": "wechat_mp", "provider_key": 123, "display_name": "n", "app_id": "a", "client_secret": "b"}},
		{"缺 display_name", map[string]any{"type": "wechat_mp", "provider_key": "k1", "app_id": "a", "client_secret": "b"}},
		{"required app_id 缺失", map[string]any{"type": "wechat_mp", "provider_key": "k1", "display_name": "n", "client_secret": "b"}},
		{"required app_id 空串", map[string]any{"type": "wechat_mp", "provider_key": "k1", "display_name": "n", "app_id": "", "client_secret": "b"}},
		{"未知键拒绝", map[string]any{"type": "wechat_mp", "provider_key": "k1", "display_name": "n", "app_id": "a", "client_secret": "b", "foo": "bar"}},
		{"category 与注册表不一致", map[string]any{"type": "wechat_mp", "provider_key": "k1", "category": "sms", "display_name": "n", "app_id": "a", "client_secret": "b"}},
		{"列类型不符（checkbox 收字符串）", map[string]any{"type": "wechat_mp", "provider_key": "k1", "display_name": "n", "app_id": "a", "client_secret": "b", "auto_bind": "yes"}},
		{"死键拒绝（client_id 已收敛出键集）", map[string]any{"type": "wechat_mp", "provider_key": "k1", "display_name": "n", "app_id": "a", "client_secret": "b", "client_id": "dead"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			inv := &fakeInvalidator{}
			svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
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
// （写后 Invalidate 被调）。
func TestCreateProviderSuccess(t *testing.T) {
	store := newFakeStore()
	inv := &fakeInvalidator{}
	svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())

	if err := svc.CreateProvider(context.Background(), wechatMpCreateBody(t, nil)); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	if len(store.created) != 1 {
		t.Fatalf("created = %d, want 1", len(store.created))
	}
	row := store.created[0]
	if row.ProviderKey != "wx_new" || row.Type != "wechat_mp" || row.Category != "auth" {
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
	if ext.GetAppId() != "wx-appid" || ext.GetClientSecret() != "wx-secret" {
		t.Errorf("ext 凭证 = (%q, %q)", ext.GetAppId(), ext.GetClientSecret())
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
	svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())

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
	svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())

	if err := svc.CreateProvider(context.Background(), wechatMpCreateBody(t, nil)); !errors.Is(err, adminsvc.ErrDuplicateKey) {
		t.Fatalf("err = %v, want ErrDuplicateKey", err)
	}
	if keys := inv.snapshot(); len(keys) != 0 {
		t.Errorf("冲突不得失效缓存: %v", keys)
	}
}

// wantRowOf service 测试共用行：wechat_mp、含 Ext app_id 原值。
func wantRowOf(t *testing.T) *model.Provider {
	t.Helper()
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{AppId: "orig-id", ClientSecret: "orig-secret"})
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	return &model.Provider{
		ID: 7, ProviderKey: "wx_exist", DisplayName: "原名", Category: "auth", Type: "wechat_mp",
		EnableSignin: 1, EnableSignup: 1, IsEnabled: 1, SortOrder: 10,
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
			svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
			if err := svc.UpdateProvider(context.Background(), structBody(t, tc.body)); tc.wantID == "invalid" && !errors.Is(err, adminsvc.ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest", err)
			} else if tc.wantID == "notfound" && !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("err = %v, want sql.ErrNoRows", err)
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
	svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())

	// 仅改 display_name + 追加 Ext 键：未提交列保留原值。
	body := map[string]any{
		"provider_key": "wx_exist",
		"display_name": "新名",
		"app_id":       "new-app-id", // Ext 键（wechat_mp 声明集）
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
	if row.Type != "wechat_mp" || row.Category != "auth" ||
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
	if ext.GetAppId() != "new-app-id" || ext.GetClientSecret() != "orig-secret" {
		t.Errorf("Ext 合并 = (app_id=%q secret=%q), want 新键合并 + 原值保留", ext.GetAppId(), ext.GetClientSecret())
	}
	if keys := inv.snapshot(); len(keys) != 1 || keys[0] != "wx_exist" {
		t.Errorf("invalidate = %v, want [wx_exist]", keys)
	}
}

// TestUpdateProviderTypeSameAsCurrent 提交 type 与现值一致 → 幂等放行（只读键
// 的同值提交不算修改）。
func TestUpdateProviderTypeSameAsCurrent(t *testing.T) {
	store := newFakeStore(wantRowOf(t))
	svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
	body := map[string]any{"provider_key": "wx_exist", "type": "wechat_mp", "category": "auth", "display_name": "新名"}
	if err := svc.UpdateProvider(context.Background(), structBody(t, body)); err != nil {
		t.Fatalf("同值只读键提交应放行: %v", err)
	}
}

// TestUpdateProviderExtTypeMismatch Ext 键类型不符（checkbox 字段收字符串）
// → invalid_request（protojson 类型校验）。
func TestUpdateProviderExtTypeMismatch(t *testing.T) {
	// wechat_mp 收敛后 Ext 声明集全为字符串键；bool Ext 键取 wechat_mp_scan 的
	// qrcode_auto_delete：提交字符串 → protojson 报错。
	row := wantRowOf(t)
	row.Type = "wechat_mp_scan"
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{AppId: "orig-id", ClientSecret: "orig-secret"})
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	row.Ext = ext
	store := newFakeStore(row)
	svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
	body := map[string]any{"provider_key": "wx_exist", "qrcode_auto_delete": "not-a-bool"}
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
		svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
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
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.DeleteProvider(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("err = %v, want sql.ErrNoRows", err)
		}
	})
	t.Run("空 key", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.DeleteProvider(ctx, ""); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
}

// TestSetProviderEnabled 行内开关：true/false 列级落 1/0 + 失效；不存在 404
// （delete/enabled 不存在 404）。
func TestSetProviderEnabled(t *testing.T) {
	ctx := context.Background()
	t.Run("禁用 false", func(t *testing.T) {
		store := newFakeStore(wantRowOf(t))
		inv := &fakeInvalidator{}
		svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
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
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.SetProviderEnabled(ctx, "wx_exist", true); err != nil {
			t.Fatalf("SetProviderEnabled: %v", err)
		}
		if v := store.enabledOf[7]; v != 1 {
			t.Errorf("is_enabled = %d, want 1", v)
		}
	})
	t.Run("不存在 404", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.SetProviderEnabled(ctx, "missing", true); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("err = %v, want sql.ErrNoRows", err)
		}
	})
}

// TestSortProviders 批量排序（sort 批量落库）：空 items 拒绝、非法
// key 拒绝、成功批量透传 + 逐 key 失效、含不存在 key 透传 not found。
func TestSortProviders(t *testing.T) {
	ctx := context.Background()
	t.Run("空 items", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.SortProviders(ctx, nil); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("非法 key", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.SortProviders(ctx, []adminsvc.SortItem{{ProviderKey: "Bad-Key", SortOrder: 1}}); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("批量落库 + 逐 key 失效", func(t *testing.T) {
		store := newFakeStore(wantRowOf(t))
		inv := &fakeInvalidator{}
		svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
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
		store.sortErr = fmt.Errorf("provider repo: update sort orders: key %q: %w", "missing", sql.ErrNoRows)
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		err := svc.SortProviders(ctx, []adminsvc.SortItem{{ProviderKey: "missing", SortOrder: 1}})
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("err = %v, want sql.ErrNoRows", err)
		}
	})
}

// TestProviderTypes 静态源并集：oauth 域 wechat_mp + 消息域 smtp /
// aliyun_sms + 虚拟 Union + 服务型 captcha/storage 全部出现，type 稳定升序，
// category 由 meta 决定。
func TestProviderTypes(t *testing.T) {
	svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{}, proxyclient.NewPoolSet())
	got := svc.ProviderTypes()

	byType := map[string]adminsvc.ProviderTypeInfo{}
	for _, info := range got {
		byType[info.Type] = info
	}
	for _, want := range []adminsvc.ProviderTypeInfo{
		{Type: "wechat_mp", Category: "auth", DisplayName: "微信小程序"},
		{Type: "smtp", Category: "email", DisplayName: "SMTP（通用）"},
		{Type: "aliyun_sms", Category: "sms", DisplayName: "阿里云短信"},
		// 虚拟 Union 类型：静态 meta-only 源，管理后台新建下拉可见。
		{Type: provider.UnionProviderType, Category: provider.CategoryUnion, DisplayName: "Union ID 归并（虚拟）"},
		// 服务型类型：captcha / storage 静态 meta，同样进下拉。
		{Type: provider.CaptchaTypeTurnstile, Category: provider.CategoryCaptcha, DisplayName: "Cloudflare Turnstile"},
		{Type: provider.CaptchaTypeRecaptcha, Category: provider.CategoryCaptcha, DisplayName: "Google reCAPTCHA"},
		{Type: provider.CaptchaTypeHcaptcha, Category: provider.CategoryCaptcha, DisplayName: "hCaptcha"},
		{Type: provider.StorageTypeLocal, Category: provider.CategoryStorage, DisplayName: "本地存储"},
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

// TestCreateUnionProvider 管理后台可新建虚拟 Union Provider：type=unionid
// 由第三源 meta 命中，落行 category=union / type=unionid、无 Ext 必填项，
// 写后缓存失效照常触发。该行随后会出现在 oauth 表单 union_provider 下拉。
func TestCreateUnionProvider(t *testing.T) {
	store := newFakeStore()
	inv := &fakeInvalidator{}
	svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
	body := structBody(t, map[string]any{
		"type":         provider.UnionProviderType,
		"provider_key": "wechat_union",
		"category":     provider.CategoryUnion,
		"display_name": "微信 Union 归并",
	})
	if err := svc.CreateProvider(context.Background(), body); err != nil {
		t.Fatalf("CreateProvider(unionid): %v", err)
	}
	if len(store.created) != 1 {
		t.Fatalf("created = %d, want 1", len(store.created))
	}
	row := store.created[0]
	if row.ProviderKey != "wechat_union" || row.Type != provider.UnionProviderType ||
		row.Category != provider.CategoryUnion || row.DisplayName != "微信 Union 归并" {
		t.Errorf("落行 = %+v", row)
	}
	if keys := inv.snapshot(); len(keys) != 1 || keys[0] != "wechat_union" {
		t.Errorf("失效 key = %v, want [wechat_union]", keys)
	}
}

// TestCreateServiceProvider 管理后台可新建服务型 Provider：captcha / storage
// 的 type 由第四源静态 meta 命中，落行 category 正确、Ext 字段按 meta 声明
// 落库、写后缓存失效触发。这是 GetProviderTypes → GetProviderSchema → Create
// 全链路打通的核心回归点。
func TestCreateServiceProvider(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      map[string]any
		wantCat   string
		wantType  string
		assertExt func(t *testing.T, ext *providerpb.Ext)
	}{
		{
			name: "captcha turnstile",
			body: map[string]any{
				"type": provider.CaptchaTypeTurnstile, "provider_key": "cap_turn",
				"category": provider.CategoryCaptcha, "display_name": "Turnstile",
				"client_id": "site-1", "client_secret": "sec-1",
			},
			wantCat: provider.CategoryCaptcha, wantType: provider.CaptchaTypeTurnstile,
			assertExt: func(t *testing.T, ext *providerpb.Ext) {
				if ext.GetClientId() != "site-1" || ext.GetClientSecret() != "sec-1" {
					t.Errorf("captcha ext = %+v", ext)
				}
			},
		},
		{
			name: "storage local",
			body: map[string]any{
				"type": provider.StorageTypeLocal, "provider_key": "store_local",
				"category": provider.CategoryStorage, "display_name": "本地存储",
				"bucket": "/data/authloft", "domain": "https://cdn.example.com",
			},
			wantCat: provider.CategoryStorage, wantType: provider.StorageTypeLocal,
			assertExt: func(t *testing.T, ext *providerpb.Ext) {
				if ext.GetBucket() != "/data/authloft" || ext.GetDomain() != "https://cdn.example.com" {
					t.Errorf("storage ext = %+v", ext)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			inv := &fakeInvalidator{}
			svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
			if err := svc.CreateProvider(context.Background(), structBody(t, tc.body)); err != nil {
				t.Fatalf("CreateProvider: %v", err)
			}
			if len(store.created) != 1 {
				t.Fatalf("created = %d, want 1", len(store.created))
			}
			row := store.created[0]
			if row.Type != tc.wantType || row.Category != tc.wantCat {
				t.Errorf("落行 = %+v, want type=%q category=%q", row, tc.wantType, tc.wantCat)
			}
			ext, err := repo.ParseProviderExt(row.Ext)
			if err != nil {
				t.Fatalf("ParseProviderExt: %v", err)
			}
			tc.assertExt(t, ext)
			if keys := inv.snapshot(); len(keys) != 1 || keys[0] != tc.body["provider_key"] {
				t.Errorf("失效 key = %v", keys)
			}
		})
	}
}

// TestCreateServiceProviderRequired 服务型 meta 的 required 字段缺失拒绝：
// captcha 缺 client_secret、storage/local 缺 domain 均不得落库。
func TestCreateServiceProviderRequired(t *testing.T) {
	for _, body := range []map[string]any{
		{"type": provider.CaptchaTypeTurnstile, "provider_key": "cap", "category": provider.CategoryCaptcha,
			"display_name": "C", "client_id": "site"},
		{"type": provider.StorageTypeLocal, "provider_key": "store", "category": provider.CategoryStorage,
			"display_name": "S", "bucket": "/data"},
	} {
		store := newFakeStore()
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.CreateProvider(context.Background(), structBody(t, body)); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Errorf("缺失 required: err = %v, want ErrInvalidRequest (body %v)", err, body)
		}
		if len(store.created) != 0 {
			t.Errorf("非法请求不得落库: %v", body)
		}
	}
}

// TestCreateProviderCategoryColumnKeys 按 category 裁剪写入白名单：5 个
// oauth 专属列对 sms/email/union 提交一律 invalid_request（且零落库），
// oauth 提交同名列仍可通过（回归防线，防止过度裁剪）。
func TestCreateProviderCategoryColumnKeys(t *testing.T) {
	oauthOnly := []string{
		"union_provider", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields",
	}
	smtpBody := map[string]any{
		"type": "smtp", "provider_key": "smtp_1", "category": provider.CategoryEmail,
		"display_name": "SMTP", "host": "smtp.example.com", "from": "noreply@example.com",
		"user": "u1", "password": "p1",
	}
	for _, key := range oauthOnly {
		t.Run("email 拒绝 "+key, func(t *testing.T) {
			store := newFakeStore()
			svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
			body := map[string]any{}
			for k, v := range smtpBody {
				body[k] = v
			}
			body[key] = true
			if err := svc.CreateProvider(context.Background(), structBody(t, body)); !errors.Is(err, adminsvc.ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest", err)
			}
			if len(store.created) != 0 {
				t.Fatal("非法请求不得落库")
			}
		})
	}
	t.Run("union 拒绝 oauth 专属列", func(t *testing.T) {
		store := newFakeStore()
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		body := structBody(t, map[string]any{
			"type": provider.UnionProviderType, "provider_key": "u1",
			"category": provider.CategoryUnion, "display_name": "U", "enable_signin": true,
		})
		if err := svc.CreateProvider(context.Background(), body); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("union 拒绝 is_enabled", func(t *testing.T) {
		// 虚拟 Provider 无 adapter / 无登录入口，启用开关没有可开关的行为：
		// schema 不下发、提交即未知键（与「表单外键一律 invalid_request」同口径）。
		store := newFakeStore()
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		body := structBody(t, map[string]any{
			"type": provider.UnionProviderType, "provider_key": "u1",
			"category": provider.CategoryUnion, "display_name": "U", "is_enabled": false,
		})
		if err := svc.CreateProvider(context.Background(), body); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
		if len(store.created) != 0 {
			t.Fatal("非法请求不得落库")
		}
	})
	t.Run("email 拒绝 is_enabled", func(t *testing.T) {
		// is_enabled 是 oauth 专属：sms / email 行不声明也不消费（渠道生效由
		// §5.6 settings 键决定），提交该键即未知键 invalid_request。
		store := newFakeStore()
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		body := map[string]any{}
		for k, v := range smtpBody {
			body[k] = v
		}
		body["is_enabled"] = false
		if err := svc.CreateProvider(context.Background(), structBody(t, body)); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("email 提交 is_enabled 应拒绝: %v", err)
		}
		if len(store.created) != 0 {
			t.Fatal("非法请求不得落库")
		}
	})
	t.Run("oauth 允许 oauth 专属列", func(t *testing.T) {
		store := newFakeStore()
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		overrides := map[string]any{"auto_bind": true, "union_provider": "wechat_union"}
		if err := svc.CreateProvider(context.Background(), wechatMpCreateBody(t, overrides)); err != nil {
			t.Fatalf("oauth 提交 oauth 专属列应通过: %v", err)
		}
		if store.created[0].AutoBind != 1 || store.created[0].UnionProvider != "wechat_union" {
			t.Errorf("落行 = %+v（oauth 专属列应写入）", store.created[0])
		}
	})
}

// TestUpdateUnionProvider 编辑虚拟 Union Provider：type=unionid 由第三源
// meta 命中（旧实现会报 unregistered type），通用列可改、oauth 专属列拒绝。
func TestUpdateUnionProvider(t *testing.T) {
	row := &model.Provider{
		ID: 7, ProviderKey: "wechat_union", DisplayName: "原名",
		Category: provider.CategoryUnion, Type: provider.UnionProviderType, IsEnabled: 1,
	}
	store := newFakeStore(row)
	svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
	if err := svc.UpdateProvider(context.Background(), structBody(t, map[string]any{
		"provider_key": "wechat_union", "display_name": "新名",
	})); err != nil {
		t.Fatalf("UpdateProvider(unionid): %v", err)
	}
	if len(store.updated) != 1 || store.updated[0].DisplayName != "新名" {
		t.Errorf("updated = %+v", store.updated)
	}
	if err := svc.UpdateProvider(context.Background(), structBody(t, map[string]any{
		"provider_key": "wechat_union", "enable_signin": true,
	})); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest（union 不接受 oauth 专属列）", err)
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
		store := newFakeStore(wantRowOf(t)) // category=auth
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.TestProvider(ctx, "wx_exist", "alice@example.com"); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest（oauth 类别不可测试发送）", err)
		}
	})
	t.Run("空 target 拒绝", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(emailRow), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.TestProvider(ctx, "smtp_exist", ""); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("不存在 404", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.TestProvider(ctx, "missing", "a@b.c"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("err = %v, want sql.ErrNoRows", err)
		}
	})
	t.Run("Ext 配置缺失拒绝", func(t *testing.T) {
		// 行 type 未注册为消息厂商（oauth 渠道名 + email 类别脏数据）→
		// NewSender ErrChannelNotConfigured → invalid_request。
		dirty := &model.Provider{ID: 10, ProviderKey: "dirty", Category: "email", Type: "wechat_mp", IsEnabled: 1}
		svc := adminsvc.NewService(newFakeStore(dirty), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.TestProvider(ctx, "dirty", "a@b.c"); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest（厂商构造失败 = 配置状态）", err)
		}
	})
	t.Run("同步 Send 收到测试模板入参", func(t *testing.T) {
		svc := adminsvc.NewService(newFakeStore(emailRow), &fakeInvalidator{}, proxyclient.NewPoolSet())
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
	mustPanic("nil store", func() { adminsvc.NewService(nil, &fakeInvalidator{}, proxyclient.NewPoolSet()) })
	mustPanic("nil invalidator", func() { adminsvc.NewService(newFakeStore(), nil, proxyclient.NewPoolSet()) })
	mustPanic("nil pools", func() { adminsvc.NewService(newFakeStore(), &fakeInvalidator{}, nil) })
}

// proxyRowOf 测试用 category=proxy 行：socks5 固定 host，按 port / 凭据区分场景。
func proxyRowOf(t *testing.T, key string, enabled int8) *model.Provider {
	t.Helper()
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{Scheme: "socks5", Host: "10.0.0.8", Port: 1080})
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	return &model.Provider{ID: 20, ProviderKey: key, Category: provider.CategoryProxy, Type: provider.ProxyType,
		IsEnabled: enabled, Ext: ext}
}

// emailRowWithRef email 测试行：ext 携带 proxy_provider_key（TestProvider 引用解析）。
func emailRowWithRef(t *testing.T, key, ref string) *model.Provider {
	t.Helper()
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{Host: "smtp.example.com", ProxyProviderKey: ref})
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	return &model.Provider{ID: 21, ProviderKey: key, Category: "email", Type: testAdminSenderType,
		IsEnabled: 1, Ext: ext}
}

// proxyCreateBody type=proxy 合法新建提交体基线（overrides 覆盖 / nil 删除）。
func proxyCreateBody(t *testing.T, overrides map[string]any) *structpb.Struct {
	t.Helper()
	body := map[string]any{
		"type": provider.ProxyType, "provider_key": "pxy_new",
		"category": provider.CategoryProxy, "display_name": "出站代理",
		"scheme": "socks5", "host": " 127.0.0.1 ", "port": 1080.0,
		"user": " u1 ", "password": " p1 ",
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

// TestCreateProviderProxyRow proxy 行合法保存：五真实字段落 Ext，scheme / host /
// user / password trim 回写（不保留首尾空白，§5.3），port 原值；写后失效触发。
func TestCreateProviderProxyRow(t *testing.T) {
	store := newFakeStore()
	inv := &fakeInvalidator{}
	svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
	if err := svc.CreateProvider(context.Background(), proxyCreateBody(t, nil)); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	if len(store.created) != 1 {
		t.Fatalf("created = %d, want 1", len(store.created))
	}
	row := store.created[0]
	if row.Category != provider.CategoryProxy || row.Type != provider.ProxyType {
		t.Errorf("落行 = (%q, %q), want (proxy, proxy)", row.Category, row.Type)
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		t.Fatalf("ParseProviderExt: %v", err)
	}
	if ext.GetScheme() != "socks5" || ext.GetHost() != "127.0.0.1" || ext.GetPort() != 1080 ||
		ext.GetUser() != "u1" || ext.GetPassword() != "p1" {
		t.Errorf("ext trim 回写 = %+v", ext)
	}
	if keys := inv.snapshot(); len(keys) != 1 || keys[0] != "pxy_new" {
		t.Errorf("invalidate = %v, want [pxy_new]", keys)
	}
}

// TestCreateProviderProxyInvalidCombos proxy 行组合非法拒绝（§5.3：校验单一来源
// proxyclient.NewConfig，保存期对合并后的 Ext 统一执行）：scheme 封闭集外 / host
// 缺失或含禁用字符 / port 越界 / password 无 user，一律 ErrInvalidRequest 且零落库；
// port 缺失与 port=0 由 required 校验的 number-aware 缺省判定拒绝（§5.3 五字段表
// port 必填），70000 由组合校验拒绝。
func TestCreateProviderProxyInvalidCombos(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]any
	}{
		{"scheme 封闭集外", map[string]any{"scheme": "ftp"}},
		{"scheme 大小写", map[string]any{"scheme": "SOCKS5"}},
		{"host 缺失", map[string]any{"host": nil}},
		{"host 含斜杠", map[string]any{"host": "10.0.0.8/path"}},
		{"host 含空白", map[string]any{"host": "10.0.0.8 0"}},
		{"port 缺失", map[string]any{"port": nil}},
		{"port 越界 0", map[string]any{"port": 0.0}},
		{"port 越界 70000", map[string]any{"port": 70000.0}},
		{"password 无 user", map[string]any{"user": nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
			if err := svc.CreateProvider(context.Background(), proxyCreateBody(t, tc.overrides)); !errors.Is(err, adminsvc.ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest", err)
			}
			if len(store.created) != 0 {
				t.Fatal("非法请求不得落库")
			}
		})
	}
}

// TestUpdateProviderProxyPatch proxy 行 PATCH：部分提交（只改端口）未提交字段
// 保留原值且 trim 回写；清 user 留 password → 组合非法拒绝（ErrInvalidUserinfo
// 同源拦截，不落库）。
func TestUpdateProviderProxyPatch(t *testing.T) {
	orig := proxyRowOf(t, "pxy_exist", 1)
	// 行内预置首尾空白（模拟历史脏数据）：PATCH 只改端口时其余字段 trim 回写。
	origExt, err := repo.MarshalProviderExt(&providerpb.Ext{Scheme: "socks5", Host: " 10.0.0.8 ",
		Port: 1080, User: " u1 ", Password: " p1 "})
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	orig.Ext = origExt
	store := newFakeStore(orig)
	inv := &fakeInvalidator{}
	svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())

	if err := svc.UpdateProvider(context.Background(), structBody(t, map[string]any{
		"provider_key": "pxy_exist", "port": 2080.0,
	})); err != nil {
		t.Fatalf("UpdateProvider: %v", err)
	}
	if len(store.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(store.updated))
	}
	ext, err := repo.ParseProviderExt(store.updated[0].Ext)
	if err != nil {
		t.Fatalf("ParseProviderExt: %v", err)
	}
	if ext.GetScheme() != "socks5" || ext.GetHost() != "10.0.0.8" || ext.GetPort() != 2080 ||
		ext.GetUser() != "u1" || ext.GetPassword() != "p1" {
		t.Errorf("PATCH 后 ext = %+v（port 更新、其余保留并 trim）", ext)
	}

	// 清 user 留 password：合并后组合非法，拒绝且不落库不失效。
	if err := svc.UpdateProvider(context.Background(), structBody(t, map[string]any{
		"provider_key": "pxy_exist", "user": nil,
	})); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Fatalf("err = %v, want ErrInvalidRequest（清 user 留 password）", err)
	}
	if len(store.updated) != 1 || len(inv.snapshot()) != 1 {
		t.Fatalf("非法请求不得落库 / 失效: updated=%d invalidated=%v", len(store.updated), inv.snapshot())
	}
}

// TestProxyRefKeyCharset 引用键保存期仅校字符集 ^[a-z0-9_]+$、不校存在性（§5.3，
// 允许先引用后建行）：非法字符集拒绝、合法键（含尚未建行的键）放行。
func TestProxyRefKeyCharset(t *testing.T) {
	for _, tc := range []struct {
		ref  string
		want error
	}{
		{"Bad-Ref", adminsvc.ErrInvalidRequest},
		{"含 空格", adminsvc.ErrInvalidRequest},
		{"not_yet_created", nil}, // 存在性不校验：允许先引用后建行
	} {
		store := newFakeStore()
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		body := wechatMpCreateBody(t, map[string]any{provider.ProxyRefKey: tc.ref})
		err := svc.CreateProvider(context.Background(), body)
		if tc.want == nil && err != nil {
			t.Errorf("ref %q: err = %v, want 放行", tc.ref, err)
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("ref %q: err = %v, want ErrInvalidRequest", tc.ref, err)
		}
	}
}

// TestProxyRefKeyScope 引用键呈现范围的写入侧（键集白名单由 Schema 声明派生，
// §5.3）：oauth / smtp / captcha 接受提交，union / storage-local / proxy 行自身
// 提交一律 invalid_request（声明驱动，dto 不按类别裁剪）。
func TestProxyRefKeyScope(t *testing.T) {
	accepted := []map[string]any{
		{"type": "wechat_mp", "provider_key": "wx_ref", "category": "auth", "display_name": "W",
			"app_id": "a", "client_secret": "b", provider.ProxyRefKey: "pxy_new"},
		{"type": "smtp", "provider_key": "smtp_ref", "category": provider.CategoryEmail,
			"display_name": "S", "host": "smtp.example.com", "from": "n@example.com",
			"user": "u1", "password": "p1", provider.ProxyRefKey: "pxy_new"},
		{"type": provider.CaptchaTypeTurnstile, "provider_key": "cap_ref", "category": provider.CategoryCaptcha,
			"display_name": "C", "client_id": "site", "client_secret": "sec", provider.ProxyRefKey: "pxy_new"},
	}
	for _, body := range accepted {
		store := newFakeStore()
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.CreateProvider(context.Background(), structBody(t, body)); err != nil {
			t.Errorf("type %q 提交引用键应通过: %v", body["type"], err)
		}
		ext, err := repo.ParseProviderExt(store.created[0].Ext)
		if err != nil || ext.GetProxyProviderKey() != "pxy_new" {
			t.Errorf("type %q ext 引用键 = %v (ext %+v)", body["type"], err, ext)
		}
	}
	rejected := []map[string]any{
		{"type": provider.UnionProviderType, "provider_key": "u_ref", "category": provider.CategoryUnion,
			"display_name": "U", provider.ProxyRefKey: "pxy_new"},
		{"type": provider.StorageTypeLocal, "provider_key": "local_ref", "category": provider.CategoryStorage,
			"display_name": "L", "bucket": "/data", "domain": "https://cdn.example.com", provider.ProxyRefKey: "pxy_new"},
		{"type": provider.ProxyType, "provider_key": "pxy_selfref", "category": provider.CategoryProxy,
			"display_name": "P", "scheme": "socks5", "host": "10.0.0.8", "port": 1080.0,
			provider.ProxyRefKey: "pxy_new"},
	}
	for _, body := range rejected {
		store := newFakeStore()
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.CreateProvider(context.Background(), structBody(t, body)); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Errorf("type %q 提交引用键应拒绝: err = %v", body["type"], err)
		}
		if len(store.created) != 0 {
			t.Errorf("type %q 非法请求不得落库", body["type"])
		}
	}
}

// TestTestProviderProxyResolution TestProvider 引用解析两路径（§15.4：不经
// Loader，与装配期同一 ResolveOutbound 语义）：无引用 = 直连（Outbound nil）、
// 有效引用 = 固化按 proxy 行 key 键控的池；引用不可解析（缺失 / 未启用）
// fail-closed → invalid_request，不降级直连。
func TestTestProviderProxyResolution(t *testing.T) {
	ctx := context.Background()
	proxyRow := proxyRowOf(t, "pxy_a", 1)
	proxyOff := proxyRowOf(t, "pxy_off", 0)

	t.Run("无引用直连", func(t *testing.T) {
		row := emailRowWithRef(t, "smtp_direct", "")
		svc := adminsvc.NewService(newFakeStore(row, proxyRow), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.TestProvider(ctx, "smtp_direct", "a@b.c"); err != nil {
			t.Fatalf("TestProvider: %v", err)
		}
		testAdminSender.mu.Lock()
		defer testAdminSender.mu.Unlock()
		if testAdminSender.lastProv == nil || testAdminSender.lastProv.Outbound != nil {
			t.Errorf("Outbound = %v, want nil（key 空 = 直连）", testAdminSender.lastProv.Outbound)
		}
	})
	t.Run("有效引用出池", func(t *testing.T) {
		row := emailRowWithRef(t, "smtp_ref", "pxy_a")
		svc := adminsvc.NewService(newFakeStore(row, proxyRow), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.TestProvider(ctx, "smtp_ref", "a@b.c"); err != nil {
			t.Fatalf("TestProvider: %v", err)
		}
		testAdminSender.mu.Lock()
		defer testAdminSender.mu.Unlock()
		if testAdminSender.lastProv == nil || testAdminSender.lastProv.Outbound == nil {
			t.Fatal("Outbound = nil, want 非 nil（引用解析出池）")
		}
		wantCfg, err := proxyclient.NewConfig("socks5", "10.0.0.8", 1080, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if !testAdminSender.lastProv.Outbound.Config().Equal(wantCfg) {
			t.Errorf("池配置 = %+v, want %+v", testAdminSender.lastProv.Outbound.Config(), wantCfg)
		}
	})
	// 引用行不消费 is_enabled：禁用被引行仍解析出池（proxyRowOf("pxy_off", 0)）。
	t.Run("引用行禁用仍出池", func(t *testing.T) {
		row := emailRowWithRef(t, "smtp_ref", "pxy_off")
		svc := adminsvc.NewService(newFakeStore(row, proxyRow, proxyOff), &fakeInvalidator{}, proxyclient.NewPoolSet())
		if err := svc.TestProvider(ctx, "smtp_ref", "a@b.c"); err != nil {
			t.Fatalf("禁用被引行应仍解析: %v", err)
		}
	})
	for _, tc := range []struct {
		name string
		ref  string
	}{
		{"引用缺失 fail-closed", "missing_ref"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := emailRowWithRef(t, "smtp_ref", tc.ref)
			svc := adminsvc.NewService(newFakeStore(row, proxyRow, proxyOff), &fakeInvalidator{}, proxyclient.NewPoolSet())
			if err := svc.TestProvider(ctx, "smtp_ref", "a@b.c"); !errors.Is(err, adminsvc.ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest（不降级直连）", err)
			}
		})
	}
}

// —— 拉码模式保存期组合校验（§5.3 type=wechat_mp_scan 行）——

// wechatMpScanCreateBody wechat_mp_scan 新建提交体（凭证两键 required）：
// 存储与拉码模式字段由用例按需给值——url 模式（含缺省空值）存储二字段必填、
// ticket 模式模板必填含占位符，由保存期组合校验拦截。
func wechatMpScanCreateBody(t *testing.T, overrides map[string]any) *structpb.Struct {
	t.Helper()
	body := map[string]any{
		"type":          "wechat_mp_scan",
		"provider_key":  "scan_new",
		"category":      "auth",
		"display_name":  "微信小程序扫码",
		"app_id":        "wx-appid",
		"client_secret": "wx-secret",
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

// TestCreateProviderQrcodeModeValidation 拉码模式组合校验矩阵（§5.3）：
// ticket 模式模板缺失 / 缺占位符、非法模式值、url 模式（含缺省空值）存储
// 二字段缺失，一律 ErrInvalidRequest 且不落库；合法组合（ticket 模板含
// 占位符、base64、url 存储齐）放行。
func TestCreateProviderQrcodeModeValidation(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]any
		wantOK    bool
	}{
		{"ticket 模板缺失", map[string]any{"qrcode_mode": "ticket"}, false},
		{"ticket 模板缺占位符", map[string]any{"qrcode_mode": "ticket", "qrcode_format": "https://example.com/scan"}, false},
		{"非法模式值", map[string]any{"qrcode_mode": "pigeon_post"}, false},
		{"url 显式缺存储", map[string]any{"qrcode_mode": "url"}, false},
		{"url 缺省（空）缺存储", map[string]any{"qrcode_mode": ""}, false},
		{"base64 不要求存储", map[string]any{"qrcode_mode": "base64"}, true},
		{"ticket 合法（模板含占位符）", map[string]any{"qrcode_mode": "ticket", "qrcode_format": "https://example.com/scan?t={{TICKET}}"}, true},
		{"url 合法（存储齐）", map[string]any{"qrcode_mode": "url", "storage_provider": "files", "storage_path": `'qrcodes_' & $.ticket_id & '.jpg'`}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			inv := &fakeInvalidator{}
			svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
			err := svc.CreateProvider(context.Background(), wechatMpScanCreateBody(t, tc.overrides))
			if tc.wantOK {
				if err != nil {
					t.Fatalf("err = %v, want 放行", err)
				}
				if len(store.created) != 1 {
					t.Fatalf("created = %d, want 1", len(store.created))
				}
				return
			}
			if !errors.Is(err, adminsvc.ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest", err)
			}
			if len(store.created) != 0 {
				t.Fatal("非法请求不得落库")
			}
		})
	}
}

// scanRowOf 预置一行 url 模式（缺省空值）的 wechat_mp_scan 存量行，存储配置
// 齐备（url 模式存量口径下运行期必需）。
func scanRowOf(t *testing.T) *model.Provider {
	t.Helper()
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{
		AppId: "wx-id", ClientSecret: "wx-sec",
		StorageProvider: "files", StoragePath: `'qrcodes_' & $.ticket_id & '.jpg'`,
	})
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	return &model.Provider{
		ProviderKey: "scan_exist", Category: "auth", Type: "wechat_mp_scan",
		IsEnabled: 1, EnableSignin: 1, EnableSignup: 1, DisplayName: "微信小程序扫码",
		Ext: ext,
	}
}

// TestUpdateProviderQrcodeModePatch 拉码模式 PATCH 组合校验（对合并后的 Ext
// 执行，PATCH 未提交键保留原值）：url 行切 ticket 未同步提交模板 → 拒绝；
// 模板随模式一并提交 → 放行且落库；ticket 行切回 url 存储原值保留 → 放行；
// url 行清存储 → 拒绝；未触模式的普通 PATCH → 放行。
func TestUpdateProviderQrcodeModePatch(t *testing.T) {
	t.Run("切 ticket 缺模板拒绝", func(t *testing.T) {
		store := newFakeStore(scanRowOf(t))
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		body := map[string]any{"provider_key": "scan_exist", "qrcode_mode": "ticket"}
		if err := svc.UpdateProvider(context.Background(), structBody(t, body)); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest（部分提交在合并后 Ext 上拦截）", err)
		}
		if len(store.updated) != 0 {
			t.Fatal("非法请求不得落库")
		}
	})
	t.Run("模板随模式一并提交放行", func(t *testing.T) {
		store := newFakeStore(scanRowOf(t))
		inv := &fakeInvalidator{}
		svc := adminsvc.NewService(store, inv, proxyclient.NewPoolSet())
		body := map[string]any{"provider_key": "scan_exist", "qrcode_mode": "ticket", "qrcode_format": "https://example.com/scan?t={{TICKET}}"}
		if err := svc.UpdateProvider(context.Background(), structBody(t, body)); err != nil {
			t.Fatalf("UpdateProvider: %v", err)
		}
		ext, err := repo.ParseProviderExt(store.updated[len(store.updated)-1].Ext)
		if err != nil {
			t.Fatalf("ParseProviderExt: %v", err)
		}
		if ext.GetQrcodeMode() != "ticket" || ext.GetQrcodeFormat() != "https://example.com/scan?t={{TICKET}}" {
			t.Fatalf("ext = (mode=%q format=%q)", ext.GetQrcodeMode(), ext.GetQrcodeFormat())
		}
		if keys := inv.snapshot(); len(keys) != 1 || keys[0] != "scan_exist" {
			t.Errorf("invalidate = %v, want [scan_exist]", keys)
		}
	})
	t.Run("ticket 行切回 url 存储原值保留", func(t *testing.T) {
		row := scanRowOf(t)
		ext, err := repo.ParseProviderExt(row.Ext)
		if err != nil {
			t.Fatalf("ParseProviderExt: %v", err)
		}
		ext.QrcodeMode, ext.QrcodeFormat = "ticket", "https://example.com/scan?t={{TICKET}}"
		if row.Ext, err = repo.MarshalProviderExt(ext); err != nil {
			t.Fatalf("MarshalProviderExt: %v", err)
		}
		store := newFakeStore(row)
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		body := map[string]any{"provider_key": "scan_exist", "qrcode_mode": "url"}
		if err := svc.UpdateProvider(context.Background(), structBody(t, body)); err != nil {
			t.Fatalf("UpdateProvider: %v", err)
		}
		merged, err := repo.ParseProviderExt(store.updated[len(store.updated)-1].Ext)
		if err != nil {
			t.Fatalf("ParseProviderExt: %v", err)
		}
		if merged.GetQrcodeMode() != "url" || merged.GetStorageProvider() != "files" {
			t.Fatalf("ext = (mode=%q storage=%q), want url + 原值保留", merged.GetQrcodeMode(), merged.GetStorageProvider())
		}
	})
	t.Run("url 行清存储拒绝", func(t *testing.T) {
		store := newFakeStore(scanRowOf(t))
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		body := map[string]any{"provider_key": "scan_exist", "storage_provider": ""}
		if err := svc.UpdateProvider(context.Background(), structBody(t, body)); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("未触模式普通 PATCH 放行", func(t *testing.T) {
		store := newFakeStore(scanRowOf(t))
		svc := adminsvc.NewService(store, &fakeInvalidator{}, proxyclient.NewPoolSet())
		body := map[string]any{"provider_key": "scan_exist", "display_name": "微信扫码新名"}
		if err := svc.UpdateProvider(context.Background(), structBody(t, body)); err != nil {
			t.Fatalf("UpdateProvider: %v", err)
		}
	})
}
