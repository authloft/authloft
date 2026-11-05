package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

	adminv1 "authloft/gen/go/api/admin/v1"
	"authloft/gen/go/api/admin/v1/adminv1connect"
	commonv1 "authloft/gen/go/api/common/v1"
	providerpb "authloft/gen/go/provider"
	"authloft/gen/go/token"
	internalconnect "authloft/internal/connect"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/session"
	adminsvc "authloft/internal/service/admin"
	// 注册表数据源（§15.3）：与 bootstrap 同款 _ import 触发自注册，
	// schema 用例断言「与注册表 meta 逐项一致」需两域真实注册项。
	_ "authloft/internal/provider/email/smtp"
	_ "authloft/internal/provider/oauth/wechat_mp"
	_ "authloft/internal/provider/sms/aliyun_sms"
)

// fakeEpochReader 隔离型 epoch 读取（口径同 handler/account/account_test.go）。
type fakeEpochReader struct{ values map[int64]int64 }

func (f *fakeEpochReader) Current(_ context.Context, uid int64) (int64, error) {
	return f.values[uid], nil
}

// fakeProviders ProviderReader 的 fake：list 按 q 分类返回（union 查询固定
// 返回一行，其余返回 rows/total），key 透传到闭包；全部查询入参留档断言。
type fakeProviders struct {
	rows     []model.Provider
	total    int64
	listErr  error
	keyRow   *model.Provider
	keyErr   error
	queries  []repo.ProviderListQuery
	gotKeys  []string
	unionRow model.Provider
}

func (f *fakeProviders) FindByKey(_ context.Context, providerKey string) (*model.Provider, error) {
	f.gotKeys = append(f.gotKeys, providerKey)
	return f.keyRow, f.keyErr
}

func (f *fakeProviders) ListProviders(_ context.Context, q repo.ProviderListQuery) ([]model.Provider, int64, error) {
	f.queries = append(f.queries, q)
	if q.Category != nil && *q.Category == "union" {
		return []model.Provider{f.unionRow}, 1, nil
	}
	return f.rows, f.total, f.listErr
}

// fakeWriter ProviderService（写族 7 方法）的 fake：入参全留档断言，错误可
// 注入。
type fakeWriter struct {
	createErr error
	updateErr error
	deleteErr error
	enableErr error
	sortErr   error
	testErr   error

	createBody map[string]any
	updateBody map[string]any
	deleteKey  string
	enableKey  string
	enableTo   bool
	sortItems  []adminsvc.SortItem
	testKey    string
	testTarget string

	types []adminsvc.ProviderTypeInfo
}

func (f *fakeWriter) CreateProvider(_ context.Context, body *structpb.Struct) error {
	f.createBody = body.AsMap()
	return f.createErr
}

func (f *fakeWriter) UpdateProvider(_ context.Context, body *structpb.Struct) error {
	f.updateBody = body.AsMap()
	return f.updateErr
}

func (f *fakeWriter) DeleteProvider(_ context.Context, providerKey string) error {
	f.deleteKey = providerKey
	return f.deleteErr
}

func (f *fakeWriter) SetProviderEnabled(_ context.Context, providerKey string, enabled bool) error {
	f.enableKey, f.enableTo = providerKey, enabled
	return f.enableErr
}

func (f *fakeWriter) SortProviders(_ context.Context, items []adminsvc.SortItem) error {
	f.sortItems = items
	return f.sortErr
}

func (f *fakeWriter) ProviderTypes() []adminsvc.ProviderTypeInfo { return f.types }

func (f *fakeWriter) TestProvider(_ context.Context, providerKey, target string) error {
	f.testKey, f.testTarget = providerKey, target
	return f.testErr
}

// newAdminHandler 构造挂真实 session + admin 拦截链（链序同装配：session
// 在外注入身份、admin 在内判 uid，§3.14 行 494）的生成 handler，返回签发
// 助手与 http.Handler（口径同 handler/account/account_test.go）。writer 传
// nil 时用 no-op fake（读路径用例不触写族）。
func newAdminHandler(t *testing.T, providers ProviderReader, writer ProviderService) (*session.Tokens, *fakeEpochReader, http.Handler) {
	t.Helper()
	if writer == nil {
		writer = &fakeWriter{}
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	tokens := session.NewTokens(security.NewCodec(ks))
	epochs := &fakeEpochReader{values: map[int64]int64{}}
	_, h := adminv1connect.NewAdminServiceHandler(
		New(providers, writer),
		connectrpc.WithInterceptors(
			internalconnect.NewSessionInterceptor(
				session.NewVerifier(tokens, epochs),
				session.NewRenewer(tokens, time.Hour),
				session.NewCookie("al_session", "", time.Hour),
				nil,
			),
			internalconnect.NewAdminInterceptor(),
		),
	)
	return tokens, epochs, h
}

// adminCookie 签发指定 uid（epoch=3）的有效会话 Cookie。
func adminCookie(t *testing.T, tokens *session.Tokens, epochs *fakeEpochReader, uid int64) string {
	t.Helper()
	p := &token.SessionTokenPayload{
		Id:    uid,
		Epoch: 3,
		Amr:   []string{"pwd"},
		Sid:   "sid-admin",
		Iat:   time.Now().Add(-time.Minute).Unix(),
		Exp:   time.Now().Add(time.Hour).Unix(),
	}
	epochs.values[uid] = p.Epoch
	tok, err := tokens.Sign(p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return "al_session=" + tok
}

// wantRow GetProvider / List 用例的 provider 行（§5.2 列表列 + 详情列全覆盖）。
func wantRow(t *testing.T) *model.Provider {
	t.Helper()
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{
		ClientId:     "wx-123",
		ClientSecret: "secret-456",
		AppId:        "app-789",
	})
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	return &model.Provider{
		ID: 7, ProviderKey: "wechat_official", UnionProvider: "wechat_union",
		DisplayName: "微信扫码", Category: "oauth", Type: "wechat_mp",
		EnableSignin: 1, EnableSignup: 0, AutoBind: 1, AutoBindFields: "email,phone",
		IsEnabled: 1, UiGroup: "social", SortOrder: 30,
		IconURL: "https://cdn.example.com/wechat.png", Remark: "生产渠道",
		Ext:       ext,
		CreatedAt: time.Unix(1761700000, 0).UTC(), UpdatedAt: time.Unix(1761800000, 0).UTC(),
	}
}

// doRPC 打一次带 JSON body 的 admin RPC（cookie 可空），返回响应与原文。
func doRPC(t *testing.T, h http.Handler, target, body, cookie string) (*http.Response, string) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	req, err := http.NewRequest(http.MethodPost, srv.URL+target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	raw := readBody(t, resp.Body)
	return resp, raw
}

func readBody(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// decodeErrorCode 从 Connect 错误体解出顶层 code（§1.5 行 197-211）。
func decodeErrorCode(t *testing.T, raw string) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	return body.Code
}

// decodeErrorInfo 从 Connect 错误体 details 解出 ErrorInfo（base64 value →
// proto 解码，§1.5 行 203-210），断言 domain / code 在 §1.6 封闭集合内。
func decodeErrorInfo(t *testing.T, raw string) *commonv1.ErrorInfo {
	t.Helper()
	var body struct {
		Code    string `json:"code"`
		Details []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	if len(body.Details) != 1 {
		t.Fatalf("details 数量 = %d, want 1 (body %s)", len(body.Details), raw)
	}
	if body.Details[0].Type != "api.common.v1.ErrorInfo" {
		t.Fatalf("details[0].type = %q, want api.common.v1.ErrorInfo", body.Details[0].Type)
	}
	buf, err := base64.RawStdEncoding.DecodeString(body.Details[0].Value)
	if err != nil {
		t.Fatalf("decode detail value: %v", err)
	}
	info := &commonv1.ErrorInfo{}
	if err := proto.Unmarshal(buf, info); err != nil {
		t.Fatalf("unmarshal ErrorInfo: %v", err)
	}
	return info
}

// schemaOf 打 GetProviderSchema（管理员会话）并解出 200 响应。
func schemaOf(t *testing.T, h http.Handler, providerType, cookie string) *adminv1.SchemaResponse {
	t.Helper()
	resp, raw := doRPC(t, h,
		adminv1connect.AdminServiceGetProviderSchemaProcedure,
		`{"type":"`+providerType+`"}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetProviderSchema(%q): status = %d, want 200 (body %s)", providerType, resp.StatusCode, raw)
	}
	var got adminv1.SchemaResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode schema response %q: %v", raw, err)
	}
	return &got
}

// TestListProvidersAdminSession 管理员会话（uid=1）列表：200；§5.2 行 1168
// 列表列逐项；筛选 / 分页入参按 §1.7 透传（归一后回显）；响应无任何 ext
// 凭证字段（明文仅在 GetProvider，§12.1 行 1719）。
func TestListProvidersAdminSession(t *testing.T) {
	fakes := &fakeProviders{
		rows:     []model.Provider{*wantRow(t)},
		total:    5,
		unionRow: model.Provider{ProviderKey: "union_a", Category: "union", Type: "unionid"},
	}
	tokens, epochs, h := newAdminHandler(t, fakes, nil)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceListProvidersProcedure,
		`{"category":"oauth"}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	var got adminv1.ProviderListResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetTotal() != 5 || got.GetPage() != 1 || got.GetPageSize() != 20 {
		t.Errorf("分页 = (total=%d page=%d size=%d), want (5, 1, 20)（缺省归一回显）", got.GetTotal(), got.GetPage(), got.GetPageSize())
	}
	if len(got.GetItems()) != 1 {
		t.Fatalf("items = %d, want 1", len(got.GetItems()))
	}
	item := got.GetItems()[0]
	if item.GetProviderKey() != "wechat_official" || item.GetDisplayName() != "微信扫码" ||
		item.GetCategory() != "oauth" || item.GetType() != "wechat_mp" {
		t.Errorf("列表列 = %+v", item)
	}
	if !item.GetIsEnabled() || !item.GetEnableSignin() || item.GetEnableSignup() || !item.GetAutoBind() {
		t.Errorf("状态 / 策略标签 = (enabled=%v signin=%v signup=%v bind=%v)", item.GetIsEnabled(), item.GetEnableSignin(), item.GetEnableSignup(), item.GetAutoBind())
	}
	if item.GetSortOrder() != 30 {
		t.Errorf("sortOrder = %d, want 30", item.GetSortOrder())
	}
	// 列表响应不含 ext 任何字段（proto 列表消息即无 ext；wire 上也不得出现）。
	if strings.Contains(raw, "ext") || strings.Contains(raw, "secret-456") {
		t.Errorf("列表响应出现 ext / 凭证内容（明文仅在 GetProvider）: %s", raw)
	}
	// 筛选与分页透传。
	if len(fakes.queries) != 1 {
		t.Fatalf("list 查询次数 = %d, want 1", len(fakes.queries))
	}
	q := fakes.queries[0]
	if q.Category == nil || *q.Category != "oauth" || q.Type != nil || q.IsEnabled != nil {
		t.Errorf("筛选透传 = %+v（category=oauth，其余 nil）", q)
	}
	if q.Page != 1 || q.PageSize != 20 {
		t.Errorf("分页透传 = (%d, %d), want (1, 20)", q.Page, q.PageSize)
	}

	// optional is_enabled=false 与显式分页同样透传（0 = 禁用过滤，指针区分未传）。
	resp, raw = doRPC(t, h, adminv1connect.AdminServiceListProvidersProcedure,
		`{"isEnabled":false,"page":2,"pageSize":50}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("第二次 list status = %d (body %s)", resp.StatusCode, raw)
	}
	q = fakes.queries[1]
	if q.IsEnabled == nil || *q.IsEnabled != 0 {
		t.Errorf("isEnabled 透传 = %v, want *0（false 过滤）", q.IsEnabled)
	}
	if q.Page != 2 || q.PageSize != 50 {
		t.Errorf("显式分页透传 = (%d, %d), want (2, 50)", q.Page, q.PageSize)
	}
}

// TestGetProviderAdminSession 管理员会话详情：200；§5.2 行 1170 全列 + ext
// Struct 明文（全站唯一明文出口，键 = Ext 字段名 snake_case）。
func TestGetProviderAdminSession(t *testing.T) {
	fakes := &fakeProviders{keyRow: wantRow(t)}
	tokens, epochs, h := newAdminHandler(t, fakes, nil)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetProviderProcedure,
		`{"providerKey":"wechat_official"}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	var got adminv1.AdminProvider
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetProviderKey() != "wechat_official" || got.GetUnionProvider() != "wechat_union" ||
		got.GetDisplayName() != "微信扫码" || got.GetCategory() != "oauth" || got.GetType() != "wechat_mp" {
		t.Errorf("详情基础列 = %+v", &got)
	}
	if got.GetAutoBindFields() != "email,phone" || got.GetUiGroup() != "social" ||
		got.GetIconUrl() != "https://cdn.example.com/wechat.png" || got.GetRemark() != "生产渠道" {
		t.Errorf("详情展示列 = %+v", &got)
	}
	if got.GetCreatedAt() != 1761700000 || got.GetUpdatedAt() != 1761800000 {
		t.Errorf("timestamps = (%d, %d)", got.GetCreatedAt(), got.GetUpdatedAt())
	}
	// ext 明文逐项（§5.2 行 1170：返回明文凭证，需管理员会话）。
	ext := got.GetExt().GetFields()
	if v := ext["client_id"].GetStringValue(); v != "wx-123" {
		t.Errorf("ext.client_id = %q, want wx-123（明文）", v)
	}
	if v := ext["client_secret"].GetStringValue(); v != "secret-456" {
		t.Errorf("ext.client_secret = %q, want secret-456（明文，不脱敏）", v)
	}
	if v := ext["app_id"].GetStringValue(); v != "app-789" {
		t.Errorf("ext.app_id = %q, want app-789（键 = Ext 字段名）", v)
	}
	if len(fakes.gotKeys) != 1 || fakes.gotKeys[0] != "wechat_official" {
		t.Errorf("FindByKey 入参 = %v", fakes.gotKeys)
	}
}

// TestGetProviderNotFound 详情目标不存在 → 404 not_found（§1.5 行 189
// 管理后台单资源）。
func TestGetProviderNotFound(t *testing.T) {
	fakes := &fakeProviders{keyErr: fmt.Errorf("provider repo: find by key: %w", gorm.ErrRecordNotFound)}
	tokens, epochs, h := newAdminHandler(t, fakes, nil)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetProviderProcedure,
		`{"providerKey":"missing"}`, cookie)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", resp.StatusCode, raw)
	}
	if code := decodeErrorCode(t, raw); code != "not_found" {
		t.Errorf("code = %q, want not_found (body %s)", code, raw)
	}
}

// TestGetProviderSchemaSenderMeta 消息域 schema（smtp）与注册表 meta 逐项
// 一致（§15.3：/schema 唯一数据源）：category=email 由 meta 决定；Ext 字段
// 逐项等于 LookupSenderMeta；基线字段同在；union options 来自 union 查询。
func TestGetProviderSchemaSenderMeta(t *testing.T) {
	fakes := &fakeProviders{unionRow: model.Provider{ProviderKey: "union_a", Category: "union", Type: "unionid"}}
	tokens, epochs, h := newAdminHandler(t, fakes, nil)
	cookie := adminCookie(t, tokens, epochs, 1)

	got := schemaOf(t, h, "smtp", cookie)
	meta, ok := provider.LookupSenderMeta("smtp")
	if !ok {
		t.Fatal("LookupSenderMeta(smtp) 未注册（_ import 缺失）")
	}
	if got.GetCategory() != meta.Category || got.GetCategory() != "email" {
		t.Errorf("category = %q, want email（注册表 meta 决定）", got.GetCategory())
	}
	byKey := map[string]*adminv1.SchemaField{}
	for _, f := range got.GetFields() {
		byKey[f.GetKey()] = f
	}
	for _, mf := range meta.Fields {
		f, ok := byKey[mf.Key]
		if !ok {
			t.Fatalf("schema 缺少 meta 声明字段 %q", mf.Key)
		}
		if f.GetLabel() != mf.Label || f.GetType() != mf.Type || f.GetSection() != mf.Section ||
			f.GetRequired() != mf.Required || f.GetAdvanced() != mf.Advanced || f.GetHelp() != mf.Help {
			t.Errorf("%s 与注册表 meta 不一致: schema=%+v meta=%+v", mf.Key, f, mf)
		}
		if mf.Default == "" && f.GetDefault() != nil {
			t.Errorf("%s default = %+v, want nil（meta 未声明默认值）", mf.Key, f.GetDefault())
		}
	}
	if v := byKey["port"].GetDefault().GetNumberValue(); v != 587 {
		t.Errorf("port default = %v, want 587", v)
	}
	// 基线表列字段仍在。
	for _, key := range []string{"provider_key", "display_name", "category", "union_provider",
		"icon_url", "ui_group", "sort_order", "remark",
		"is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields"} {
		if _, ok := byKey[key]; !ok {
			t.Errorf("schema 缺少表列基线字段 %q", key)
		}
	}
	// union_provider options 来自 union 类查询（§5.3 行 1197）。
	if len(fakes.queries) != 1 || fakes.queries[0].Category == nil || *fakes.queries[0].Category != "union" {
		t.Fatalf("union 查询入参 = %+v, want category=union", fakes.queries)
	}
	if opts := byKey["union_provider"].GetOptions(); len(opts) != 1 || opts[0] != "union_a" {
		t.Errorf("union_provider options = %v, want [union_a]", opts)
	}
}

// TestGetProviderSchemaOauthMeta oauth 域 schema（wechat_mp）：category=oauth
// 由 oauth 注册表 Lookup 决定；fields = 表列基线 13 项 + §5.3 行 1235 oauth
// 追加 10 字段 + 行 1239 全类 metadata = 24 项。追加字段 label / type /
// section / required / advanced / help 与 §5.3 示例（行 1187-1226）逐字一致，
// 且与注册表 meta.Fields 逐项相同（§15.3：/schema 唯一数据源，不硬编码）。
func TestGetProviderSchemaOauthMeta(t *testing.T) {
	fakes := &fakeProviders{unionRow: model.Provider{ProviderKey: "union_b", Category: "union", Type: "unionid"}}
	tokens, epochs, h := newAdminHandler(t, fakes, nil)
	cookie := adminCookie(t, tokens, epochs, 1)

	got := schemaOf(t, h, "wechat_mp", cookie)
	meta, ok := provider.Lookup("wechat_mp")
	if !ok {
		t.Fatal("Lookup(wechat_mp) 未注册（_ import 缺失）")
	}
	if got.GetType() != "wechat_mp" || got.GetCategory() != meta.Category || got.GetCategory() != "oauth" {
		t.Errorf("type/category = (%q, %q), want (wechat_mp, oauth)", got.GetType(), got.GetCategory())
	}
	// 13 表列基线 + 10 oauth 追加（行 1235）+ 全类 metadata（行 1239）。
	if len(got.GetFields()) != 24 {
		t.Fatalf("字段数 = %d, want 24（13 表列基线 + 10 oauth 追加 + metadata）", len(got.GetFields()))
	}
	byKey := map[string]*adminv1.SchemaField{}
	for _, f := range got.GetFields() {
		byKey[f.GetKey()] = f
		// 每字段必须带合法 section（§5.3 行 1185 封闭五区块）。
		switch f.GetSection() {
		case "basic", "credential", "endpoint", "display", "policy":
		default:
			t.Errorf("%s section = %q, 非法（不在五区块封闭集合）", f.GetKey(), f.GetSection())
		}
	}
	// 表列基线 13 项仍在。
	for _, key := range []string{"provider_key", "display_name", "category", "union_provider",
		"icon_url", "ui_group", "sort_order", "remark",
		"is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields"} {
		if _, ok := byKey[key]; !ok {
			t.Errorf("schema 缺少表列基线字段 %q", key)
		}
	}
	// 追加字段逐字对照 §5.3 示例（行 1200-1211）+ 行 1239 metadata（json，
	// 行 1243 约定「其余按语义归 basic」）；声明序即渲染序（行 1185），
	// Ext 区块夹在 basic / display 基线之间。
	wantExt := []provider.FieldMeta{
		{Key: "client_id", Label: "AppID", Type: "text", Section: "credential", Required: true},
		{Key: "client_secret", Label: "AppSecret", Type: "secret", Section: "credential", Required: true},
		{Key: "app_id", Label: "小程序 AppID", Type: "text", Section: "credential", Advanced: true},
		{Key: "cert", Label: "证书 / 公钥", Type: "secret", Section: "credential", Advanced: true},
		{Key: "scopes", Label: "授权范围", Type: "text", Section: "credential", Advanced: true},
		{Key: "provider_url", Label: "服务地址", Type: "text", Section: "endpoint", Advanced: true},
		{Key: "custom_auth_url", Label: "授权地址", Type: "text", Section: "endpoint", Advanced: true},
		{Key: "custom_token_url", Label: "令牌地址", Type: "text", Section: "endpoint", Advanced: true},
		{Key: "custom_user_info_url", Label: "UserInfo 地址", Type: "text", Section: "endpoint", Advanced: true},
		{Key: "user_mapping", Label: "字段映射", Type: "json", Section: "endpoint", Advanced: true,
			Help: "三方字段 → Authloft 字段，值为 JSONata 表达式"},
		{Key: "metadata", Label: "长尾键值", Type: "json", Section: "basic", Advanced: true},
	}
	if len(meta.Fields) != len(wantExt) {
		t.Fatalf("注册表 meta.Fields 数 = %d, want %d", len(meta.Fields), len(wantExt))
	}
	for i, want := range wantExt {
		if meta.Fields[i] != want {
			t.Errorf("meta.Fields[%d] = %+v, want %+v（§5.3 行 1187-1226）", i, meta.Fields[i], want)
		}
		f := got.GetFields()[4+i] // basic 基线 4 项之后即 Ext 区块（声明序）。
		if f.GetKey() != want.Key {
			t.Errorf("fields[%d].key = %q, want %q（Ext 区块按 meta 声明序）", 4+i, f.GetKey(), want.Key)
		}
		if f.GetLabel() != want.Label || f.GetType() != want.Type || f.GetSection() != want.Section ||
			f.GetRequired() != want.Required || f.GetAdvanced() != want.Advanced || f.GetHelp() != want.Help {
			t.Errorf("%s 与 §5.3 示例不一致: schema=%+v", want.Key, f)
		}
	}
	// category / union_provider options 仍由注册表 / union 查询驱动。
	if opts := byKey["category"].GetOptions(); len(opts) != 1 || opts[0] != "oauth" {
		t.Errorf("category options = %v, want [oauth]", opts)
	}
	if opts := byKey["union_provider"].GetOptions(); len(opts) != 1 || opts[0] != "union_b" {
		t.Errorf("union_provider options = %v, want [union_b]", opts)
	}
}

// TestGetProviderSchemaUnknownType 未注册 / 空 type → §1.6 封闭集合内
// invalid_request（Connect 标准码 invalid_argument，ErrorInfo domain=admin）。
func TestGetProviderSchemaUnknownType(t *testing.T) {
	tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil)
	cookie := adminCookie(t, tokens, epochs, 1)

	for _, body := range []string{`{"type":"no_such_type"}`, `{"type":""}`} {
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetProviderSchemaProcedure, body, cookie)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400 (body %s)", body, resp.StatusCode, raw)
		}
		if code := decodeErrorCode(t, raw); code != "invalid_argument" {
			t.Errorf("body %s: code = %q, want invalid_argument (body %s)", body, code, raw)
		}
		info := decodeErrorInfo(t, raw)
		if info.GetDomain() != "admin" || info.GetCode() != "invalid_request" {
			t.Errorf("body %s: ErrorInfo = (domain=%q code=%q), want (admin, invalid_request)（§1.6 封闭集合）", body, info.GetDomain(), info.GetCode())
		}
	}
}

// TestListProvidersWithoutSession 无会话：session 拦截器放行匿名（既定语义），
// admin 拦截器拦下 → 401 unauthenticated（§5 行 1145，与 account 域
// handler 自判 401 的路径不同——admin 域在拦截器层）。
func TestListProvidersWithoutSession(t *testing.T) {
	_, _, h := newAdminHandler(t, &fakeProviders{}, nil)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceListProvidersProcedure, `{}`, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", resp.StatusCode, raw)
	}
	if code := decodeErrorCode(t, raw); code != "unauthenticated" {
		t.Errorf("code = %q, want unauthenticated (body %s)", code, raw)
	}
}

// TestNonAdminReturns404 会话有效但 uid≠1 → 404 not_found，文案与普通 404
// 一致（掩护管理面存在，§1.5 行 189 / wrapper_test 口径）。
func TestNonAdminReturns404(t *testing.T) {
	tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil)
	cookie := adminCookie(t, tokens, epochs, 42)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceListProvidersProcedure, `{}`, cookie)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", resp.StatusCode, raw)
	}
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	if body.Code != "not_found" {
		t.Errorf("code = %q, want not_found", body.Code)
	}
	if body.Message != "not found" {
		t.Errorf("message = %q, want %q（不透露路径存在）", body.Message, "not found")
	}
}

// TestStubsUnimplemented 其余全部 admin 方法（管理员自身 / 用户 / 客户端 /
// settings / 工具，共 23 个）一律返回生成基类的 unimplemented（桩 + TODO(后续
// admin 实现)，见包注释清单）。
func TestStubsUnimplemented(t *testing.T) {
	tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil)
	cookie := adminCookie(t, tokens, epochs, 1)
	cases := []string{
		adminv1connect.AdminServiceGetMeProcedure,
		adminv1connect.AdminServiceListUsersProcedure,
		adminv1connect.AdminServiceGetUserProcedure,
		adminv1connect.AdminServiceUpdateUserStatusProcedure,
		adminv1connect.AdminServiceResetUserPasswordProcedure,
		adminv1connect.AdminServiceUnbindUserThirdpartyProcedure,
		adminv1connect.AdminServiceUnlockUserProcedure,
		adminv1connect.AdminServiceGetUserEventsProcedure,
		adminv1connect.AdminServiceListSsoClientsProcedure,
		adminv1connect.AdminServiceCreateSsoClientProcedure,
		adminv1connect.AdminServiceGetSsoClientProcedure,
		adminv1connect.AdminServiceUpdateSsoClientProcedure,
		adminv1connect.AdminServiceDeleteSsoClientProcedure,
		adminv1connect.AdminServiceListOidcClientsProcedure,
		adminv1connect.AdminServiceCreateOidcClientProcedure,
		adminv1connect.AdminServiceGetOidcClientProcedure,
		adminv1connect.AdminServiceUpdateOidcClientProcedure,
		adminv1connect.AdminServiceDeleteOidcClientProcedure,
		adminv1connect.AdminServiceGetSettingsProcedure,
		adminv1connect.AdminServiceSetSettingsProcedure,
		adminv1connect.AdminServiceListEventsProcedure,
		adminv1connect.AdminServiceDecodeTokenProcedure,
		adminv1connect.AdminServiceGetStatusProcedure,
	}
	for _, procedure := range cases {
		req := httptest.NewRequest(http.MethodPost, procedure, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if code := decodeErrorCode(t, rec.Body.String()); code != "unimplemented" {
			t.Errorf("%s: code = %q, want unimplemented (body %s)", procedure, code, rec.Body.String())
		}
	}
}

// —— 写族 7 方法（handler 层：Connect 形态映射 + 入参透传）——

// TestCreateProviderHandler 管理员会话新建：合法提交体原样平铺透传到
// service（Struct 不包装）；uk 冲突 → 409 already_exists（§1.5 行 190，无
// ErrorInfo，§1.6 无对应业务细分码）；校验失败 → 400 + ErrorInfo
// (admin, invalid_request)（同 GetProviderSchema 先例）。
func TestCreateProviderHandler(t *testing.T) {
	t.Run("合法提交体透传", func(t *testing.T) {
		writer := &fakeWriter{}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceCreateProviderProcedure,
			`{"type":"wechat_mp","provider_key":"wx_new","display_name":"微信","client_id":"a","client_secret":"b"}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		if writer.createBody["provider_key"] != "wx_new" || writer.createBody["type"] != "wechat_mp" ||
			writer.createBody["client_secret"] != "b" {
			t.Errorf("提交体透传 = %v（平铺键值原样到达 service）", writer.createBody)
		}
	})
	t.Run("唯一键冲突 409", func(t *testing.T) {
		writer := &fakeWriter{createErr: adminsvc.ErrDuplicateKey}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceCreateProviderProcedure, `{}`, cookie)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (body %s)", resp.StatusCode, raw)
		}
		if code := decodeErrorCode(t, raw); code != "already_exists" {
			t.Errorf("code = %q, want already_exists (body %s)", code, raw)
		}
		// §1.6 封闭集合无 provider 冲突业务码 → 不挂 ErrorInfo，前端按标准码兜底（行 226）。
		if strings.Contains(raw, "api.common.v1.ErrorInfo") {
			t.Errorf("冲突响应不应携带 ErrorInfo detail: %s", raw)
		}
	})
	t.Run("校验失败 400 + ErrorInfo", func(t *testing.T) {
		writer := &fakeWriter{createErr: adminsvc.ErrInvalidRequest}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceCreateProviderProcedure, `{}`, cookie)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, raw)
		}
		if code := decodeErrorCode(t, raw); code != "invalid_argument" {
			t.Errorf("code = %q, want invalid_argument (body %s)", code, raw)
		}
		info := decodeErrorInfo(t, raw)
		if info.GetDomain() != "admin" || info.GetCode() != "invalid_request" {
			t.Errorf("ErrorInfo = (domain=%q code=%q), want (admin, invalid_request)", info.GetDomain(), info.GetCode())
		}
	})
}

// TestUpdateProviderHandler 编辑：提交体平铺透传（provider_key 兼定位）；
//「改 key 拒绝」等校验失败 → 400 + ErrorInfo(admin, invalid_request)。
func TestUpdateProviderHandler(t *testing.T) {
	t.Run("提交体透传", func(t *testing.T) {
		writer := &fakeWriter{}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceUpdateProviderProcedure,
			`{"provider_key":"wx_exist","display_name":"新名"}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		if writer.updateBody["provider_key"] != "wx_exist" || writer.updateBody["display_name"] != "新名" {
			t.Errorf("提交体透传 = %v", writer.updateBody)
		}
	})
	t.Run("改 key 拒绝 400", func(t *testing.T) {
		writer := &fakeWriter{updateErr: adminsvc.ErrInvalidRequest}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceUpdateProviderProcedure,
			`{"provider_key":"changed","display_name":"x"}`, cookie)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, raw)
		}
		info := decodeErrorInfo(t, raw)
		if info.GetDomain() != "admin" || info.GetCode() != "invalid_request" {
			t.Errorf("ErrorInfo = (domain=%q code=%q), want (admin, invalid_request)", info.GetDomain(), info.GetCode())
		}
	})
}

// TestDeleteAndEnableHandler 删除 / 行内开关：入参透传；不存在 → 404
// not_found（§1.5 行 189 管理后台单资源）。
func TestDeleteAndEnableHandler(t *testing.T) {
	t.Run("delete 透传", func(t *testing.T) {
		writer := &fakeWriter{}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceDeleteProviderProcedure,
			`{"providerKey":"wx_exist"}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		if writer.deleteKey != "wx_exist" {
			t.Errorf("delete 入参 = %q, want wx_exist", writer.deleteKey)
		}
	})
	t.Run("delete 不存在 404", func(t *testing.T) {
		writer := &fakeWriter{deleteErr: fmt.Errorf("admin service: %w", gorm.ErrRecordNotFound)}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceDeleteProviderProcedure,
			`{"providerKey":"missing"}`, cookie)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", resp.StatusCode, raw)
		}
		if code := decodeErrorCode(t, raw); code != "not_found" {
			t.Errorf("code = %q, want not_found (body %s)", code, raw)
		}
	})
	t.Run("enabled 开关透传（false 非零值语义）", func(t *testing.T) {
		writer := &fakeWriter{}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceSetProviderEnabledProcedure,
			`{"providerKey":"wx_exist","isEnabled":false}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		if writer.enableKey != "wx_exist" || writer.enableTo {
			t.Errorf("enabled 入参 = (%q, %v), want (wx_exist, false)", writer.enableKey, writer.enableTo)
		}
	})
	t.Run("enabled 不存在 404", func(t *testing.T) {
		writer := &fakeWriter{enableErr: fmt.Errorf("admin service: %w", gorm.ErrRecordNotFound)}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceSetProviderEnabledProcedure,
			`{"providerKey":"missing","isEnabled":true}`, cookie)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", resp.StatusCode, raw)
		}
	})
}

// TestSortProvidersHandler 拖拽排序：items 透传到 service（providerKey +
// sortOrder，int64 → int32 收窄）；成功 200。
func TestSortProvidersHandler(t *testing.T) {
	writer := &fakeWriter{}
	tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceSortProvidersProcedure,
		`{"items":[{"providerKey":"smtp_exist","sortOrder":"10"},{"providerKey":"wx_exist","sortOrder":"30"}]}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	if len(writer.sortItems) != 2 ||
		writer.sortItems[0].ProviderKey != "smtp_exist" || writer.sortItems[0].SortOrder != 10 ||
		writer.sortItems[1].ProviderKey != "wx_exist" || writer.sortItems[1].SortOrder != 30 {
		t.Errorf("sort items 透传 = %+v", writer.sortItems)
	}
}

// TestGetProviderTypesHandler 下拉数据源：service 返回项逐字段透传
//（type/category/display_name）；排序归 service 层，此处只验映射。
func TestGetProviderTypesHandler(t *testing.T) {
	writer := &fakeWriter{types: []adminsvc.ProviderTypeInfo{
		{Type: "aliyun_sms", Category: "sms", DisplayName: "阿里云短信"},
		{Type: "wechat_mp", Category: "oauth", DisplayName: "微信小程序"},
	}}
	tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetProviderTypesProcedure, `{}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	var got adminv1.ProviderTypesResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if len(got.GetItems()) != 2 {
		t.Fatalf("items = %d, want 2", len(got.GetItems()))
	}
	for i, want := range []struct{ typ, cat, name string }{
		{"aliyun_sms", "sms", "阿里云短信"},
		{"wechat_mp", "oauth", "微信小程序"},
	} {
		item := got.GetItems()[i]
		if item.GetType() != want.typ || item.GetCategory() != want.cat || item.GetDisplayName() != want.name {
			t.Errorf("items[%d] = %+v, want (%q, %q, %q)", i, item, want.typ, want.cat, want.name)
		}
	}
}

// TestTestProviderHandler 发送测试：{providerKey, target} 透传；非 sms/email
// 类别校验失败 → 400 + ErrorInfo(admin, invalid_request)。
func TestTestProviderHandler(t *testing.T) {
	t.Run("入参透传", func(t *testing.T) {
		writer := &fakeWriter{}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceTestProviderProcedure,
			`{"providerKey":"smtp_exist","target":"alice@example.com"}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		if writer.testKey != "smtp_exist" || writer.testTarget != "alice@example.com" {
			t.Errorf("test 入参 = (%q, %q)", writer.testKey, writer.testTarget)
		}
	})
	t.Run("非 sms/email 类别拒绝 400", func(t *testing.T) {
		writer := &fakeWriter{testErr: adminsvc.ErrInvalidRequest}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, writer)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceTestProviderProcedure,
			`{"providerKey":"wx_exist","target":"alice@example.com"}`, cookie)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, raw)
		}
		if code := decodeErrorCode(t, raw); code != "invalid_argument" {
			t.Errorf("code = %q, want invalid_argument (body %s)", code, raw)
		}
		info := decodeErrorInfo(t, raw)
		if info.GetDomain() != "admin" || info.GetCode() != "invalid_request" {
			t.Errorf("ErrorInfo = (domain=%q code=%q), want (admin, invalid_request)", info.GetDomain(), info.GetCode())
		}
	})
}
