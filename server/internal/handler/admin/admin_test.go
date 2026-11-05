package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	"authloft/internal/eventlog"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	adminsvc "authloft/internal/service/admin"
	"authloft/internal/session"
	"authloft/internal/settings"
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

// fakeUserService 用户管理族（UserService）的 fake：入参全留档断言，
// 错误可注入；返回数据可预置。
type fakeUserService struct {
	meErr     error
	listErr   error
	getErr    error
	statusErr error
	resetErr  error
	unbindErr error
	unlockErr error
	eventsErr error

	meRow     *model.User
	listRows  []model.User
	listTotal int64
	detail    *adminsvc.UserDetail
	events    []model.EventLog
	eventsTot int64

	gotList     adminsvc.ListUsersFilter
	gotMeUID    int64
	gotDetailID int64
	gotStatus   adminsvcStatusCall
	gotReset    adminsvcResetCall
	gotUnbind   adminsvcUnbindCall
	gotUnlockID int64
	gotEvents   adminsvcEventsCall
}

type (
	adminsvcStatusCall struct {
		actor, id int64
		status    int64
	}
	adminsvcResetCall struct {
		actor, id int64
		password  string
	}
	adminsvcUnbindCall struct {
		actor, id int64
		provider  string
	}
	adminsvcEventsCall struct {
		id             int64
		page, pageSize int
	}
)

func (f *fakeUserService) GetMe(_ context.Context, uid int64) (*model.User, error) {
	f.gotMeUID = uid
	return f.meRow, f.meErr
}

func (f *fakeUserService) ListUsers(_ context.Context, flt adminsvc.ListUsersFilter) ([]model.User, int64, error) {
	f.gotList = flt
	return f.listRows, f.listTotal, f.listErr
}

func (f *fakeUserService) GetUser(_ context.Context, id int64) (*adminsvc.UserDetail, error) {
	f.gotDetailID = id
	return f.detail, f.getErr
}

func (f *fakeUserService) UpdateUserStatus(_ context.Context, actor, id int64, status int64) error {
	f.gotStatus = adminsvcStatusCall{actor: actor, id: id, status: status}
	return f.statusErr
}

func (f *fakeUserService) ResetUserPassword(_ context.Context, actor, id int64, password string) error {
	f.gotReset = adminsvcResetCall{actor: actor, id: id, password: password}
	return f.resetErr
}

func (f *fakeUserService) UnbindUserThirdparty(_ context.Context, actor, id int64, providerKey string) error {
	f.gotUnbind = adminsvcUnbindCall{actor: actor, id: id, provider: providerKey}
	return f.unbindErr
}

func (f *fakeUserService) UnlockUser(_ context.Context, id int64) error {
	f.gotUnlockID = id
	return f.unlockErr
}

func (f *fakeUserService) GetUserEvents(_ context.Context, id int64, page, pageSize int) ([]model.EventLog, int64, error) {
	f.gotEvents = adminsvcEventsCall{id: id, page: page, pageSize: pageSize}
	return f.events, f.eventsTot, f.eventsErr
}

// fakeClientService 客户端管理族（ClientService）的 fake：入参全
// 留档断言，错误可注入；返回数据可预置。sso / oidc 共用 err 字段（handler
// 用例只关注拆解 / 归一 / 映射 / 投影，业务规则断言在 service/admin/
// client_test.go）。
type fakeClientService struct {
	listErr error
	getErr  error
	crudErr error // Create / Update / Delete 共用注入位

	ssoRows  []adminsvc.SsoClientDetail
	oidcRows []adminsvc.OidcClientDetail
	total    int64

	ssoDetail  *adminsvc.SsoClientDetail
	oidcDetail *adminsvc.OidcClientDetail

	gotSsoList      adminsvcClientListCall
	gotOidcList     adminsvcClientListCall
	gotCreateSso    adminsvc.SsoClientInput
	gotCreateOidc   adminsvc.OidcClientInput
	gotGetSsoID     int64
	gotGetOidcID    int64
	gotUpdateSso    adminsvcClientUpdateSsoCall
	gotUpdateOidc   adminsvcClientUpdateOidcCall
	gotDeleteSsoID  int64
	gotDeleteOidcID int64
}

type (
	adminsvcClientListCall struct {
		page, pageSize int
		sort, order    string
	}
	adminsvcClientUpdateSsoCall struct {
		id int64
		p  adminsvc.SsoClientPatch
	}
	adminsvcClientUpdateOidcCall struct {
		id int64
		p  adminsvc.OidcClientPatch
	}
)

func (f *fakeClientService) ListSsoClients(_ context.Context, page, pageSize int, sort, order string) ([]adminsvc.SsoClientDetail, int64, error) {
	f.gotSsoList = adminsvcClientListCall{page: page, pageSize: pageSize, sort: sort, order: order}
	return f.ssoRows, f.total, f.listErr
}

func (f *fakeClientService) ListOidcClients(_ context.Context, page, pageSize int, sort, order string) ([]adminsvc.OidcClientDetail, int64, error) {
	f.gotOidcList = adminsvcClientListCall{page: page, pageSize: pageSize, sort: sort, order: order}
	return f.oidcRows, f.total, f.listErr
}

func (f *fakeClientService) CreateSsoClient(_ context.Context, in adminsvc.SsoClientInput) error {
	f.gotCreateSso = in
	return f.crudErr
}

func (f *fakeClientService) CreateOidcClient(_ context.Context, in adminsvc.OidcClientInput) error {
	f.gotCreateOidc = in
	return f.crudErr
}

func (f *fakeClientService) GetSsoClient(_ context.Context, id int64) (*adminsvc.SsoClientDetail, error) {
	f.gotGetSsoID = id
	return f.ssoDetail, f.getErr
}

func (f *fakeClientService) GetOidcClient(_ context.Context, id int64) (*adminsvc.OidcClientDetail, error) {
	f.gotGetOidcID = id
	return f.oidcDetail, f.getErr
}

func (f *fakeClientService) UpdateSsoClient(_ context.Context, id int64, p adminsvc.SsoClientPatch) error {
	f.gotUpdateSso = adminsvcClientUpdateSsoCall{id: id, p: p}
	return f.crudErr
}

func (f *fakeClientService) UpdateOidcClient(_ context.Context, id int64, p adminsvc.OidcClientPatch) error {
	f.gotUpdateOidc = adminsvcClientUpdateOidcCall{id: id, p: p}
	return f.crudErr
}

func (f *fakeClientService) DeleteSsoClient(_ context.Context, id int64) error {
	f.gotDeleteSsoID = id
	return f.crudErr
}

func (f *fakeClientService) DeleteOidcClient(_ context.Context, id int64) error {
	f.gotDeleteOidcID = id
	return f.crudErr
}

// fakeSettingsService settings/事件/工具族（SettingsService）的 fake：
// 入参全留档断言，错误可注入；返回数据可预置。业务规则断言
// （全量替换、审计、分页透传等）在 service/admin/settings_test.go，本文件
// 只关注 Connect 形态映射 / 分页归一 / 错误码投影。
type fakeSettingsService struct {
	snap     map[string]any
	setErr   error
	listErr  error
	decode   proto.Message
	decodeFn func(purpose, token string) (proto.Message, error)
	status   adminsvc.QueueStatus

	gotSet   adminsvcSettingsSetCall
	gotList  adminsvc.EventListFilter
	gotDcd   adminsvcDecodeCall
	getCalls int
}

type (
	adminsvcSettingsSetCall struct {
		actor int64
		req   *adminv1.SetSettingsRequest
	}
	adminsvcDecodeCall struct {
		purpose string
		token   string
	}
)

func (f *fakeSettingsService) GetSettings() map[string]any {
	f.getCalls++
	return f.snap
}

func (f *fakeSettingsService) SetSettings(_ context.Context, actor int64, req *adminv1.SetSettingsRequest) error {
	f.gotSet = adminsvcSettingsSetCall{actor: actor, req: req}
	return f.setErr
}

func (f *fakeSettingsService) ListEvents(_ context.Context, flt adminsvc.EventListFilter) ([]model.EventLog, int64, error) {
	f.gotList = flt
	return []model.EventLog{
		{ID: 9, Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, CreatedAt: time.Unix(1700000000, 0)},
	}, 1, f.listErr
}

func (f *fakeSettingsService) DecodeToken(purpose, token string) (proto.Message, error) {
	f.gotDcd = adminsvcDecodeCall{purpose: purpose, token: token}
	if f.decodeFn != nil {
		return f.decodeFn(purpose, token)
	}
	return f.decode, f.setErr
}

func (f *fakeSettingsService) GetStatus() adminsvc.QueueStatus {
	return f.status
}

// newAdminHandler 构造挂真实 session + admin 拦截链（链序同装配：session
// 在外注入身份、admin 在内判 uid，§3.14 行 494）的生成 handler，返回签发
// 助手与 http.Handler（口径同 handler/account/account_test.go）。writer 传
// nil 时用 no-op fake（读路径用例不触写族）；users 为用户族 fake
//（variadic——既有用例零改动，缺省 no-op）；clients 为
// 客户端族 fake，既有用例缺省 no-op，客户端用例经 newAdminHandlerClients
// 注入（variadic 只能一个，故拆两个入口、共享 assembleAdminHandler）。
func newAdminHandler(t *testing.T, providers ProviderReader, writer ProviderService, users ...UserService) (*session.Tokens, *fakeEpochReader, http.Handler) {
	t.Helper()
	if writer == nil {
		writer = &fakeWriter{}
	}
	var user UserService = &fakeUserService{}
	if len(users) > 0 && users[0] != nil {
		user = users[0]
	}
	return assembleAdminHandler(t, providers, writer, user, &fakeClientService{}, &fakeSettingsService{})
}

// newAdminHandlerSettings settings/工具族用例的构造入口（其余 service 全部
// no-op——settings 用例不触它们）。
func newAdminHandlerSettings(t *testing.T, settings SettingsService) (*session.Tokens, *fakeEpochReader, http.Handler) {
	t.Helper()
	return assembleAdminHandler(t, &fakeProviders{}, &fakeWriter{}, &fakeUserService{}, &fakeClientService{}, settings)
}

// newAdminHandlerClients 客户端管理族用例的构造入口（providers / writer /
// users 全部 no-op——客户端用例不触它们）。
func newAdminHandlerClients(t *testing.T, clients ClientService) (*session.Tokens, *fakeEpochReader, http.Handler) {
	t.Helper()
	return assembleAdminHandler(t, &fakeProviders{}, &fakeWriter{}, &fakeUserService{}, clients, &fakeSettingsService{})
}

// assembleAdminHandler newAdminHandler / newAdminHandlerClients /
// newAdminHandlerSettings 的公共主体。
func assembleAdminHandler(t *testing.T, providers ProviderReader, writer ProviderService, user UserService, clients ClientService, settings SettingsService) (*session.Tokens, *fakeEpochReader, http.Handler) {
	t.Helper()
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
		New(providers, writer, user, clients, settings),
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

// —— settings/事件/工具族 5 方法（handler 层：Connect 形态映射 +
// 入参透传 + 分页归一；业务规则断言在 service/admin/settings_test.go）——
//（TestStubsUnimplemented 随桩清单清空而删除：33 方法全部实装，无桩可断言。）

// TestGetSettingsHandler 管理员会话取全部系统配置：Snapshot 原样经
// dto.AdminSettings 投影（35 键全键，键名对 §5.6 四张表逐键一致）——响应
// 按 protojson UseProtoNames 回放为 snake 键名与快照逐键比对（同时验证
// 键名零自造与投影完整性）。
func TestGetSettingsHandler(t *testing.T) {
	fake := &fakeSettingsService{snap: settings.Defaults()}
	tokens, epochs, h := newAdminHandlerSettings(t, fake)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetSettingsProcedure, `{}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	var out adminv1.SettingsResponse
	if err := protojson.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("unmarshal: %v (body %s)", err, raw)
	}
	// UseProtoNames + EmitUnpopulated：仅用于测试侧回放 proto 消息为
	// snake 键名全集（= §5.6 键 = settings 常量），验证 35 字段键名零自造
	// 与投影完整性；线上序列化零值省略是标准 protojson 行为（§12.9 行
	// 1779），不在此断言。
	b, err := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(&out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	want := settings.Defaults()
	if len(got) != len(want) {
		t.Fatalf("响应键数 = %d, want %d（§5.6 四张表全键）", len(got), len(want))
	}
	for k, v := range want {
		g, ok := got[k]
		if !ok {
			t.Fatalf("键 %q 缺失（§5.6 键集应零自造）", k)
		}
		switch wv := v.(type) {
		case int64:
			gs, ok := g.(string)
			if !ok || gs != strconv.FormatInt(wv, 10) {
				t.Errorf("键 %q = %v, want %d", k, g, wv)
			}
		case bool, string:
			if g != any(wv) {
				t.Errorf("键 %q = %v, want %v", k, g, wv)
			}
		case []string:
			ga, ok := g.([]any)
			if !ok || len(ga) != len(wv) {
				t.Errorf("键 %q = %v, want %v", k, g, wv)
			}
		}
	}
}

// TestSetSettingsHandler 全量提交：请求体原样绑定到 flat 消息透传 service，
// actor 取会话 uid（审计口径在 service）；service 校验失败 → 400 +
// ErrorInfo(admin, invalid_request)。
func TestSetSettingsHandler(t *testing.T) {
	t.Run("合法提交透传且 actor=会话 uid", func(t *testing.T) {
		fake := &fakeSettingsService{}
		tokens, epochs, h := newAdminHandlerSettings(t, fake)
		cookie := adminCookie(t, tokens, epochs, 1)

		body := `{"pwdMinLength":10,"allowRegistration":false,"ssoDomains":["https://a.example.com"],"cookieName":"al_session"}`
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceSetSettingsProcedure, body, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		if fake.gotSet.actor != 1 {
			t.Errorf("actor = %d, want 1（会话 uid）", fake.gotSet.actor)
		}
		if fake.gotSet.req.GetPwdMinLength() != 10 || fake.gotSet.req.GetAllowRegistration() {
			t.Errorf("req 字段绑定错误: %+v", fake.gotSet.req)
		}
		if got := fake.gotSet.req.GetSsoDomains(); len(got) != 1 || got[0] != "https://a.example.com" {
			t.Errorf("ssoDomains = %v", got)
		}
	})
	t.Run("校验失败映射 invalid_request", func(t *testing.T) {
		fake := &fakeSettingsService{setErr: adminsvc.ErrInvalidRequest}
		tokens, epochs, h := newAdminHandlerSettings(t, fake)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceSetSettingsProcedure, `{}`, cookie)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, raw)
		}
		if info := decodeErrorInfo(t, raw); info.Code != "invalid_request" || info.Domain != "admin" {
			t.Errorf("ErrorInfo = %v, want admin/invalid_request", info)
		}
	})
}

// TestListEventsHandler 统一事件视图：optional 指针原样透传（nil 不过滤）、
// 分页归一（page 0 → 1、pageSize 0 → 20、>100 clamp）+ sort/order 透传，
// 行经 dto.AdminEventItem 投影（detail msgpack → JSON 在 dto）。
func TestListEventsHandler(t *testing.T) {
	fake := &fakeSettingsService{}
	tokens, epochs, h := newAdminHandlerSettings(t, fake)
	cookie := adminCookie(t, tokens, epochs, 1)

	body := `{"event":"login_success","actorType":"user","actorId":"42","userId":"42",` +
		`"from":"1700000000","to":"1700003600","page":"0","pageSize":"200","sort":"created_at","order":"asc"}`
	resp, raw := doRPC(t, h, adminv1connect.AdminServiceListEventsProcedure, body, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	flt := fake.gotList
	if flt.Event != "login_success" || flt.ActorType != "user" {
		t.Errorf("筛选透传错误: %+v", flt)
	}
	if flt.ActorID == nil || *flt.ActorID != 42 || flt.UserID == nil || *flt.UserID != 42 {
		t.Errorf("optional 指针透传错误: %+v", flt)
	}
	if flt.From == nil || *flt.From != 1700000000 || flt.To == nil || *flt.To != 1700003600 {
		t.Errorf("from/to 透传错误: %+v", flt)
	}
	if flt.Page != 1 || flt.PageSize != 100 {
		t.Errorf("分页归一错误: page=%d pageSize=%d, want 1/100", flt.Page, flt.PageSize)
	}
	if flt.Sort != "created_at" || flt.Order != "asc" {
		t.Errorf("sort/order 透传错误: %+v", flt)
	}
	var out struct {
		Items    []json.RawMessage `json:"items"`
		Total    string            `json:"total"`
		Page     string            `json:"page"`
		PageSize string            `json:"pageSize"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("json: %v (body %s)", err, raw)
	}
	if out.Total != "1" || out.Page != "1" || out.PageSize != "100" || len(out.Items) != 1 {
		t.Errorf("响应分页字段错误: %s", raw)
	}
}

// TestDecodeTokenHandler 解码成功 → payload Struct 透出；service 报
// invalid_request（非法 purpose / 解码失败 / cookie 载荷 schema 未落地）→
// 400 + ErrorInfo(admin, invalid_request)，且响应体不含 token 内容。
func TestDecodeTokenHandler(t *testing.T) {
	t.Run("成功投影", func(t *testing.T) {
		ks := testKeyStore(t)
		codec := security.NewCodec(ks)
		tokStr := sealToken(t, codec, security.PurposeSession, &token.SessionTokenPayload{Id: 7, Epoch: 3, Sid: "sid-x", Amr: []string{"pwd"}, Iat: 100, Exp: 200})
		fake := &fakeSettingsService{decodeFn: func(purpose, tk string) (proto.Message, error) {
			return security.Open[token.SessionTokenPayload](codec, security.PurposeSession, tk)
		}}
		tokens, epochs, h := newAdminHandlerSettings(t, fake)
		cookie := adminCookie(t, tokens, epochs, 1)

		body, _ := json.Marshal(map[string]string{"purpose": "session", "token": tokStr})
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceDecodeTokenProcedure, string(body), cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		var out struct {
			Payload struct {
				ID    string   `json:"id"`
				Epoch string   `json:"epoch"`
				Sid   string   `json:"sid"`
				Amr   []string `json:"amr"`
			} `json:"payload"`
		}
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatalf("json: %v (body %s)", err, raw)
		}
		if out.Payload.ID != "7" || out.Payload.Epoch != "3" || out.Payload.Sid != "sid-x" {
			t.Errorf("payload 投影错误: %s", raw)
		}
		if len(out.Payload.Amr) != 1 || out.Payload.Amr[0] != "pwd" {
			t.Errorf("amr = %v, want [pwd]（camelCase + EmitUnpopulated 口径）", out.Payload.Amr)
		}
	})
	t.Run("解码失败映射 invalid_request 且不落 token", func(t *testing.T) {
		fake := &fakeSettingsService{decodeFn: func(string, string) (proto.Message, error) {
			return nil, adminsvc.ErrInvalidRequest
		}}
		tokens, epochs, h := newAdminHandlerSettings(t, fake)
		cookie := adminCookie(t, tokens, epochs, 1)

		resp, raw := doRPC(t, h, adminv1connect.AdminServiceDecodeTokenProcedure, `{"purpose":"cookie","token":"whatever"}`, cookie)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, raw)
		}
		if info := decodeErrorInfo(t, raw); info.Code != "invalid_request" || info.Domain != "admin" {
			t.Errorf("ErrorInfo = %v, want admin/invalid_request", info)
		}
		if strings.Contains(raw, "whatever") {
			t.Errorf("错误体不得回显 token 内容: %s", raw)
		}
	})
}

// TestGetStatusHandler 监控三字段只读透传。
func TestGetStatusHandler(t *testing.T) {
	fake := &fakeSettingsService{status: adminsvc.QueueStatus{QueueLength: 7, Dropped: 3, FlushMs: 25}}
	tokens, epochs, h := newAdminHandlerSettings(t, fake)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetStatusProcedure, `{}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	var out struct {
		QueueLength string `json:"queueLength"`
		Dropped     string `json:"dropped"`
		FlushMs     string `json:"flushMs"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("json: %v (body %s)", err, raw)
	}
	if out.QueueLength != "7" || out.Dropped != "3" || out.FlushMs != "25" {
		t.Errorf("status 三字段 = %s/%s/%s, want 7/3/25", out.QueueLength, out.Dropped, out.FlushMs)
	}
}

// testKeyStore / sealToken DecodeToken handler 用例的编解码 helper：与
// assembleAdminHandler 同款 32B 密钥（仅用于签发已知令牌，解密走
// service/admin/settings_test.go 的独立 codec——本文件只测 Connect 形态）。
func testKeyStore(t *testing.T) *security.KeyStore {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x40 + i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return ks
}

func sealToken(t *testing.T, c *security.Codec, purpose string, msg proto.Message) string {
	t.Helper()
	tokStr, err := c.Seal(purpose, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return tokStr
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
// 「改 key 拒绝」等校验失败 → 400 + ErrorInfo(admin, invalid_request)。
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
// （type/category/display_name）；排序归 service 层，此处只验映射。
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

// —— 用户管理族 handler 用例（§5.1 行 1162、§5.4 行 1249-1255）——

// adminUserRow 用户族用例的 user 行（phone / email / 时间齐备）。
func adminUserRow() *model.User {
	phone, email := "13800138000", "alice@example.com"
	now := time.Unix(1761700000, 0).UTC()
	return &model.User{
		ID: 42, Username: "alice", Nickname: "Alice", AvatarURL: "https://cdn.example.com/a.png",
		Phone: &phone, Email: &email, PhoneVerified: 1, EmailVerified: 1,
		UserStatus: 1, MfaRequired: 1, Epoch: 3, CreatedAt: now, UpdatedAt: now,
	}
}

// TestGetMeHandler 覆盖清单：GetMe 四字段 + isAdmin 恒 true（§5.1 行 1162）；
// uid 从 session ctx 取（= cookie uid）；行缺失 404。
func TestGetMeHandler(t *testing.T) {
	users := &fakeUserService{meRow: adminUserRow()}
	tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil, users)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetMeProcedure, `{}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	var got adminv1.MeResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetId() != 42 || got.GetUsername() != "alice" || got.GetNickname() != "Alice" ||
		got.GetAvatarUrl() != "https://cdn.example.com/a.png" || !got.GetIsAdmin() {
		t.Fatalf("GetMe = %+v, want 四字段 + isAdmin=true", &got)
	}
	if users.gotMeUID != 1 {
		t.Errorf("uid 透传 = %d, want 1（session ctx）", users.gotMeUID)
	}

	// 行缺失（安装账号被删的脏数据）→ 404。
	notFound := &fakeUserService{meErr: gorm.ErrRecordNotFound}
	tokens2, epochs2, h2 := newAdminHandler(t, &fakeProviders{}, nil, notFound)
	resp, raw = doRPC(t, h2, adminv1connect.AdminServiceGetMeProcedure, `{}`, adminCookie(t, tokens2, epochs2, 1))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("行缺失 status = %d, want 404 (body %s)", resp.StatusCode, raw)
	}
}

// TestListUsersHandler：{q, userStatus} + 分页透传（归一后回显 page/pageSize）、
// {items,total,page,pageSize} 响应形态、AdminUser 列投影。
func TestListUsersHandler(t *testing.T) {
	users := &fakeUserService{listRows: []model.User{*adminUserRow()}, listTotal: 1}
	tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil, users)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceListUsersProcedure,
		`{"q":"ali","userStatus":1,"page":0,"pageSize":2,"sort":"created_at","order":"asc"}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	var got adminv1.UserListResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetTotal() != 1 || got.GetPage() != 1 || got.GetPageSize() != 2 || len(got.GetItems()) != 1 {
		t.Fatalf("响应 = (total=%d page=%d size=%d items=%d)", got.GetTotal(), got.GetPage(), got.GetPageSize(), len(got.GetItems()))
	}
	item := got.GetItems()[0]
	if item.GetId() != 42 || item.GetUsername() != "alice" || item.GetPhone() != "13800138000" ||
		item.GetEmail() != "alice@example.com" || item.GetUserStatus() != 1 || item.GetMfaRequired() != 1 {
		t.Fatalf("列表项 = %+v", item)
	}
	flt := users.gotList
	if flt.Q != "ali" || flt.UserStatus == nil || *flt.UserStatus != 1 ||
		flt.Page != 1 || flt.PageSize != 2 || flt.Sort != "created_at" || flt.Order != "asc" {
		t.Errorf("透传 = %+v, want q=ali status=1 page=1(归一) size=2", flt)
	}
}

// TestGetUserHandler：详情 = user 投影 + 凭证概览（kind/is_enabled，含
// mfa_setting 行）+ 绑定列表 + mfa 五因子明细（otp_sms bound + 掩码 target）。
func TestGetUserHandler(t *testing.T) {
	now := time.Unix(1761700000, 0).UTC()
	users := &fakeUserService{detail: &adminsvc.UserDetail{
		User: adminUserRow(),
		Credentials: []model.UserCredential{
			{ID: 7, UserID: 42, Kind: "password", IsEnabled: 1, CreatedAt: now},
			{ID: 8, UserID: 42, Kind: "mfa_setting", IsEnabled: 1, CreatedAt: now},
		},
		Bindings: []model.UserThirdpartyBind{
			{ID: 9, UserID: 42, ProviderKey: "wechat_mp_1", OpenID: "oX-1", CreatedAt: now},
		},
	}}
	tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil, users)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetUserProcedure, `{"id":42}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	var got adminv1.UserDetailResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetUser().GetId() != 42 || got.GetUser().GetMfaRequired() != 1 {
		t.Fatalf("user 投影 = %+v", got.GetUser())
	}
	if len(got.GetCredentials()) != 2 || got.GetCredentials()[0].GetKind() != "password" ||
		!got.GetCredentials()[0].GetIsEnabled() || got.GetCredentials()[1].GetKind() != "mfa_setting" {
		t.Fatalf("凭证概览 = %+v", got.GetCredentials())
	}
	if len(got.GetBindings()) != 1 || got.GetBindings()[0].GetProviderKey() != "wechat_mp_1" ||
		got.GetBindings()[0].GetOpenId() != "oX-1" {
		t.Fatalf("绑定列表 = %+v", got.GetBindings())
	}
	if len(got.GetMfa().GetFactors()) != 5 {
		t.Fatalf("mfa 五因子 = %d 项", len(got.GetMfa().GetFactors()))
	}
	for _, f := range got.GetMfa().GetFactors() {
		switch f.GetFactor() {
		case "totp", "webauthn", "recovery_code":
			if f.GetBound() {
				t.Errorf("factor %q 未绑定应 false", f.GetFactor())
			}
		case "otp_sms":
			if !f.GetBound() || f.GetTarget() != "138****8000" {
				t.Errorf("otp_sms = (bound=%v target=%q), want (true, 138****8000)", f.GetBound(), f.GetTarget())
			}
		case "otp_email":
			if !f.GetBound() || f.GetTarget() != "a***@example.com" {
				t.Errorf("otp_email = (bound=%v target=%q)", f.GetBound(), f.GetTarget())
			}
		}
	}
	if users.gotDetailID != 42 {
		t.Errorf("id 透传 = %d", users.gotDetailID)
	}
}

// TestUserWriteHandlers：UpdateUserStatus / ResetUserPassword /
// UnbindUserThirdparty / UnlockUser 四写方法——入参（含 actor=ctx uid）透传 +
// OkResponse；错误映射：invalid_request 与 password_weak → 400 +
// ErrorInfo(admin)；404 → not_found。
func TestUserWriteHandlers(t *testing.T) {
	const reqStatus = `{"id":42,"userStatus":0}`
	const reqReset = `{"id":42,"password":"Str0ngPass!"}`
	const reqUnbind = `{"id":42,"providerKey":"wechat_mp_1"}`
	const reqUnlock = `{"id":42}`

	t.Run("透传与空应答", func(t *testing.T) {
		users := &fakeUserService{}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil, users)
		cookie := adminCookie(t, tokens, epochs, 1)

		for target, body := range map[string]string{
			adminv1connect.AdminServiceUpdateUserStatusProcedure:     reqStatus,
			adminv1connect.AdminServiceResetUserPasswordProcedure:    reqReset,
			adminv1connect.AdminServiceUnbindUserThirdpartyProcedure: reqUnbind,
			adminv1connect.AdminServiceUnlockUserProcedure:           reqUnlock,
		} {
			resp, raw := doRPC(t, h, target, body, cookie)
			if resp.StatusCode != http.StatusOK || raw != "{}" {
				t.Fatalf("%s: (%d, %s), want (200, {})", target, resp.StatusCode, raw)
			}
		}
		want := adminsvcStatusCall{actor: 1, id: 42, status: 0}
		if users.gotStatus != want {
			t.Errorf("status 透传 = %+v, want %+v", users.gotStatus, want)
		}
		if users.gotReset != (adminsvcResetCall{actor: 1, id: 42, password: "Str0ngPass!"}) {
			t.Errorf("reset 透传 = %+v", users.gotReset)
		}
		if users.gotUnbind != (adminsvcUnbindCall{actor: 1, id: 42, provider: "wechat_mp_1"}) {
			t.Errorf("unbind 透传 = %+v", users.gotUnbind)
		}
		if users.gotUnlockID != 42 {
			t.Errorf("unlock 透传 = %d", users.gotUnlockID)
		}
	})

	t.Run("invalid_request 映射", func(t *testing.T) {
		users := &fakeUserService{statusErr: adminsvc.ErrInvalidRequest}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil, users)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceUpdateUserStatusProcedure, reqStatus, cookie)
		if resp.StatusCode != http.StatusBadRequest || decodeErrorCode(t, raw) != "invalid_argument" {
			t.Fatalf("status=%d raw=%s", resp.StatusCode, raw)
		}
		info := decodeErrorInfo(t, raw)
		if info.GetDomain() != "admin" || info.GetCode() != "invalid_request" {
			t.Errorf("ErrorInfo = (%q, %q)", info.GetDomain(), info.GetCode())
		}
	})

	t.Run("password_weak 映射（§1.6 封闭集合）", func(t *testing.T) {
		users := &fakeUserService{resetErr: adminsvc.ErrPasswordWeak}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil, users)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceResetUserPasswordProcedure, reqReset, cookie)
		if resp.StatusCode != http.StatusBadRequest || decodeErrorCode(t, raw) != "invalid_argument" {
			t.Fatalf("status=%d raw=%s", resp.StatusCode, raw)
		}
		info := decodeErrorInfo(t, raw)
		if info.GetDomain() != "admin" || info.GetCode() != "password_weak" {
			t.Errorf("ErrorInfo = (%q, %q), want (admin, password_weak)", info.GetDomain(), info.GetCode())
		}
	})

	t.Run("404 映射", func(t *testing.T) {
		users := &fakeUserService{unlockErr: gorm.ErrRecordNotFound}
		tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil, users)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceUnlockUserProcedure, reqUnlock, cookie)
		if resp.StatusCode != http.StatusNotFound || decodeErrorCode(t, raw) != "not_found" {
			t.Fatalf("status=%d raw=%s", resp.StatusCode, raw)
		}
	})
}

// TestGetUserEventsHandler：{id} + 分页透传 + EventItem 投影（detail msgpack
// → JSON 对象；事件类型固定 login_success 由 service 过滤）。
func TestGetUserEventsHandler(t *testing.T) {
	now := time.Unix(1761700000, 0).UTC()
	users := &fakeUserService{
		events: []model.EventLog{{
			ID: 3, Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42,
			AMR: "pwd", IP: "1.2.3.4", UA: "curl/8", Detail: eventlog.DetailLoginSuccess("pwd", "", "sid-x", ""),
			CreatedAt: now,
		}},
		eventsTot: 7,
	}
	tokens, epochs, h := newAdminHandler(t, &fakeProviders{}, nil, users)
	cookie := adminCookie(t, tokens, epochs, 1)

	resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetUserEventsProcedure,
		`{"id":42,"page":0,"pageSize":5}`, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	var got adminv1.UserEventsResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetTotal() != 7 || got.GetPage() != 1 || got.GetPageSize() != 5 || len(got.GetItems()) != 1 {
		t.Fatalf("响应 = (total=%d page=%d size=%d items=%d)", got.GetTotal(), got.GetPage(), got.GetPageSize(), len(got.GetItems()))
	}
	item := got.GetItems()[0]
	if item.GetEvent() != "login_success" || item.GetUserId() != 42 || item.GetIp() != "1.2.3.4" {
		t.Fatalf("事件项 = %+v", item)
	}
	detail := item.GetDetail().GetFields()
	if detail["factor"].GetStringValue() != "pwd" || detail["session_id"].GetStringValue() != "sid-x" {
		t.Fatalf("detail = %+v, want factor=pwd session_id=sid-x（msgpack → JSON）", detail)
	}
	if users.gotEvents != (adminsvcEventsCall{id: 42, page: 1, pageSize: 5}) {
		t.Errorf("分页透传 = %+v", users.gotEvents)
	}
}

// —— 客户端管理族 10 方法（handler 层：拆解 / 归一 / 映射 / 投影；
// 业务规则断言在 service/admin/client_test.go）——

// TestClientListHandlers：§1.7 分页归一（page=0 → 1、pageSize=200 → 100）+
// 列表投影（明文 secret、redirect_uris、OIDC scopes/TTL）+ 空页 items 省略
// （§1.7 行 278，proto3 空 repeated 不输出）；sort / order 接收但透传面无此
// 参数（repo 固定 ORDER BY id ASC，默认）。
func TestClientListHandlers(t *testing.T) {
	now := time.Unix(1761700000, 0).UTC()
	ssoRow := &model.SsoClient{
		ID: 7, ClientID: "portal-main", ClientSecret: "sec-plain-64", Name: "门户",
		CreatedAt: now, UpdatedAt: now,
	}
	oidcRow := &model.OidcClient{
		ID: 8, ClientID: "oidc-app", ClientSecret: "oidc-sec-64", Name: "OIDC",
		Scopes: "openid,profile", AccessTokenTTL: 1800, RefreshTokenTTL: 864000,
		CreatedAt: now, UpdatedAt: now,
	}

	t.Run("SSO 分页归一与投影", func(t *testing.T) {
		clients := &fakeClientService{
			ssoRows: []adminsvc.SsoClientDetail{{Row: ssoRow, RedirectURIs: []string{"*"}}},
			total:   1,
		}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceListSsoClientsProcedure,
			`{"page":0,"pageSize":200,"sort":"created_at","order":"desc"}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		var got adminv1.SsoClientListResponse
		if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("decode response %q: %v", raw, err)
		}
		if got.GetTotal() != 1 || got.GetPage() != 1 || got.GetPageSize() != 100 || len(got.GetItems()) != 1 {
			t.Fatalf("响应 = (total=%d page=%d size=%d items=%d)", got.GetTotal(), got.GetPage(), got.GetPageSize(), len(got.GetItems()))
		}
		item := got.GetItems()[0]
		if item.GetId() != 7 || item.GetClientId() != "portal-main" || item.GetClientSecret() != "sec-plain-64" ||
			item.GetName() != "门户" || len(item.GetRedirectUris()) != 1 || item.GetRedirectUris()[0] != "*" {
			t.Fatalf("列表项 = %+v", item)
		}
		if clients.gotSsoList != (adminsvcClientListCall{page: 1, pageSize: 100, sort: "created_at", order: "desc"}) {
			t.Errorf("分页归一透传 = %+v, want (1, 100, created_at, desc)", clients.gotSsoList)
		}
	})
	t.Run("SSO 空页 items 省略", func(t *testing.T) {
		clients := &fakeClientService{}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceListSsoClientsProcedure, `{"page":9}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		if strings.Contains(raw, `"items"`) {
			t.Errorf("空页 items 应省略（§1.7 行 278）, raw = %s", raw)
		}
		var got adminv1.SsoClientListResponse
		if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("decode response %q: %v", raw, err)
		}
		if got.GetTotal() != 0 || got.GetPage() != 9 || got.GetPageSize() != 20 || len(got.GetItems()) != 0 {
			t.Fatalf("响应 = (total=%d page=%d size=%d items=%d)", got.GetTotal(), got.GetPage(), got.GetPageSize(), len(got.GetItems()))
		}
	})
	t.Run("OIDC 分页归一与投影", func(t *testing.T) {
		clients := &fakeClientService{
			oidcRows: []adminsvc.OidcClientDetail{{
				Row: oidcRow, RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes: []string{"openid", "profile"},
			}},
			total: 1,
		}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceListOidcClientsProcedure,
			`{"page":3,"pageSize":0}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		var got adminv1.OidcClientListResponse
		if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("decode response %q: %v", raw, err)
		}
		if got.GetPage() != 3 || got.GetPageSize() != 20 || len(got.GetItems()) != 1 {
			t.Fatalf("响应 = (page=%d size=%d items=%d)", got.GetPage(), got.GetPageSize(), len(got.GetItems()))
		}
		item := got.GetItems()[0]
		if item.GetClientSecret() != "oidc-sec-64" || item.GetAccessTokenTtl() != 1800 || item.GetRefreshTokenTtl() != 864000 ||
			len(item.GetScopes()) != 2 || item.GetScopes()[0] != "openid" || item.GetScopes()[1] != "profile" {
			t.Fatalf("列表项 = %+v", item)
		}
		if clients.gotOidcList != (adminsvcClientListCall{page: 3, pageSize: 20}) {
			t.Errorf("分页归一透传 = %+v", clients.gotOidcList)
		}
	})
}

// TestClientGetHandlers：{id} 定位透传 + 详情投影（明文 secret、uris、OIDC
// scopes/TTL）+ 404 映射。
func TestClientGetHandlers(t *testing.T) {
	now := time.Unix(1761700000, 0).UTC()
	ssoRow := &model.SsoClient{
		ID: 7, ClientID: "portal-main", ClientSecret: "sec-plain-64", Name: "门户",
		CreatedAt: now, UpdatedAt: now,
	}
	oidcRow := &model.OidcClient{
		ID: 8, ClientID: "oidc-app", ClientSecret: "oidc-sec-64",
		Scopes: "openid", AccessTokenTTL: 1800, RefreshTokenTTL: 864000,
		CreatedAt: now, UpdatedAt: now,
	}

	t.Run("SSO 详情含明文 secret", func(t *testing.T) {
		clients := &fakeClientService{
			ssoDetail: &adminsvc.SsoClientDetail{Row: ssoRow, RedirectURIs: []string{"https://app.example.com/cb"}},
		}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetSsoClientProcedure, `{"id":7}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		var got adminv1.SsoClient
		if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("decode response %q: %v", raw, err)
		}
		if got.GetId() != 7 || got.GetClientId() != "portal-main" || got.GetClientSecret() != "sec-plain-64" ||
			len(got.GetRedirectUris()) != 1 || got.GetRedirectUris()[0] != "https://app.example.com/cb" {
			t.Fatalf("详情 = %+v", &got)
		}
		if clients.gotGetSsoID != 7 {
			t.Errorf("id 透传 = %d, want 7", clients.gotGetSsoID)
		}
	})
	t.Run("OIDC 详情投影", func(t *testing.T) {
		clients := &fakeClientService{
			oidcDetail: &adminsvc.OidcClientDetail{
				Row: oidcRow, RedirectURIs: []string{"*"}, Scopes: []string{"openid"},
			},
		}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceGetOidcClientProcedure, `{"id":8}`, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
		}
		var got adminv1.OidcClient
		if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("decode response %q: %v", raw, err)
		}
		if got.GetClientSecret() != "oidc-sec-64" || got.GetAccessTokenTtl() != 1800 ||
			len(got.GetScopes()) != 1 || got.GetScopes()[0] != "openid" || len(got.GetRedirectUris()) != 1 {
			t.Fatalf("详情 = %+v", &got)
		}
		if clients.gotGetOidcID != 8 {
			t.Errorf("id 透传 = %d, want 8", clients.gotGetOidcID)
		}
	})
	t.Run("404 映射", func(t *testing.T) {
		clients := &fakeClientService{getErr: gorm.ErrRecordNotFound}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)
		for _, target := range []string{
			adminv1connect.AdminServiceGetSsoClientProcedure,
			adminv1connect.AdminServiceGetOidcClientProcedure,
		} {
			resp, raw := doRPC(t, h, target, `{"id":99}`, cookie)
			if resp.StatusCode != http.StatusNotFound || decodeErrorCode(t, raw) != "not_found" {
				t.Fatalf("%s: status=%d raw=%s", target, resp.StatusCode, raw)
			}
		}
	})
}

// TestClientWriteHandlers：Create / Update / Delete 的请求拆解透传（Create
// 请求中的 client_secret 字段被忽略——SsoClientInput/OidcClientInput 无该
// 字段，服务端生成口径由类型系统挡住）+ OkResponse 空应答 + 错误三态映射
// （invalid_request 400+ErrorInfo / already_exists 409 / not_found 404）。
func TestClientWriteHandlers(t *testing.T) {
	const reqCreateSso = `{"clientId":"portal-x","clientSecret":"should-be-ignored","name":"门户","redirectUris":["*"]}`
	const reqUpdateSso = `{"id":7,"clientId":"portal-x","clientSecret":"rotated-sec","name":"新名","redirectUris":["https://app.example.com/cb"]}`
	const reqDeleteSso = `{"id":7}`
	const reqCreateOidc = `{"clientId":"oidc-x","clientSecret":"should-be-ignored","name":"OIDC","redirectUris":["https://a.example.com/cb"],"scopes":["openid","profile"],"accessTokenTtl":1800,"refreshTokenTtl":864000}`
	const reqUpdateOidc = `{"id":8,"name":"改名","scopes":["openid"],"accessTokenTtl":7200,"refreshTokenTtl":2592000}`
	const reqDeleteOidc = `{"id":8}`

	t.Run("透传与空应答", func(t *testing.T) {
		clients := &fakeClientService{}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)

		for target, body := range map[string]string{
			adminv1connect.AdminServiceCreateSsoClientProcedure:  reqCreateSso,
			adminv1connect.AdminServiceUpdateSsoClientProcedure:  reqUpdateSso,
			adminv1connect.AdminServiceDeleteSsoClientProcedure:  reqDeleteSso,
			adminv1connect.AdminServiceCreateOidcClientProcedure: reqCreateOidc,
			adminv1connect.AdminServiceUpdateOidcClientProcedure: reqUpdateOidc,
			adminv1connect.AdminServiceDeleteOidcClientProcedure: reqDeleteOidc,
		} {
			resp, raw := doRPC(t, h, target, body, cookie)
			if resp.StatusCode != http.StatusOK || raw != "{}" {
				t.Fatalf("%s: (%d, %s), want (200, {})", target, resp.StatusCode, raw)
			}
		}
		cs := clients.gotCreateSso
		if cs.ClientID != "portal-x" || cs.Name != "门户" || len(cs.RedirectURIs) != 1 || cs.RedirectURIs[0] != "*" {
			t.Errorf("create sso 透传 = %+v", cs)
		}
		us := clients.gotUpdateSso
		if us.id != 7 || us.p.ClientID != "portal-x" || us.p.ClientSecret != "rotated-sec" ||
			us.p.Name != "新名" || len(us.p.RedirectURIs) != 1 || us.p.RedirectURIs[0] != "https://app.example.com/cb" {
			t.Errorf("update sso 透传 = %+v", us)
		}
		if clients.gotDeleteSsoID != 7 {
			t.Errorf("delete sso 透传 = %d", clients.gotDeleteSsoID)
		}
		co := clients.gotCreateOidc
		if co.ClientID != "oidc-x" || co.Name != "OIDC" || len(co.RedirectURIs) != 1 ||
			len(co.Scopes) != 2 || co.Scopes[0] != "openid" || co.AccessTokenTTL != 1800 || co.RefreshTokenTTL != 864000 {
			t.Errorf("create oidc 透传 = %+v", co)
		}
		uo := clients.gotUpdateOidc
		if uo.id != 8 || uo.p.Name != "改名" || len(uo.p.Scopes) != 1 || uo.p.Scopes[0] != "openid" ||
			uo.p.AccessTokenTTL != 7200 || uo.p.RefreshTokenTTL != 2592000 || uo.p.ClientID != "" || len(uo.p.RedirectURIs) != 0 {
			t.Errorf("update oidc 透传 = %+v", uo)
		}
		if clients.gotDeleteOidcID != 8 {
			t.Errorf("delete oidc 透传 = %d", clients.gotDeleteOidcID)
		}
	})
	t.Run("invalid_request 映射", func(t *testing.T) {
		clients := &fakeClientService{crudErr: adminsvc.ErrInvalidRequest}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceCreateSsoClientProcedure, reqCreateSso, cookie)
		if resp.StatusCode != http.StatusBadRequest || decodeErrorCode(t, raw) != "invalid_argument" {
			t.Fatalf("status=%d raw=%s", resp.StatusCode, raw)
		}
		info := decodeErrorInfo(t, raw)
		if info.GetDomain() != "admin" || info.GetCode() != "invalid_request" {
			t.Errorf("ErrorInfo = (%q, %q), want (admin, invalid_request)", info.GetDomain(), info.GetCode())
		}
	})
	t.Run("already_exists 映射", func(t *testing.T) {
		clients := &fakeClientService{crudErr: adminsvc.ErrDuplicateKey}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceCreateSsoClientProcedure, reqCreateSso, cookie)
		if resp.StatusCode != http.StatusConflict || decodeErrorCode(t, raw) != "already_exists" {
			t.Fatalf("status=%d raw=%s", resp.StatusCode, raw)
		}
	})
	t.Run("404 映射", func(t *testing.T) {
		clients := &fakeClientService{crudErr: gorm.ErrRecordNotFound}
		tokens, epochs, h := newAdminHandlerClients(t, clients)
		cookie := adminCookie(t, tokens, epochs, 1)
		resp, raw := doRPC(t, h, adminv1connect.AdminServiceDeleteOidcClientProcedure, reqDeleteOidc, cookie)
		if resp.StatusCode != http.StatusNotFound || decodeErrorCode(t, raw) != "not_found" {
			t.Fatalf("status=%d raw=%s", resp.StatusCode, raw)
		}
	})
}
