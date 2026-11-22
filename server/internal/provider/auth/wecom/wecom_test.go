// wecom 适配器单测：httptest 扮演企业微信 CGI 端点，覆盖授权 URL 组装
// （appid / agentid / #wechat_redirect）、两段式令牌链路（gettoken →
// getuserinfo）、应用级令牌缓存（复用 / 到期重取 / 缺 expires_in 不缓存）、
// body 内 errcode 分支（errcode=0 成功不误判 / 非零 / HTTP 非 2xx / JSON
// 损坏 / 缺 access_token）、snsapi_privateinfo 详情合并与失败降级、
// 缺 UserId fail-closed、user_ticket 不入身份 Raw、user_mapping 覆盖、
// 注册表装配与 Schema 键集。
package wecom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
	"authloft/internal/provider/schemafield"
)

func testProvider(key, corpID, secret, agentID string) *provider.Provider {
	return &provider.Provider{Key: key, Type: Type,
		Ext: &providerpb.Ext{ClientId: corpID, ClientSecret: secret, AgentId: agentID}}
}

// wecomMock 企业微信三端点本地 mock：按路径分发并计数，请求断言写在
// handler 内（可证伪：参数名 / 取值错即测试红）。
type wecomMock struct {
	getTokenCalls     int
	getUserInfoCalls  int
	getUserDetail     int
	getTokenStatus    int // 非 0 时 gettoken 返回该 HTTP 状态码
	getTokenBody      string
	getUserInfoBody   string
	getUserDetailBody string
}

func (m *wecomMock) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			m.getTokenCalls++
			if r.Method != http.MethodGet {
				t.Errorf("gettoken method = %s, want GET", r.Method)
			}
			if q.Get("corpid") != "corp-1" || q.Get("corpsecret") != "secret-1" {
				t.Errorf("gettoken params = %v", q)
			}
			if m.getTokenStatus != 0 {
				w.WriteHeader(m.getTokenStatus)
			}
			fmt.Fprint(w, m.getTokenBody)
		case "/cgi-bin/user/getuserinfo":
			m.getUserInfoCalls++
			if q.Get("code") == "" {
				t.Errorf("getuserinfo 缺 code: %v", q)
			}
			if q.Get("access_token") != "app-token-1" {
				t.Errorf("getuserinfo access_token = %q, want 第一段 gettoken 下发的 app-token-1", q.Get("access_token"))
			}
			fmt.Fprint(w, m.getUserInfoBody)
		case "/cgi-bin/user/get":
			m.getUserDetail++
			if q.Get("userid") != "zhangsan" {
				t.Errorf("user/get userid = %q, want zhangsan", q.Get("userid"))
			}
			if q.Get("access_token") != "app-token-1" {
				t.Errorf("user/get access_token = %q", q.Get("access_token"))
			}
			fmt.Fprint(w, m.getUserDetailBody)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const (
	tokenBodyOK    = `{"errcode":0,"errmsg":"ok","access_token":"app-token-1","expires_in":7200}`
	userInfoBodyOK = `{"errcode":0,"errmsg":"ok","UserId":"zhangsan","DeviceId":"dev-1","user_ticket":"ticket-1"}`
	detailBodyOK   = `{"errcode":0,"errmsg":"ok","userid":"zhangsan","name":"张三","avatar":"http://wework/qpic","mobile":"13800000000","email":"zhangsan@example.com"}`
)

func newTestAdapter(t *testing.T, m *wecomMock, ext *providerpb.Ext) (*Adapter, error) {
	t.Helper()
	if ext == nil {
		ext = &providerpb.Ext{ClientId: "corp-1", ClientSecret: "secret-1", AgentId: "ag-1"}
	}
	return build(&provider.Provider{Key: "wecom", Type: Type, Ext: ext}, oauthcore.NewRewriteClient(m.serve(t).URL))
}

func TestBuildAuthURL(t *testing.T) {
	a, err := newTestAdapter(t, &wecomMock{}, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-wc", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	// 端点断言（独立字面量，与生产常量解耦）：防「BuildAuthURL 输出 ≠ 企业微信
	// 官方授权端点」；不防与真实端点的互通性（httptest 无法覆盖，真机联调未覆盖）。
	const wantAuthURL = "https://open.weixin.qq.com/connect/oauth2/authorize"
	if u.Scheme+"://"+u.Host+u.Path != wantAuthURL {
		t.Fatalf("endpoint = %q, want %q", u.Scheme+"://"+u.Host+u.Path, wantAuthURL)
	}
	if u.Fragment != "wechat_redirect" {
		t.Fatalf("fragment = %q, want wechat_redirect（企业微信私有尾锚）", u.Fragment)
	}
	q := u.Query()
	if q.Get("appid") != "corp-1" || q.Get("agentid") != "ag-1" {
		t.Fatalf("query = %v（微信系参数名为 appid 且 agentid 必带）", q)
	}
	if q.Get("client_id") != "" {
		t.Fatalf("client_id = %q, want 空（企业微信不认标准 OAuth2 参数名）", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" || q.Get("state") != "l-wc" || q.Get("redirect_uri") != "https://app/cb" {
		t.Fatalf("query = %v", q)
	}
	if q.Get("scope") != defaultScopes {
		t.Fatalf("scope = %q, want 缺省 %q", q.Get("scope"), defaultScopes)
	}
	// ctx.Scope 覆盖预设。
	got, err = a.BuildAuthURL(&provider.AuthContext{State: "s", Scope: scopePrivateInfo})
	if err != nil {
		t.Fatalf("BuildAuthURL override: %v", err)
	}
	u2, _ := url.Parse(got)
	if u2.Query().Get("scope") != scopePrivateInfo {
		t.Fatalf("scope override 未生效: %s", got)
	}
	// state 缺失 fail-closed（service 层生成后透传，adapter 只校验）。
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

func TestExchangeTwoStage(t *testing.T) {
	// 两段式链路可证伪：第一段 gettoken（corpid/corpsecret）→ 第二段
	// getuserinfo（access_token + code → UserId）。mock 断言 access_token
	// 恰为第一段下发值（见 handler）。
	m := &wecomMock{getTokenBody: tokenBodyOK, getUserInfoBody: userInfoBodyOK}
	a, err := newTestAdapter(t, m, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "code-1"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if m.getTokenCalls != 1 || m.getUserInfoCalls != 1 {
		t.Fatalf("calls = gettoken:%d getuserinfo:%d, want 1/1", m.getTokenCalls, m.getUserInfoCalls)
	}
	if tok.AccessToken != "app-token-1" || tok.ExpiresIn != 7200 {
		t.Fatalf("token = %+v", tok)
	}
	if tok.Raw["UserId"] != "zhangsan" {
		t.Fatalf("raw UserId = %v, want zhangsan", tok.Raw["UserId"])
	}
	if _, err := a.Exchange(context.Background(), provider.ExchangeInput{}); !errors.Is(err, oauthcore.ErrEmptyCode) {
		t.Fatalf("err = %v, want ErrEmptyCode", err)
	}
}

func TestTokenCacheReuse(t *testing.T) {
	// 同一适配器连续交换：应用级令牌缓存命中，gettoken 只打一次。
	m := &wecomMock{getTokenBody: tokenBodyOK, getUserInfoBody: userInfoBodyOK}
	a, _ := newTestAdapter(t, m, nil)
	for i := 0; i < 3; i++ {
		if _, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: fmt.Sprintf("code-%d", i)}); err != nil {
			t.Fatalf("Exchange #%d: %v", i, err)
		}
	}
	if m.getTokenCalls != 1 || m.getUserInfoCalls != 3 {
		t.Fatalf("calls = gettoken:%d getuserinfo:%d, want 1/3（缓存命中不重取）", m.getTokenCalls, m.getUserInfoCalls)
	}
}

func TestTokenCacheExpiry(t *testing.T) {
	// 可注入时钟验证过期戳：expires_in 7200 - margin 60 = 7140 秒后重取。
	m := &wecomMock{getTokenBody: tokenBodyOK, getUserInfoBody: userInfoBodyOK}
	a, _ := newTestAdapter(t, m, nil)
	base := time.Unix(1700000000, 0)
	now := base
	a.now = func() time.Time { return now }

	if _, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c1"}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	now = base.Add(7139 * time.Second) // margin 内：命中缓存
	if _, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c2"}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if m.getTokenCalls != 1 {
		t.Fatalf("gettoken calls = %d, want 1（margin 内不重取）", m.getTokenCalls)
	}
	now = base.Add(7141 * time.Second) // 过期戳已过：重取
	if _, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c3"}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if m.getTokenCalls != 2 {
		t.Fatalf("gettoken calls = %d, want 2（过期重取）", m.getTokenCalls)
	}
}

func TestTokenNotCachedWithoutExpiresIn(t *testing.T) {
	// 响应缺 expires_in → 视为不可缓存（下次交换重取，宁可多打一次也不挂死令牌）。
	m := &wecomMock{getTokenBody: `{"errcode":0,"errmsg":"ok","access_token":"app-token-1"}`,
		getUserInfoBody: userInfoBodyOK}
	a, _ := newTestAdapter(t, m, nil)
	for i := 0; i < 2; i++ {
		if _, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"}); err != nil {
			t.Fatalf("Exchange #%d: %v", i, err)
		}
	}
	if m.getTokenCalls != 2 {
		t.Fatalf("gettoken calls = %d, want 2（无 expires_in 不缓存）", m.getTokenCalls)
	}
}

func TestErrcodeBranches(t *testing.T) {
	t.Run("gettoken_errcode", func(t *testing.T) {
		m := &wecomMock{getTokenBody: `{"errcode":60020,"errmsg":"not allow corpsecret"}`}
		a, _ := newTestAdapter(t, m, nil)
		_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
		pe, ok := oauthcore.AsProviderError(err)
		if !ok || pe.Code != "60020" {
			t.Fatalf("err = %v, want ProviderError code 60020", err)
		}
	})
	t.Run("getuserinfo_errcode", func(t *testing.T) {
		// errcode 在 body 且 HTTP 200：不能当成功放行（40029 invalid code）。
		m := &wecomMock{getTokenBody: tokenBodyOK,
			getUserInfoBody: `{"errcode":40029,"errmsg":"invalid code"}`}
		a, _ := newTestAdapter(t, m, nil)
		_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
		pe, ok := oauthcore.AsProviderError(err)
		if !ok || pe.Code != "40029" {
			t.Fatalf("err = %v, want ProviderError code 40029", err)
		}
	})
	t.Run("errcode_zero_is_success", func(t *testing.T) {
		// 成功响应也携带 errcode=0：不得误判为错误（区别于 oauthcore 含
		// errcode 即错误的通用归一）。
		m := &wecomMock{getTokenBody: tokenBodyOK, getUserInfoBody: userInfoBodyOK}
		a, _ := newTestAdapter(t, m, nil)
		if _, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"}); err != nil {
			t.Fatalf("errcode=0 被误判为错误: %v", err)
		}
	})
	t.Run("gettoken_http_500", func(t *testing.T) {
		// HTTP 非 2xx 即拒绝，即使 body errcode=0。
		m := &wecomMock{getTokenStatus: http.StatusInternalServerError, getTokenBody: `{"errcode":0,"errmsg":"ok"}`}
		a, _ := newTestAdapter(t, m, nil)
		_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
		pe, ok := oauthcore.AsProviderError(err)
		if !ok || pe.Code != "http_500" {
			t.Fatalf("err = %v, want ProviderError http_500", err)
		}
	})
	t.Run("gettoken_unparsable", func(t *testing.T) {
		m := &wecomMock{getTokenBody: `not-json`}
		a, _ := newTestAdapter(t, m, nil)
		_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
		pe, ok := oauthcore.AsProviderError(err)
		if !ok || pe.Code != "unparsable_wecom_body" {
			t.Fatalf("err = %v, want ProviderError unparsable_wecom_body（JSON 损坏 fail-closed）", err)
		}
	})
	t.Run("gettoken_missing_access_token", func(t *testing.T) {
		m := &wecomMock{getTokenBody: `{"errcode":0,"errmsg":"ok"}`}
		a, _ := newTestAdapter(t, m, nil)
		_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
		pe, ok := oauthcore.AsProviderError(err)
		if !ok || pe.Code != "empty_access_token" {
			t.Fatalf("err = %v, want ProviderError empty_access_token", err)
		}
	})
}

func TestFetchUserSilent(t *testing.T) {
	// snsapi_base 静默授权：只从 getuserinfo 响应抽 UserId，不调 user/get；
	// user_ticket 属凭证类字段，禁入身份 Raw。
	m := &wecomMock{getTokenBody: tokenBodyOK, getUserInfoBody: userInfoBodyOK}
	a, _ := newTestAdapter(t, m, nil)
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if m.getUserDetail != 0 {
		t.Fatalf("user/get calls = %d, want 0（静默授权不拉详情）", m.getUserDetail)
	}
	if id.OpenID != "zhangsan" || id.ProviderKey != "wecom" || id.ProviderType != Type {
		t.Fatalf("identity = %+v", id)
	}
	if _, has := id.Raw["user_ticket"]; has {
		t.Fatalf("身份 Raw 携带 user_ticket（凭证类字段禁入 Raw）: %v", id.Raw)
	}
	if _, has := id.Raw["UserId"]; !has {
		t.Fatalf("身份 Raw 缺 UserId: %v", id.Raw)
	}
	// 非企业成员响应（无 UserId，仅 OpenId）→ fail-closed。
	extOnly := &wecomMock{getTokenBody: tokenBodyOK,
		getUserInfoBody: `{"errcode":0,"errmsg":"ok","OpenId":"open-1"}`}
	a2, _ := newTestAdapter(t, extOnly, nil)
	tok2, _ := a2.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
	if _, err := a2.FetchUser(context.Background(), tok2); !errors.Is(err, oauthcore.ErrEmptyOpenID) {
		t.Fatalf("err = %v, want ErrEmptyOpenID（缺 UserId fail-closed）", err)
	}
}

func TestFetchUserPrivateInfo(t *testing.T) {
	// snsapi_privateinfo：调 user/get 合并详情（name/avatar/mobile/email）。
	m := &wecomMock{getTokenBody: tokenBodyOK, getUserInfoBody: userInfoBodyOK, getUserDetailBody: detailBodyOK}
	a, err := newTestAdapter(t, m, &providerpb.Ext{
		ClientId: "corp-1", ClientSecret: "secret-1", AgentId: "ag-1", Scopes: "snsapi_privateinfo"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if m.getUserDetail != 1 {
		t.Fatalf("user/get calls = %d, want 1", m.getUserDetail)
	}
	if id.Nickname != "张三" || id.AvatarURL != "http://wework/qpic" || id.Phone != "13800000000" || id.Email != "zhangsan@example.com" {
		t.Fatalf("identity = %+v", id)
	}
	if id.OpenID != "zhangsan" {
		t.Fatalf("openid = %q, want UserId zhangsan", id.OpenID)
	}
	if _, has := id.Raw["user_ticket"]; has {
		t.Fatalf("身份 Raw 携带 user_ticket: %v", id.Raw)
	}
}

func TestFetchUserDetailFailureNonFatal(t *testing.T) {
	// 详情为可选增强：user/get errcode 非零（如 60011 权限不足）不打断登录，
	// 保留静默链路已取得的身份。
	m := &wecomMock{getTokenBody: tokenBodyOK, getUserInfoBody: userInfoBodyOK,
		getUserDetailBody: `{"errcode":60011,"errmsg":"no privilege"}`}
	a, _ := newTestAdapter(t, m, &providerpb.Ext{
		ClientId: "corp-1", ClientSecret: "secret-1", AgentId: "ag-1", Scopes: "snsapi_privateinfo"})
	tok, _ := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("详情失败不应打断登录: %v", err)
	}
	if id.OpenID != "zhangsan" || id.Nickname != "" {
		t.Fatalf("identity = %+v, want 仅静默身份（无详情字段）", id)
	}
}

func TestFetchUserGates(t *testing.T) {
	a, _ := newTestAdapter(t, &wecomMock{}, nil)
	if _, err := a.FetchUser(context.Background(), nil); !errors.Is(err, oauthcore.ErrNilToken) {
		t.Fatalf("err = %v, want ErrNilToken", err)
	}
}

func TestUserMappingOverride(t *testing.T) {
	// user_mapping 覆盖渠道抽取值（映射结果优先）。
	m := &wecomMock{getTokenBody: tokenBodyOK, getUserInfoBody: userInfoBodyOK, getUserDetailBody: detailBodyOK}
	a, _ := newTestAdapter(t, m, &providerpb.Ext{
		ClientId: "corp-1", ClientSecret: "secret-1", AgentId: "ag-1",
		Scopes: "snsapi_privateinfo", UserMapping: map[string]string{"nickname": "$.email"}})
	tok, _ := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.Nickname != "zhangsan@example.com" {
		t.Fatalf("nickname = %q, want mapping 覆盖为 zhangsan@example.com", id.Nickname)
	}
}

func TestNotConfigured(t *testing.T) {
	for name, ext := range map[string]*providerpb.Ext{
		"缺corpID":   {ClientSecret: "s", AgentId: "a"},
		"缺secret":   {ClientId: "id", AgentId: "a"},
		"缺agent_id": {ClientId: "id", ClientSecret: "s"},
	} {
		if _, err := build(&provider.Provider{Key: "wecom", Type: Type, Ext: ext}, nil); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s: err = %v, want ErrNotConfigured", name, err)
		}
	}
	if _, err := build(nil, nil); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("err = %v, want ErrNilProvider", err)
	}
}

func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "企业微信" || meta.Category != "auth" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	adapter, err := provider.NewAdapter(testProvider("wecom", "corp-1", "secret-1", "ag-1"))
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if adapter.Channel() != provider.ChannelRedirect {
		t.Fatalf("channel = %q", adapter.Channel())
	}
}

// TestSchemaKeepSet Schema 键集（接口文档 §5.3 声明即消费）：注册表 Schema()
// 恰为表列基线 + 标准四键（基线序）+ agent_id（授权 URL 硬依赖，必填）+
// 引用键 proxy_provider_key；端点键（provider_url / custom_*）固化不透出，
// keep 外键不再下发；scopes / user_mapping 预设值随字段 default 下发
// （§15.5 收窄边界），标准键其余属性与 schemafield 基线逐项一致。
func TestSchemaKeepSet(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("type %q 未注册", Type)
	}
	schema := meta.Schema()
	wantKeys := []string{
		"provider_key", "display_name", "union_provider",
		"client_id", "client_secret", "agent_id", "scopes", "user_mapping",
		"icon_url", "sort_order", "remark",
		"is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields",
		provider.ProxyRefKey,
	}
	if len(schema) != len(wantKeys) {
		var got []string
		for _, f := range schema {
			got = append(got, f.Key)
		}
		t.Fatalf("schema keys = %v, want %v", got, wantKeys)
	}
	for i, k := range wantKeys {
		if schema[i].Key != k {
			t.Fatalf("schema[%d].Key = %q, want %q（声明序即 wire 序）", i, schema[i].Key, k)
		}
	}
	baseline := map[string]provider.FieldMeta{}
	for _, f := range schemafield.OAuthCredentials() {
		baseline[f.Key] = f
	}
	for _, f := range schema {
		b, ok := baseline[f.Key]
		if !ok {
			continue
		}
		switch f.Key {
		case "scopes":
			if f.Default != defaultScopes {
				t.Errorf("scopes default = %q, want %q", f.Default, defaultScopes)
			}
			f.Default = b.Default
		case "user_mapping":
			if f.Default != defaultUserMapping {
				t.Errorf("user_mapping default = %q, want 预设映射", f.Default)
			}
			f.Default = b.Default
		}
		if !reflect.DeepEqual(f, b) {
			t.Errorf("字段 %q = %+v, want 基线 %+v", f.Key, f, b)
		}
	}
	// agent_id 为新增 Ext 键（接口文档 §12.1）：必填于企业微信，文案键已在前端字典预置。
	for _, f := range schema {
		if f.Key != "agent_id" {
			continue
		}
		if !f.Required || f.Label != "admin.schemaField.agentIdLabel" || f.Help != "admin.schemaField.agentIdHelp" ||
			f.Type != "text" || f.Section != "credential" || f.Storage != provider.StorageExt {
			t.Errorf("agent_id 字段 = %+v, want text/credential/Required 且文案键 agentId*", f)
		}
	}
}
