// 微信小程序渠道适配器（docs/后端架构.md §12.2 行 1441、§13.0 行 1552-1561、
// §13.1 行 1563-1567）：code → code2session → ExternalIdentity，
// channel=api。
//
// AppID / AppSecret 一律取该 provider 实例的 Ext.app_id / Ext.client_secret
// （§13.0 唯一口径）：无硬编码、不读 config、无全局默认回落；二者为空视为
// 未配置，构造适配器即失败。SDK 引用被隔离在本包（§13.0 行 1561），服务层
// 不暴露 SDK 类型。
package wechatmp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/medivhzhan/weapp/v3"
	"github.com/medivhzhan/weapp/v3/logger"

	"authloft/internal/provider"
)

// Type 渠道类型（§12.2 内置清单）。
const Type = "wechat_mp"

// 可判别错误。
var (
	// ErrNotConfigured app_id / client_secret 缺失（§13.0：视为未配置）。
	ErrNotConfigured = errors.New("wechat_mp: provider not configured")
	// ErrEmptyCode 前端未提交 code。
	ErrEmptyCode = errors.New("wechat_mp: empty code")
	// ErrEmptyOpenID 微信未返回 openid。
	ErrEmptyOpenID = errors.New("wechat_mp: empty openid")
	// ErrNilToken FetchUser 入参为空。
	ErrNilToken = errors.New("wechat_mp: nil token")
	// ErrAuthURLNotSupported channel=api 无跳转授权流程（§13.1），
	// BuildAuthURL 明确不支持。
	ErrAuthURLNotSupported = errors.New("wechat_mp: auth url not supported for api channel")
)

func init() {
	provider.Register(Type, provider.Meta{
		Type:        Type,
		DisplayName: "微信小程序",
		Category:    "oauth",
		Channel:     provider.ChannelAPI,
		// Fields §5.3 行 1235 oauth 追加 10 字段 + 行 1239 全类 metadata；
		// label / type / section / required / advanced / help 与 §5.3 示例
		// （行 1187-1226）逐字一致：user_mapping 在示例端点区块内 → endpoint，
		// metadata 按行 1243 约定「其余按语义归 basic」。
		Fields: []provider.FieldMeta{
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
		},
	}, newAdapter)
}

// loginClient 本包用到的 SDK 窄接口（*weapp.Client 天然满足；便于测试注入
// httptest 驱动的客户端）。
type loginClient interface {
	Login(code string) (*weapp.LoginResponse, error)
}

// Adapter 微信小程序适配器（channel=api）。
type Adapter struct {
	providerKey string
	client      loginClient
}

// newAdapter 注册表工厂：从 Provider 实例取凭证并构造 SDK 客户端。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) {
	return build(p, nil)
}

// build 可注入 http.Client 的构造函数（仅供本包测试用 httptest 拦截微信
// 请求；生产 newAdapter 传 nil 走 SDK 默认客户端）。
func build(p *provider.Provider, hc *http.Client) (*Adapter, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	appID := p.Ext.GetAppId()
	appSecret := p.Ext.GetClientSecret()
	if appID == "" || appSecret == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}

	opts := make([]func(*weapp.Client), 0, 1)
	if hc != nil {
		opts = append(opts, weapp.WithHttpClient(hc))
	}
	client := weapp.NewClient(appID, appSecret, opts...)
	// SDK 默认日志会打印完整请求 URL（含 appid/secret），必须关闭（安全口径）。
	client.SetLogLevel(logger.Silent)

	return &Adapter{
		providerKey: p.Key,
		client:      client,
	}, nil
}

// Channel 固定为 api（§13.1）。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelAPI }

// BuildAuthURL channel=api 由小程序自行完成交互（§13.1），不存在跳转
// 授权 URL：明确返回 ErrAuthURLNotSupported，不返回空串当成功、不伪造 URL。
func (a *Adapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	return "", ErrAuthURLNotSupported
}

// Code2Session 调用微信 code2session，返回统一身份（§13.1）。凭证来自
// provider 实例字段，不读配置、不回落默认值。
func (a *Adapter) Code2Session(ctx context.Context, code string) (*provider.ExternalIdentity, error) {
	if code == "" {
		return nil, ErrEmptyCode
	}
	rsp, err := a.client.Login(code)
	if err != nil {
		return nil, fmt.Errorf("wechat_mp: code2session: %w", err)
	}
	if rsp == nil {
		return nil, fmt.Errorf("wechat_mp: code2session: empty response")
	}
	if err := rsp.GetResponseError(); err != nil {
		return nil, fmt.Errorf("wechat_mp: code2session: %w", err)
	}
	if rsp.OpenID == "" {
		return nil, ErrEmptyOpenID
	}
	return &provider.ExternalIdentity{
		ProviderKey:  a.providerKey,
		ProviderType: Type,
		OpenID:       rsp.OpenID,
		UnionID:      rsp.UnionID,
	}, nil
}

// Exchange 用 code 换取身份并放入 Token.Raw，供后续 FetchUser 组装。
// code2session 无 access/refresh token 语义（§13.1）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	id, err := a.Code2Session(ctx, in.Code)
	if err != nil {
		return nil, err
	}
	return &provider.Token{Raw: map[string]any{
		"openid":  id.OpenID,
		"unionid": id.UnionID,
	}}, nil
}

// FetchUser 从 Exchange 的结果组装 ExternalIdentity。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, ErrNilToken
	}
	openID, _ := t.Raw["openid"].(string)
	if openID == "" {
		return nil, ErrEmptyOpenID
	}
	unionID, _ := t.Raw["unionid"].(string)
	return &provider.ExternalIdentity{
		ProviderKey:  a.providerKey,
		ProviderType: Type,
		OpenID:       openID,
		UnionID:      unionID,
	}, nil
}
