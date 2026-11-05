// 微信小程序扫码渠道适配器（docs/后端架构.md §12.2、§13.0、§13.2：
// channel=qrcode，code → code2session → ExternalIdentity；拉码走
// GetwxacodeUnlimit）。
//
// 与 wechat_mp（channel=api）同构：AppID / AppSecret 一律
// 取该 provider 实例的 Ext.app_id / Ext.client_secret（§13.0 唯一口径），
// 无硬编码、不读 config、无全局默认回落；二者为空视为未配置，构造适配器
// 即失败。SDK 引用被隔离在本包（§13.0 行 1578），服务层不暴露 SDK 类型；
// 码图有损压缩不在本包（归 internal/qrcode）。
//
// access_token 跨实例共享缓存（§3.4 行 469）：bootstrap 装配期经
// SetAccessTokenCache 注入 cache.WxacodeStore（Redis 键 al:wxacode:*）；
// 未注入时 SDK 自带进程内内存缓存兜底（单实例可用）。
package wechatmpscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/medivhzhan/weapp/v3"
	"github.com/medivhzhan/weapp/v3/logger"
	"github.com/medivhzhan/weapp/v3/request"

	"authloft/internal/provider"
)

// Type 渠道类型（§12.2 内置清单：wechat_mp_scan）。
const Type = "wechat_mp_scan"

// 可判别错误。
var (
	// ErrNotConfigured app_id / client_secret 缺失（§13.0：视为未配置）。
	ErrNotConfigured = errors.New("wechat_mp_scan: provider not configured")
	// ErrEmptyCode 前端未提交 code。
	ErrEmptyCode = errors.New("wechat_mp_scan: empty code")
	// ErrEmptyOpenID 微信未返回 openid。
	ErrEmptyOpenID = errors.New("wechat_mp_scan: empty openid")
	// ErrNilToken FetchUser 入参为空。
	ErrNilToken = errors.New("wechat_mp_scan: nil token")
	// ErrAuthURLNotSupported channel=qrcode 无跳转授权流程（§13.2），
	// BuildAuthURL 明确不支持。
	ErrAuthURLNotSupported = errors.New("wechat_mp_scan: auth url not supported for qrcode channel")
	// ErrEmptyScene 拉码 scene 为空（scene 承载 ticket_id，§13.2）。
	ErrEmptyScene = errors.New("wechat_mp_scan: empty scene")
)

// AccessTokenCache access_token 跨实例共享缓存（cache.WxacodeStore 天然
// 满足）；由 bootstrap 装配期注入（SetAccessTokenCache）。
type AccessTokenCache interface {
	Get(ctx context.Context, key string) (string, bool)
	Set(ctx context.Context, key, val string, ttl time.Duration)
}

// accessTokenCache 装配期注入一次；bootstrap 在 Redis 就绪后、接受请求
// 前调用，运行期只读，不加锁。
var accessTokenCache AccessTokenCache

// SetAccessTokenCache 注入共享缓存（bootstrap 装配期调用一次；nil 表示
// 未注入，SDK 内存缓存兜底）。测试如需隔离请 Set + defer 恢复。
func SetAccessTokenCache(c AccessTokenCache) { accessTokenCache = c }

// sdkCache 把 AccessTokenCache 桥接为 weapp SDK 的 cache.Cache（SDK 侧
// Get/Set 无 ctx，桥接体补 context.Background；access_token 恒为 string）。
type sdkCache struct{ store AccessTokenCache }

func (c sdkCache) Get(key string) (interface{}, bool) {
	v, ok := c.store.Get(context.Background(), key)
	return v, ok
}

func (c sdkCache) Set(key string, val interface{}, timeout time.Duration) {
	s, _ := val.(string)
	if s == "" {
		return
	}
	c.store.Set(context.Background(), key, s, timeout)
}

func init() {
	provider.Register(Type, provider.Meta{
		Type:        Type,
		DisplayName: "微信小程序扫码",
		Category:    "oauth",
		Channel:     provider.ChannelQRCode,
		// Fields §5.3 行 1249 oauth 类追加字段 + 行 1252 type=wechat_mp_scan
		// 追加三字段；section 约定行 1257：开关类归 policy、路径 / 存储引用
		// 类归 endpoint、密钥 / AppID 类归 credential、其余按语义归 basic
		//（metadata）。与 wechat_mp 同款基线。
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
			{Key: "qrcode_auto_delete", Label: "登录后自动删除码图", Type: "checkbox", Section: "policy"},
			{Key: "storage_provider", Label: "存储 Provider", Type: "text", Section: "endpoint"},
			{Key: "storage_path", Label: "存储路径模板", Type: "text", Section: "endpoint",
				Help: "JSONata 表达式，内置变量 ticket_id / timestamp，如 'qrcodes_' & $.ticket_id & '.jpg'"},
			{Key: "metadata", Label: "长尾键值", Type: "json", Section: "basic", Advanced: true},
		},
	}, newAdapter)
}

// loginClient 本包用到的 SDK 窄接口（*weapp.Client 天然满足；便于测试注入
// httptest 驱动的客户端）。
type loginClient interface {
	Login(code string) (*weapp.LoginResponse, error)
}

// wxacodeClient 拉码窄接口（*weapp.Client 天然满足）。
type wxacodeClient interface {
	GetUnlimitedQRCode(code *weapp.UnlimitedQRCode) (*http.Response, *request.CommonError, error)
}

// Adapter 微信小程序扫码适配器（channel=qrcode）。
type Adapter struct {
	providerKey string
	client      loginClient
	qrcode      wxacodeClient
}

// newAdapter 注册表工厂：从 Provider 实例取凭证并构造 SDK 客户端。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) {
	return build(p, nil)
}

// build 可注入 http.Client 的构造函数（仅供本包测试用 httptest 拦截微信
// 请求；生产 newAdapter 传 nil 走 SDK 默认客户端）。共享 access_token
// 缓存注入（SetAccessTokenCache）后按请求生效——适配器按请求构造，
// 每次构造都读当前注入值（bootstrap 装配期先 Set 后服务，无竞态窗口）。
func build(p *provider.Provider, hc *http.Client) (*Adapter, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	appID := p.Ext.GetAppId()
	appSecret := p.Ext.GetClientSecret()
	if appID == "" || appSecret == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}

	opts := make([]func(*weapp.Client), 0, 2)
	if hc != nil {
		opts = append(opts, weapp.WithHttpClient(hc))
	}
	if accessTokenCache != nil {
		opts = append(opts, weapp.WithCache(sdkCache{store: accessTokenCache}))
	}
	client := weapp.NewClient(appID, appSecret, opts...)
	// SDK 默认日志会打印完整请求 URL（含 appid/secret），必须关闭（安全口径）。
	client.SetLogLevel(logger.Silent)

	return &Adapter{
		providerKey: p.Key,
		client:      client,
		qrcode:      client,
	}, nil
}

// Channel 固定为 qrcode（§13.2）。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelQRCode }

// BuildAuthURL channel=qrcode 由小程序扫码完成交互（§13.2），不存在跳转
// 授权 URL：明确返回 ErrAuthURLNotSupported，不返回空串当成功。
func (a *Adapter) BuildAuthURL(*provider.AuthContext) (string, error) {
	return "", ErrAuthURLNotSupported
}

// Code2Session 调用微信 code2session，返回统一身份（§13.1）。凭证来自
// provider 实例字段，不读配置、不回落默认值（与 wechat_mp 同构）。
func (a *Adapter) Code2Session(_ context.Context, code string) (*provider.ExternalIdentity, error) {
	if code == "" {
		return nil, ErrEmptyCode
	}
	rsp, err := a.client.Login(code)
	if err != nil {
		return nil, fmt.Errorf("wechat_mp_scan: code2session: %w", err)
	}
	if rsp == nil {
		return nil, fmt.Errorf("wechat_mp_scan: code2session: empty response")
	}
	if err := rsp.GetResponseError(); err != nil {
		return nil, fmt.Errorf("wechat_mp_scan: code2session: %w", err)
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
func (a *Adapter) FetchUser(_ context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
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

// FetchQrcode 实现 provider.QRCodeSupporter（§13.2）：GetwxacodeUnlimit，
// scene 承载 ticket_id；check_path=false——码图生成不依赖小程序页面发布
// 状态（未发布的小程序也要能开发联调，§13.2「Authloft 不负责小程序端
// 实现」）。返回微信原始图片字节（压缩归 internal/qrcode）。微信错误
// （Content-Type 为 JSON 的 errcode 应答）上抛，不当空图返回。
func (a *Adapter) FetchQrcode(_ context.Context, scene string) ([]byte, error) {
	if scene == "" {
		return nil, ErrEmptyScene
	}
	res, cerr, err := a.qrcode.GetUnlimitedQRCode(&weapp.UnlimitedQRCode{
		Scene:     scene,
		CheckPath: false,
	})
	if err != nil {
		return nil, fmt.Errorf("wechat_mp_scan: getwxacodeunlimit: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("wechat_mp_scan: getwxacodeunlimit: empty response")
	}
	defer res.Body.Close()
	if cerr != nil && cerr.ErrCode != 0 {
		return nil, fmt.Errorf("wechat_mp_scan: getwxacodeunlimit: errcode %d: %s", cerr.ErrCode, cerr.ErrMSG)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("wechat_mp_scan: getwxacodeunlimit: read body: %w", err)
	}
	return body, nil
}

// 接口实现静态断言：*Adapter 是 QRCodeSupporter（可选接口）。
var _ provider.QRCodeSupporter = (*Adapter)(nil)
