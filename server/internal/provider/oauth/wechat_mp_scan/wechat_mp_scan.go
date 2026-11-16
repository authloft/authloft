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
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2 内置清单：wechat_mp_scan）。
const Type = "wechat_mp_scan"

// dynamicKeyStorageProviderKeys storage_provider 字段 Schema 声明的 DynamicKey：
// 候选为 storage 类 provider_key，由管理面按此键查库注入（§5.3，声明形态同
// union_provider / proxy_provider_key 动态先例，构造器不下发候选值）。
const dynamicKeyStorageProviderKeys = "storage_provider_keys"

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
	// §5.3 keep 集表 oauth 行与 type=wechat_mp_scan 行（声明即运行期实际
	// 消费）：凭证收敛至 app_id / client_secret（必填主凭证，并置 required、
	// 撤 advanced，声明序按 §5.3 示例置 app_id 在前），keep 外死字段（metadata
	// 等）不再下发；扫码三字段随 metadata 撤除移至 Ext 段尾、相对顺序不变。
	// storage_provider 为动态 select（Kind=FieldDynamicOptions + DynamicKey），
	// 候选 storage 类 provider_key 由 handler 查库注入，声明形态同
	// union_provider / proxy_provider_key 先例，构造器不下发候选值。
	m := oauthcore.KeepFields(oauthcore.NewMeta(Type, "微信小程序扫码", provider.ChannelQRCode), "app_id", "client_secret")
	byKey := make(map[string]provider.FieldMeta, 2)
	for _, f := range m.Fields {
		byKey[f.Key] = f
	}
	appID := byKey["app_id"]
	appID.Required = true
	appID.Advanced = false
	m.Fields = append([]provider.FieldMeta{appID, byKey["client_secret"]},
		provider.FieldMeta{Key: "qrcode_auto_delete", Label: "admin.schemaField.qrcodeAutoDeleteLabel", Type: "checkbox", Section: "policy", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "storage_provider", Label: "admin.schemaField.storageProviderLabel", Type: "select", Section: "endpoint",
			Storage: provider.StorageExt, Kind: provider.FieldDynamicOptions, DynamicKey: dynamicKeyStorageProviderKeys},
		provider.FieldMeta{Key: "storage_path", Label: "admin.schemaField.storagePathLabel", Type: "text", Section: "endpoint",
			Help: "admin.schemaField.storagePathHelp", Storage: provider.StorageExt},
	)
	// Fields 整体重赋，重设 Schema 使 Ext 段与最终 Fields 一致。
	m.Schema = oauthcore.SchemaFor(m.Fields)
	provider.Register(Type, m, newAdapter)
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
	hc          *http.Client // 包内测试钩子：记录注入 SDK 的出站 client
}

// newAdapter 注册表工厂：从 Provider 实例取凭证并构造 SDK 客户端。出站
// client 按装配期固化的 Outbound 连接池构造（§15.4）：非 nil 用池化 client
// （Transport 共享、连接复用）；nil（proxy_provider_key 空 = 直连）沿用既有
// 10s 超时的默认直连 client。引用不可解析在 Loader 装配期已 fail（§15.4），
// 本层无代理失败路径。测试注入走 build，不经此工厂。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) {
	if p == nil || p.Ext == nil {
		return build(p, nil)
	}
	hc := &http.Client{Timeout: 10 * time.Second}
	if p.Outbound != nil {
		hc = p.Outbound.HTTPClient(10 * time.Second)
	}
	return build(p, hc)
}

// build 可注入 http.Client 的构造函数（测试用 httptest 拦截微信请求；
// 生产 newAdapter 传入按装配期固化出站代理池构造的 client）。hc 非空时经
// weapp.WithHttpClient 注入 SDK，SDK 日志静默始终保留。共享 access_token
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
		hc:          hc,
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
