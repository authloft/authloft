// bootstrap.go 按 docs/后端架构.md §3.1 的固定顺序装配启动链，只做顺序编排与接线。
// 配置文件缺失 → setup 模式（§3.15）：不加载 config、不初始化 DB / Redis。
// 顶层用标准库 http.ServeMux 分流：Connect 前缀挂 mux 链，其余交给 gin。
// 监听协议由 server 段 TLS 配置决定（Go 1.26 原生 http.Server.Protocols，不引 x/net）。

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	connectrpc "connectrpc.com/connect"

	"authloft/assets"
	accountv1connect "authloft/gen/go/api/account/v1/accountv1connect"
	adminv1connect "authloft/gen/go/api/admin/v1/adminv1connect"
	rpcv1connect "authloft/gen/go/api/rpc/v1/rpcv1connect"
	ssov1connect "authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/asyncqueue"
	"authloft/internal/cache"
	"authloft/internal/captcha"
	"authloft/internal/config"
	"authloft/internal/connect"
	"authloft/internal/eventlog"
	"authloft/internal/factor"
	factorotp "authloft/internal/factor/otp"
	factorpassword "authloft/internal/factor/password"
	"authloft/internal/factor/recovery"
	"authloft/internal/factor/totp"
	"authloft/internal/factor/webauthn"
	accounthandler "authloft/internal/handler/account"
	adminhandler "authloft/internal/handler/admin"
	gatewayhandler "authloft/internal/handler/gateway"
	oidchandler "authloft/internal/handler/oidc"
	rpchandler "authloft/internal/handler/rpc"
	ssohandler "authloft/internal/handler/sso"
	"authloft/internal/logx"
	"authloft/internal/middleware"
	"authloft/internal/migrate"
	"authloft/internal/oidc"
	"authloft/internal/otp"
	"authloft/internal/pages"
	"authloft/internal/provider"
	// 注册表导入统一触发 init() 自注册：内置渠道适配器与 smtp / aliyun_sms
	// 消息 Sender 在此登记工厂（§3.1 / §12.2 / §15.2）。
	_ "authloft/internal/provider/email/smtp"
	_ "authloft/internal/provider/oauth/alipay"
	_ "authloft/internal/provider/oauth/baidu"
	_ "authloft/internal/provider/oauth/feishu"
	_ "authloft/internal/provider/oauth/gitee"
	_ "authloft/internal/provider/oauth/github"
	_ "authloft/internal/provider/oauth/google"
	_ "authloft/internal/provider/oauth/microsoft"
	_ "authloft/internal/provider/oauth/oauth2"
	_ "authloft/internal/provider/oauth/oidc"
	_ "authloft/internal/provider/oauth/qq"
	_ "authloft/internal/provider/oauth/wechat"
	_ "authloft/internal/provider/oauth/wechat_mp"
	_ "authloft/internal/provider/oauth/weibo"
	_ "authloft/internal/provider/sms/aliyun_sms"
	// wechat_mp_scan 具名导入：除 init() 自注册外，装配期还需
	// SetAccessTokenCache 注入共享 access_token 缓存（§3.4），须在 Redis 就绪后调用。
	wechatmpscan "authloft/internal/provider/oauth/wechat_mp_scan"
	"authloft/internal/qrcode"
	"authloft/internal/repo"
	"authloft/internal/security"
	accountsvc "authloft/internal/service/account"
	adminsvc "authloft/internal/service/admin"
	eventlogsvc "authloft/internal/service/eventlog"
	"authloft/internal/service/orchestrator"
	qrcodesvc "authloft/internal/service/qrcode"
	sessionsvc "authloft/internal/service/session"
	thirdpartysvc "authloft/internal/service/thirdparty"
	ticketsvc "authloft/internal/service/ticket"
	"authloft/internal/service/verification"
	"authloft/internal/session"
	"authloft/internal/settings"
	"authloft/internal/setup"
	"authloft/internal/storage"
)

// defaultReadMaxBytes Connect 域请求体上限默认值（§1.6）：装配层经 connect.NewServer 注入，
// 包自身不读 config。
const defaultReadMaxBytes = 1 << 20

// run 装配并阻塞运行 HTTP 服务。错误原样上抛由 main 转 exit 非 0（fail-fast）；
// setup 模式安装完成的退出走 Run 的 nil 返回（exit 0，由部署环境拉起）。
func run(configPath string) error {
	// 先按默认 info/text 接管 slog（format 空串回落 TextHandler），保证
	// setup 模式与 config 加载失败的 fail-fast 日志也结构化；读到配置后覆盖。
	logx.Setup("", "")
	if setupMode(configPath) {
		return setup.NewServer(configPath).Run()
	}
	// config 启动期一次读取 + env 覆盖 + Validate，任一失败即 fail-fast（§3.2）。
	// sign_key 只在安装流程生成，文件存在但缺项 / 非法一律 fail-fast、不自动补写。
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logx.Setup(cfg.Log.Level, cfg.Log.Format)
	// 内置模板常驻内存（§3.13 / §8.1）：启动期扫描嵌入的 templatesFS 注册，
	// 失败即 fail-fast——Resolve 依赖该表命中内置模板。
	if err := pages.InitBuiltinTemplates(); err != nil {
		return err
	}
	return serve(cfg)
}

// shutdownTimeout HTTP 优雅关闭上限（与队列 CloseTimeout 同口径 10s，超时后不再等待在途请求 / 批次）。
const shutdownTimeout = 10 * time.Second

// assembled 正常模式装配产物（§3.1 启动链）：基础设施、共享单例与各域 service。
// cron 仍为 TODO（§3.12）。
type assembled struct {
	db       *gorm.DB
	rdb      *redis.Client
	codecs   *codecs
	settings *settings.Store
	watcher  *settings.Watcher
	queue    *asyncqueue.Queue
	sink     *eventlogsvc.LoginEventWriter
	engine   *orchestrator.Engine
	// verification step-up 服务（§3.8）：挑战 / 断言两把独立密钥，SSO / account 两域共用。
	verification *verification.Service

	// provider 链（§3.9 / §15.3）：Whitelist 是 origin 中间件 Referer 白名单的唯一
	// 动态来源（已启用 wechat_mp / wechat_mp_scan 的 app_id 集合）。providerCache
	// 必须与 Loader 共用同一实例：读写共用键空间，双实例会导致失效与回写各说各话。
	providerLoader    *provider.Loader
	providerWhitelist *provider.Whitelist
	providerCache     *cache.ProviderCache

	// 会话 / 令牌共享单例：各只构造一份——sessionTokens 供 sso 拦截器与 Terminal
	// 共用，epochStore 供会话校验与 OIDC 令牌共用，codeIssuer 供 Terminal 与
	// OIDC token 端点共用；多实例会导致签发与校验不同源。
	sessionTokens *session.Tokens
	epochStore    *cache.EpochStore
	codeIssuer    *oidc.CodeIssuer

	// permissionProbe 登录签发侧「是否持有任意管理权限」探针：启动预热重建
	// 权限集合后构造，注入会话签发器；只读缓存、miss / 故障回源 DB。
	permissionProbe func(context.Context, int64) (bool, error)

	// oidcJWT OIDC RS256 签名密钥集（§14.3）：启动期一次解析，首项签发、全列表发 JWKS。
	oidcJWT *oidc.JWT

	// captcha 链（§9）：Gate 是登录引擎人机校验唯一拦截点；catalog / verifier
	// 每次 Evaluate 现算不缓存（provider 行源走 repo 直查，保证「每次生成时重新判定」）。
	// catalog 同实例兼任 CSP supporter——CSP 贡献与下发配置、拦截校验必须同源。
	gate           *captcha.Gate
	captchaCatalog *captcha.Catalog
	imageCaptcha   *captcha.ImageCaptcha

	// factors 因子注册表（§3.8）：供页面壳 methods 快照按 settings.login_methods 过滤读取。
	factors *factor.Registry

	// thirdparty 三方登录通道 service（§3.9）：与登录终点复用同一 State / Terminal。
	thirdparty *thirdpartysvc.Thirdparty

	// qrcode 扫码拉码与轮询 service（§2.8 / §13.2）：复用 State / Terminal / Loader / Gate。
	qrcode *qrcodesvc.QRCode

	// loginTicket 统一写票 service（§2.8）：ConfirmLoginTicket 与 LoginOauth 扫码分支共用同一 al:ticket 读写。
	loginTicket *ticketsvc.LoginTicket

	// accountThirdparty account 域三方绑定族 service（§3.7）：与 thirdparty / qrcode 共用同一 al:ticket 实例。
	accountThirdparty *accountsvc.ThirdpartyService

	// accountWebauthn account 域通行密钥族 service（§3.6 / §8.3）：注册内核复用
	// webauthn 因子同一实例。启动降级时注入 nil 接口（非 nil 指针）让四方法
	// fail-closed——typed-nil 会绕过 Factor==nil 判定。
	accountWebauthn *accountsvc.WebauthnService

	// account 五族 service（avatar / password / mfa / events / bindcontact，§3.2-§3.7）。
	accountAvatar   *accountsvc.AvatarService
	accountPassword *accountsvc.PasswordService
	accountMfa      *accountsvc.MfaService
	accountEvents   *accountsvc.EventsService

	// accountBindContact 换绑族双渠道组合（§3.4）：两实例共用同一 OTP 单例 / captcha
	// Gate / 限流 Config，仅 Sender 按渠道分注；handler 侧由 bindContactPair 适配。
	accountBindContact accounthandler.ContactBinder

	// repos 全进程共享仓储（repo 只持 *gorm.DB、无状态，复用等价）。
	repos *repoSet

	// admin admin 域四族 service。
	admin *adminSet

	// sessionSvc 会话校验 / 重签 / Cookie / 域级拦截器 / 同步首跳构造器（各域共用同一实例）。
	sessionSvc *sessionSet

	// infra 基础设施小件：事件 Writer 单例、RPC nonce 去重、密码失败计数、RPC HMAC 拦截器。
	infra *infraSet

	// accountProfile account 域资料族 service。
	accountProfile *accountsvc.ProfileService
}

// repoSet 装配层共享仓储（repo 只持 *gorm.DB、无状态，全进程同一实例与多处 new 等价）。
type repoSet struct {
	Users       *repo.UserRepo
	Creds       *repo.CredentialRepo
	Webauthn    *repo.WebauthnRepo
	Binds       *repo.BindRepo
	Providers   *repo.ProviderRepo
	EventLogs   *repo.EventLogRepo
	Clients     *repo.ClientRepo
	OidcTokens  *repo.OidcTokenRepo
	Permissions *repo.PermissionRepo
	Templates   *repo.TemplateRepo
}

// adminSet admin 域五族 service（wireSharedServices 构造）。
type adminSet struct {
	Providers  *adminsvc.Service
	Users      *adminsvc.UserService
	Clients    *adminsvc.ClientService
	Templates  *adminsvc.TemplateService
	Settings   *adminsvc.SettingsService
	Permission *adminsvc.PermissionService
}

// sessionSet 会话侧共享产物：Verifier / Renewer 复用共享 sessionTokens / epochStore，Cookie 与域级拦截器同源。
type sessionSet struct {
	Verifier    *session.Verifier
	Renewer     *session.Renewer
	Cookie      *session.Cookie
	Interceptor connectrpc.UnaryInterceptorFunc
	Sync        *sessionsvc.SyncCookieURLBuilder
}

// infraSet 基础设施小件（wireSharedServices 构造）。
type infraSet struct {
	Events *eventlog.Writer
	Nonce  *cache.NonceStore
	PwFail *cache.PwFailStore
	HMAC   connectrpc.UnaryInterceptorFunc
}

// newRepoSet 构造共享仓储集合（装配层一次）。
func newRepoSet(db *gorm.DB) *repoSet {
	return &repoSet{
		Users:       repo.NewUserRepo(db),
		Creds:       repo.NewCredentialRepo(db),
		Webauthn:    repo.NewWebauthnRepo(db),
		Binds:       repo.NewBindRepo(db),
		Providers:   repo.NewProviderRepo(db),
		EventLogs:   repo.NewEventLogRepo(db),
		Clients:     repo.NewClientRepo(db),
		OidcTokens:  repo.NewOidcTokenRepo(db),
		Permissions: repo.NewPermissionRepo(db),
		Templates:   repo.NewTemplateRepo(db),
	}
}

// wireSharedServices 构造 register* 消费的共享产物（会话拦截器 / Cookie / 同步首跳 /
// 事件 Writer / nonce / HMAC / admin 四族 / 资料族），须在共享单例就绪后调用。
func wireSharedServices(cfg *config.Config, deps *assembled) {
	deps.infra = &infraSet{
		Events: eventlog.NewWriter(deps.queue),
		Nonce:  cache.NewNonceStore(deps.rdb),
		PwFail: cache.NewPwFailStore(deps.rdb, cache.PwFailOptions{}),
	}
	// SecretLookup 未命中 / 已禁用 / 查询失败统一 ok=false：与签名错误同响应，
	// 不区分以防探测；签名无错误通道，查询故障只能并入未注册口径。
	clients := deps.repos.Clients
	deps.infra.HMAC = connect.NewRPCHMACInterceptor(deps.infra.Nonce,
		func(ctx context.Context, clientID string) (string, bool) {
			c, err := clients.FindSsoClientByClientID(ctx, clientID)
			if err != nil {
				// DB 查询故障此前并入 ok=false，对外表现"客户端未注册"且排障
				// 无痕；此处在请求链路内，logx.Error 自动带 request_id。
				// 只记 client_id，不记 secret / 签名。
				logx.Error(ctx, "bootstrap: rpc secret lookup failed",
					"client_id", clientID,
					"error", logx.RedactText(err.Error()),
				)
				return "", false
			}
			// 未注册 / 已禁用属业务预期，与签名错误同响应，不记日志。
			if c == nil || c.IsEnabled == 0 {
				return "", false
			}
			return c.ClientSecret, true
		})

	deps.sessionSvc = &sessionSet{
		Verifier:    session.NewVerifier(deps.sessionTokens, deps.epochStore),
		Renewer:     session.NewRenewer(deps.sessionTokens, ssoSessionTTLRaw(deps.settings)),
		Cookie:      newSessionCookie(cfg, deps),
		Interceptor: newDomainSessionInterceptor(cfg, deps),
		Sync:        sessionsvc.NewSyncCookieURLBuilder(deps.codecs.SyncPayload),
	}

	deps.accountProfile = accountsvc.NewProfileService(deps.repos.Users)

	deps.admin = &adminSet{
		Providers: adminsvc.NewService(deps.repos.Providers, deps.providerCache),
		Users: adminsvc.NewUserService(
			deps.repos.Users,
			deps.repos.Creds,
			deps.repos.Binds,
			deps.repos.Providers,
			deps.repos.EventLogs,
			deps.epochStore,
			deps.infra.PwFail,
			deps.infra.Events,
			deps.settings,
			deps.repos.Permissions,
		),
		Clients: adminsvc.NewClientService(deps.repos.Clients),
		Templates: adminsvc.NewTemplateService(
			deps.repos.Templates,
			cache.NewTemplateCache(deps.rdb),
		),
		Settings: adminsvc.NewSettingsService(
			deps.settings,
			deps.repos.EventLogs,
			deps.infra.Events,
			adminsvc.TokenCodecs{
				Session: deps.codecs.Session,
				Login:   deps.codecs.Login,
				Cookie:  deps.codecs.Cookie,
			},
			deps.queue,
		),
		Permission: adminsvc.NewPermissionService(deps.repos.Permissions),
	}
}

// codecs 七场景独立编解码器（§11.6.1）：各持一把密钥，互不复用。
type codecs struct {
	Session      *security.Codec
	Login        *security.Codec
	Ticket       *security.Codec
	Cookie       *security.Codec
	SyncPayload  *security.Codec
	Challenge    *security.Codec
	Verification *security.Codec
}

// buildCodecs 把 cfg.SignKey 七把 KeyMaterial 逐把转成 security.Codec（§1.4）。
// 任一步非法即返错由 serve 转 fail-fast；每把独立构造 KeyStore，绝不共用。
func buildCodecs(cfg *config.Config) (*codecs, error) {
	build := func(field string, km config.KeyMaterial) (*security.Codec, error) {
		raw, err := base64.StdEncoding.DecodeString(km.Key)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: %s.key: decode base64: %w", field, err)
		}
		if km.Kid <= 0 || km.Kid > 255 {
			return nil, fmt.Errorf("bootstrap: %s.kid: must be in 1..255, got %d", field, km.Kid)
		}
		ks, err := security.NewKeyStore(security.KeyEntry{
			ID:  security.KeyID{Version: 1, Kid: byte(km.Kid)},
			Key: raw,
		})
		if err != nil {
			return nil, fmt.Errorf("bootstrap: %s: %w", field, err)
		}
		return security.NewCodec(ks), nil
	}

	var (
		c   codecs
		err error
	)
	if c.Session, err = build("sign_key.session", cfg.SignKey.Session); err != nil {
		return nil, err
	}
	if c.Login, err = build("sign_key.login", cfg.SignKey.Login); err != nil {
		return nil, err
	}
	if c.Ticket, err = build("sign_key.ticket", cfg.SignKey.Ticket); err != nil {
		return nil, err
	}
	if c.Cookie, err = build("sign_key.cookie", cfg.SignKey.Cookie); err != nil {
		return nil, err
	}
	if c.SyncPayload, err = build("sign_key.sync_payload", cfg.SignKey.SyncPayload); err != nil {
		return nil, err
	}
	if c.Challenge, err = build("sign_key.challenge", cfg.SignKey.Challenge); err != nil {
		return nil, err
	}
	if c.Verification, err = build("sign_key.verification", cfg.SignKey.Verification); err != nil {
		return nil, err
	}
	return &c, nil
}

// loginCore 登录链共享单例：terminal / state 由三方、扫码、写票、step-up 各域复用
// （同一 login 密钥与终点链路）。
type loginCore struct {
	terminal *orchestrator.Terminal
	state    *orchestrator.State
}

// factorEnv 因子侧产物：注册表、webauthn 实例（降级时为 nil）、密码失败计数、
// otp service 与两条码值发送桥。
type factorEnv struct {
	registry *factor.Registry
	webauthn *webauthn.Factor
	fails    *cache.PwFailStore
	userRef  factorpassword.UserRefResolver
	otpSvc   *otp.Service
	otpCfg   otp.Config
	sms      *provider.CodeBridge
	email    *provider.CodeBridge
}

// buildLoginCore 构造会话写入适配器、Terminal 与 State；共享单例由 assemble 构造后传入。
func buildLoginCore(deps *assembled) *loginCore {
	sessions := sessionsvc.NewSessionWriter(deps.sessionTokens, deps.epochStore, deps.settings, deps.permissionProbe)
	terminal := orchestrator.NewTerminal(
		sessions,
		deps.codeIssuer,
		deps.sink,
		sessionsvc.NewSyncCookieURLBuilder(deps.codecs.SyncPayload),
		deps.settings,
	)
	return &loginCore{
		terminal: terminal,
		state:    orchestrator.NewState(deps.codecs.Login),
	}
}

// buildFactors 构造六因子注册表（§3.8）与因子共享依赖；otp 发送桥还需
// providerLoader（settings 键 → Loader → NewSender）。
func buildFactors(cfg *config.Config, deps *assembled, users *repo.UserRepo,
	creds *repo.CredentialRepo, webauthnRepo *repo.WebauthnRepo,
) (*factorEnv, error) {
	pwOpts := factorpassword.DefaultOptions()
	if v, ok := deps.settings.GetInt64(settings.KeyPwdFailCapture); ok && v > 0 {
		pwOpts.Capture = v
	}
	if v, ok := deps.settings.GetInt64(settings.KeyPwdFailBan); ok && v > 0 {
		pwOpts.Ban = v
	}
	if v, ok := deps.settings.GetInt64(settings.KeyPwdBanTtl); ok && v > 0 {
		pwOpts.BanTTL = time.Duration(v) * time.Second
	}
	fails := cache.NewPwFailStore(deps.rdb, cache.PwFailOptions{BanTTL: pwOpts.BanTTL})

	// 引擎读计数与因子写计数必须共用同一 user_ref 推导——键口径唯一定义在
	// factor/password；IPResolver 尚未落地，后续接入时改此一处即两侧同步生效。
	var pwIP factorpassword.IPResolver
	pwUserRef := factorpassword.UserRefResolver{Users: users, IP: pwIP}

	registry := factor.NewRegistry()
	// password.New 对 ResetQueue nil 安全（跳过清零 / user_ref 回退 "unknown"）。
	if err := registry.Register(factor.FactorPassword, factorpassword.New(users, fails, nil, pwIP, pwOpts)); err != nil {
		return nil, err
	}
	// 挑战令牌用独立 sign_key.challenge（§11.6.1）：载荷与 login_token 互不解。
	// 启动期初始化失败降级（§8.3 降级窗口）：rp_id 为 IP / 非法域名时禁用
	// webauthn 因子——不注册、打 WARN、程序不退出、其余功能可用；AssertComplete
	// 以降级清单显式放行该 kind。
	wa, waErr := webauthn.New(deps.codecs.Challenge, webauthnRepo, deps.queue, webauthn.Options{
		RPID:          cfg.Authloft.RpID,
		RPDisplayName: cfg.Authloft.RPDisplayName,
		RPOrigins:     []string{cfg.Authloft.Root},
	})
	var degraded []factor.FactorKind
	if waErr != nil {
		slog.Warn("bootstrap: webauthn factor disabled (init failed, degrading; webauthn login/mfa unavailable, other factors continue)", "err", waErr)
		degraded = append(degraded, factor.FactorWebAuthn)
	} else if err := registry.Register(factor.FactorWebAuthn, wa); err != nil {
		return nil, err
	}
	if err := registry.Register(factor.FactorTOTP, totp.New()); err != nil {
		return nil, err
	}
	if err := registry.Register(factor.FactorRecovery, recovery.New()); err != nil {
		return nil, err
	}
	// otp_sms / otp_email 共用因子实现，验证码参数按 settings 启动期快照注入；
	// 发送桥 = settings 键 → Loader → NewSender → asyncqueue 异步投递。
	otpCfg, codeOpts := otp.FromSettings(deps.settings)
	otpSvc := otp.NewService(cache.NewCodeStore(deps.rdb, codeOpts), otpCfg)
	smsSender, err := provider.NewCodeBridge(deps.settings, deps.providerLoader, deps.queue,
		settings.KeySmsProviderKey, provider.CategorySMS)
	if err != nil {
		return nil, err
	}
	emailSender, err := provider.NewCodeBridge(deps.settings, deps.providerLoader, deps.queue,
		settings.KeyEmailProviderKey, provider.CategoryEmail)
	if err != nil {
		return nil, err
	}
	otpSMS, err := factorotp.New(factor.FactorOTPSMS, otpSvc, smsSender, nil, otpCfg)
	if err != nil {
		return nil, err
	}
	otpEmail, err := factorotp.New(factor.FactorOTPEmail, otpSvc, emailSender, nil, otpCfg)
	if err != nil {
		return nil, err
	}
	if err := registry.Register(factor.FactorOTPSMS, otpSMS); err != nil {
		return nil, err
	}
	if err := registry.Register(factor.FactorOTPEmail, otpEmail); err != nil {
		return nil, err
	}
	if err := registry.AssertComplete(degraded...); err != nil {
		return nil, err
	}
	return &factorEnv{
		registry: registry,
		webauthn: wa,
		fails:    fails,
		userRef:  pwUserRef,
		otpSvc:   otpSvc,
		otpCfg:   otpCfg,
		sms:      smsSender,
		email:    emailSender,
	}, nil
}

// buildThirdparty 构造三方登录通道 service（§3.9）：State / Terminal 复用引擎同一
// 实例；al:ticket 结果读写与快照与扫码域共用同一实例（同一 sign_key.ticket）；
// HTTPSMode 与 newSessionCookie 同一三态源。
func buildThirdparty(cfg *config.Config, deps *assembled, users *repo.UserRepo,
	creds *repo.CredentialRepo, core *loginCore,
	tickets *cache.TicketStore, ticketPayloads *cache.TicketPayloadStore,
) *thirdpartysvc.Thirdparty {
	return thirdpartysvc.NewThirdparty(thirdpartysvc.ThirdpartyDeps{
		Loader:         deps.providerLoader,
		Binds:          deps.repos.Binds,
		Users:          users,
		NewAdapter:     provider.NewAdapter,
		State:          core.state,
		Terminal:       core.terminal,
		Settings:       deps.settings,
		Credentials:    creds,
		Tickets:        tickets,
		TicketPayloads: ticketPayloads,
		CookieCodec:    deps.codecs.Cookie,
		// RootOrigin：redirect_uri 拼装基准 {root}/sso/oauth/callback/{key}。
		RootOrigin: cfg.Authloft.Root,
		HTTPSMode:  ssoHTTPSMode(deps),
	})
}

// buildQRCode 构造扫码 service（§2.8 / §13.2）：State / Terminal / Loader / Gate
// 复用引擎实例；al:ticket 读写与 Thirdparty 共用同一实例；码图删除走延迟队列。
func buildQRCode(deps *assembled, core *loginCore,
	tickets *cache.TicketStore, ticketPayloads *cache.TicketPayloadStore,
) *qrcodesvc.QRCode {
	return qrcodesvc.NewQRCode(qrcodesvc.QRCodeDeps{
		Loader:         deps.providerLoader,
		NewAdapter:     provider.NewAdapter,
		Gate:           deps.gate,
		TicketCodec:    deps.codecs.Ticket,
		Tickets:        tickets,
		TicketPayloads: ticketPayloads,
		Storage:        storage.NewResolver(deps.providerLoader),
		Queue:          deps.queue,
		State:          core.state,
		Terminal:       core.terminal,
	})
}

// buildLoginTicket 构造统一写票 service（§2.8）：ConfirmLoginTicket 与 LoginOauth
// 扫码分支共用；按目标用户二次验证启用状态自行判定写 success / mfa_pending。
func buildLoginTicket(deps *assembled, users *repo.UserRepo, creds *repo.CredentialRepo,
	core *loginCore, tickets *cache.TicketStore, ticketPayloads *cache.TicketPayloadStore,
) *ticketsvc.LoginTicket {
	return ticketsvc.NewLoginTicket(ticketsvc.LoginTicketDeps{
		Tickets:        tickets,
		TicketPayloads: ticketPayloads,
		Sessions:       session.NewVerifier(deps.sessionTokens, deps.epochStore),
		State:          core.state,
		Users:          users,
		Settings:       deps.settings,
		Credentials:    creds,
	})
}

// buildVerification 构造 step-up 服务（§3.8）：挑战走 PurposeChallenge + sign_key.challenge，
// 断言走 PurposeVerification + sign_key.verification；captcha 复用唯一 Gate。
func buildVerification(deps *assembled, registry *factor.Registry, users *repo.UserRepo,
	creds *repo.CredentialRepo, core *loginCore,
) *verification.Service {
	var verifGate verification.CaptchaGate
	if deps.gate != nil {
		verifGate = deps.gate
	}
	var verifOnce verification.OnceStore
	if deps.rdb != nil {
		verifOnce = cache.NewOnceStore(deps.rdb)
	}
	return verification.NewService(verification.Deps{
		Codec:       verification.NewAssertionCodec(deps.codecs.Challenge, deps.codecs.Verification),
		Policy:      verification.DefaultPolicy(),
		Settings:    deps.settings,
		Gate:        verifGate,
		Once:        verifOnce,
		Bound:       verification.NewBoundFactorReader(users, creds, deps.settings),
		Verifier:    verification.NewStepUpVerifier(registry, users, creds),
		Starter:     verification.NewStepUpVerifier(registry, users, creds),
		LoginTokens: orchestrator.NewLoginTokenReader(core.state),
		Login:       orchestrator.NewLoginCompleter(core.terminal, core.state),
	})
}

// buildAccountServices 构造 account 域各 service 并挂 deps，registerAccount 仅注入 handler。
// 审计统一走 eventlog.Writer 延迟队列；Now / Rand 缺省（service 构造内落回），
// mfa 的 Rand 显式注入 crypto/rand.Reader（与缺省同值，留显式便于阅读）。
func buildAccountServices(deps *assembled, users *repo.UserRepo, creds *repo.CredentialRepo,
	webauthnRepo *repo.WebauthnRepo, env *factorEnv,
	tickets *cache.TicketStore, ticketPayloads *cache.TicketPayloadStore,
	rootOrigin string,
) {
	// account 域三方绑定族 service（§12.6 / §3.7）：绑定内核两通道共用，ticket
	// 结果读写与 thirdparty / qrcode 共用同一 TicketStore 实例。
	deps.accountThirdparty = accountsvc.NewThirdpartyService(accountsvc.Deps{
		Loader:      deps.providerLoader,
		Providers:   deps.repos.Providers,
		Binds:       deps.repos.Binds,
		Creds:       deps.repos.Creds,
		NewAdapter:  provider.NewAdapter,
		Tickets:     tickets,
		TicketCodec: deps.codecs.Ticket,
		CookieCodec: deps.codecs.Cookie,
		Audit:       eventlog.NewWriter(deps.queue),
		RootOrigin:  rootOrigin,
	})

	// account 域通行密钥族 service（§3.6 / §8.3）：注册内核复用 webauthn 因子同一实例。
	// fail-closed 关键：wa 为 nil（启动降级，waErr 分支）时必须注入 nil 接口而非
	// nil *webauthn.Factor——typed-nil 会绕过 Factor==nil 判定。
	var accountWebauthnFactor accountsvc.WebauthnFactor
	if env.webauthn != nil {
		accountWebauthnFactor = env.webauthn
	}
	deps.accountWebauthn = accountsvc.NewWebauthnService(accountsvc.WebauthnDeps{
		Factor:   accountWebauthnFactor,
		Webauthn: webauthnRepo,
		Creds:    creds,
		Users:    users,
		Settings: deps.settings,
		Audit:    eventlog.NewWriter(deps.queue),
	})

	deps.accountAvatar = accountsvc.NewAvatarService(accountsvc.AvatarDeps{
		Settings:  deps.settings,
		Providers: deps.repos.Providers,
		Users:     users,
		// storage Resolver 与扫码域同源同构造，presign / commit 共用 provider Loader 行缓存。
		Resolver: storage.NewResolver(deps.providerLoader),
	})
	deps.accountPassword = accountsvc.NewPasswordService(accountsvc.PasswordDeps{
		Users:    users,
		Creds:    creds,
		Epoch:    deps.epochStore,
		Settings: deps.settings,
		Audit:    eventlog.NewWriter(deps.queue),
	})
	deps.accountMfa = accountsvc.NewMfaService(accountsvc.MfaDeps{
		Users:      users,
		Creds:      creds,
		Webauthn:   webauthnRepo,
		Settings:   deps.settings,
		Audit:      eventlog.NewWriter(deps.queue),
		Rand:       rand.Reader,
		Assertions: deps.verification,
	})
	deps.accountEvents = accountsvc.NewEventsService(deps.repos.EventLogs)

	// 换绑族双渠道（§3.4）：两实例共用同一 OTP 单例（purpose=bind 与登录因子
	// 隔离）/ captcha Gate / 限流 Config，仅 Sender 分渠道。
	bindContactBase := accountsvc.BindContactDeps{
		Users:  users,
		OTP:    env.otpSvc,
		Gate:   deps.gate,
		Config: env.otpCfg,
		Audit:  eventlog.NewWriter(deps.queue),
	}
	bindPhoneDeps := bindContactBase
	bindPhoneDeps.Sender = env.sms
	bindEmailDeps := bindContactBase
	bindEmailDeps.Sender = env.email
	deps.accountBindContact = bindContactPair{
		phone: accountsvc.NewBindContactService(bindPhoneDeps),
		email: accountsvc.NewBindContactService(bindEmailDeps),
	}
}

// buildDomains 按域顺序装配引擎依赖并返回 engine / terminal / registry：
// core → factors → thirdparty / qrcode / loginTicket → verification → account → engine。
// account 依赖 verification，装配顺序不可调换；register* 只消费本函数落在 deps 上的产物。
func buildDomains(cfg *config.Config, deps *assembled, users *repo.UserRepo,
	creds *repo.CredentialRepo, webauthnRepo *repo.WebauthnRepo,
) (*orchestrator.Engine, *orchestrator.Terminal, *factor.Registry, error) {
	if deps == nil || deps.codecs == nil || deps.settings == nil || deps.queue == nil || deps.sink == nil ||
		deps.sessionTokens == nil || deps.epochStore == nil || deps.codeIssuer == nil || deps.providerLoader == nil {
		return nil, nil, nil, errors.New("bootstrap: engine deps not fully assembled")
	}

	core := buildLoginCore(deps)
	env, err := buildFactors(cfg, deps, users, creds, webauthnRepo)
	if err != nil {
		return nil, nil, nil, err
	}

	// al:ticket 结果读写与快照：三方登录 / 扫码 / 写票三域共用同一实例（同一 sign_key.ticket）。
	tickets := cache.NewTicketStore(deps.rdb, ticketsvc.NewTicketResultSealer(deps.codecs.Ticket), cache.TicketOptions{})
	ticketPayloads := cache.NewTicketPayloadStore(deps.rdb, ticketsvc.NewTicketPayloadSealer(deps.codecs.Ticket))

	deps.thirdparty = buildThirdparty(cfg, deps, users, creds, core, tickets, ticketPayloads)
	deps.qrcode = buildQRCode(deps, core, tickets, ticketPayloads)
	deps.loginTicket = buildLoginTicket(deps, users, creds, core, tickets, ticketPayloads)
	deps.verification = buildVerification(deps, env.registry, users, creds, core)
	buildAccountServices(deps, users, creds, webauthnRepo, env, tickets, ticketPayloads,
		cfg.Authloft.Root)

	engine := orchestrator.NewEngine(orchestrator.EngineDeps{
		State:      core.state,
		Dispatcher: &orchestrator.Dispatcher{Registry: env.registry, Settings: deps.settings},
		// captcha Gate：测试夹具未注入时为 nil，engine 对 nil 安全。
		Gate:     deps.gate,
		Terminal: core.terminal,
		Failures: env.fails,
		// 引擎读计数键经与因子写入侧同源的 user_ref 解析器（见 buildFactors）。
		UserRef: env.userRef,
		Factor: orchestrator.FactorDeps{
			Users:       users,
			Credentials: creds,
		},
		// set_password 步写入依赖（§7.4）：窄接口由 repo 天然满足；epoch 复用共享
		// 单例；审计经 resetAuditSink 走延迟队列；Thirdparty 复用 deps.thirdparty。
		SetPass: &orchestrator.SetPassDeps{
			Users:       users,
			Credentials: creds,
			Epoch:       deps.epochStore,
			Audit:       eventlog.NewResetAuditSink(eventlog.NewWriter(deps.queue)),
			Settings:    deps.settings,
			Thirdparty:  deps.thirdparty,
		},
	})
	return engine, core.terminal, env.registry, nil
}

// assembleStep 记录启动装配失败的具体步骤后原样上抛：启动期无请求上下文，
// 按 CODE_GUIDE §3.8 用包级 slog；err 可能含 DSN 密码，先经 RedactText 脱敏。
// 此前只有 main.go 一条汇总日志，看不出挂在 DB / migrate / Redis / settings
// 哪一步。
func assembleStep(step string, err error) error {
	if err == nil {
		return nil
	}
	slog.Error("bootstrap: assemble step failed",
		"step", step,
		"error", logx.RedactText(err.Error()),
	)
	return err
}

// assemble 正常模式装配步骤 2-8（§3.1 固定顺序）；任一步失败先释放已建资源
// 再原样上抛（serve 转 fail-fast）。provider 注册表与 cron 仍为 TODO。
func assemble(ctx context.Context, cfg *config.Config) (*assembled, error) {
	db, err := repo.Open(cfg)
	if err != nil {
		return nil, assembleStep("repo.Open", err)
	}
	if err := migrate.Up(ctx, cfg.DB.DSN); err != nil {
		closeSQLDB(db)
		return nil, assembleStep("migrate.Up", err)
	}
	rdb, err := cache.NewClient(ctx, cfg)
	if err != nil {
		closeSQLDB(db)
		return nil, assembleStep("cache.NewClient", err)
	}

	deps := &assembled{db: db, rdb: rdb}
	// 共享仓储一次构造（repo 无状态，register* 与 buildDomains 复用同一实例）。
	deps.repos = newRepoSet(db)

	// 步骤 5：七把 sign_key 逐把构造 KeyStore + Codec。
	if deps.codecs, err = buildCodecs(cfg); err != nil {
		deps.closeInfra()
		return nil, assembleStep("buildCodecs", err)
	}

	// 步骤 6（provider 半步，§3.1 / §3.9）：repo 行源 + Redis 整行缓存（版本失效）
	// → Loader（本地 LRU + singleflight）→ Whitelist（Referer 白名单热更新）。
	// providerCache 同实例挂入 assembled，admin 写路径写后失效用。
	deps.providerCache = cache.NewProviderCache(rdb)
	deps.providerLoader = provider.NewLoader(
		deps.repos.Providers, deps.providerCache, provider.LoaderOptions{})
	deps.providerWhitelist = provider.NewWhitelist(deps.providerLoader)

	// 步骤 7：settings 全量预热（缺失键补齐，fail-fast）→ watcher 订阅热更新。
	store := settings.NewStore(repo.NewSettingsRepo(db), rdb)
	if err := store.Preload(ctx); err != nil {
		deps.closeInfra()
		return nil, assembleStep("settings.Preload", err)
	}
	watcher := settings.NewWatcher(rdb, store)
	if err := watcher.Start(ctx); err != nil {
		deps.closeInfra()
		return nil, assembleStep("settings.Watcher.Start", err)
	}
	deps.settings = store
	deps.watcher = watcher

	// 步骤 7.5（captcha 链，§9）：同一 CaptchaStore 供 verifier 与 CreateCaptchaImage；
	// provider 行源走 repo 直查、每次现算不缓存；catalog 提为共享单例，Gate 与
	// registerPages 的 CSP supporter 复用同一实例（CSP 贡献与下发配置必须同源）。
	captchaStore := cache.NewCaptchaStore(rdb)
	captchaSrc := captcha.NewProviderSource(deps.repos.Providers)
	deps.captchaCatalog = captcha.NewCatalog(store, captchaSrc)
	deps.gate = captcha.NewGate(store,
		deps.captchaCatalog,
		captcha.NewVerifier(captchaSrc, captchaStore, captcha.VerifierOptions{}))
	deps.imageCaptcha = captcha.NewImageCaptcha(captchaStore)

	// 步骤 8：延迟写入队列（§5.2）与登录事件 sink（§4.6）。执行器同时消费
	// event_log / last_login、webauthn sign_count、消息投递与码图自动删除（§13.3）。
	users := deps.repos.Users
	creds := deps.repos.Creds
	webauthnRepo := deps.repos.Webauthn
	deps.queue = asyncqueue.New(asyncqueue.NewCombined(
		eventlog.NewExecutor(deps.repos.EventLogs, users),
		webauthn.NewSignCountExecutor(webauthnRepo),
		// otp_sms / otp_email 消息投递（SendJob），其余任务类型原样忽略。
		provider.SendExecutor{},
		// 码图自动删除（DeleteTask，§13.3）。
		qrcode.NewDeleteExecutor(storage.NewResolver(deps.providerLoader)),
	), asyncqueue.DefaultOptions())
	deps.sink = eventlogsvc.NewLoginEventWriter(eventlog.NewWriter(deps.queue))

	// 微信 access_token 跨实例共享缓存（cache/wxacode）注入 wechat_mp_scan 适配器：
	// Redis 就绪后、接受请求前一次完成（适配器按请求构造，读当前注入值）。
	wechatmpscan.SetAccessTokenCache(cache.NewWxacodeStore(rdb))

	// 会话 / 令牌共享单例：sessionTokens / epochStore / codeIssuer 各只构造一份，
	// Terminal / 会话拦截器 / OIDC token 端点复用同一实例。
	deps.sessionTokens = session.NewTokens(deps.codecs.Session)
	deps.epochStore = cache.NewEpochStore(deps.rdb, func(ctx context.Context, uid int64) (int64, error) {
		u, err := users.FindByID(ctx, uid)
		if err != nil {
			return 0, err
		}
		return int64(u.Epoch), nil
	})
	deps.codeIssuer = oidc.NewCodeIssuer(cache.NewOIDCCodeStore(deps.rdb), deps.codecs.Ticket)

	// 权限集合启动预热（§5.1）：全量重建 al:perm:admins，登录签发侧只读；
	// 失败即 fail-fast，避免集合长期落后于 user_permission（回源兜底只覆盖单次判定）。
	permAdmins := cache.NewPermissionAdminsStore(rdb)
	adminUIDs, err := deps.repos.Permissions.ListAdminUIDs(ctx)
	if err != nil {
		deps.closeInfra()
		return nil, assembleStep("permission.ListAdminUIDs", err)
	}
	if err := permAdmins.Rebuild(ctx, adminUIDs); err != nil {
		deps.closeInfra()
		return nil, assembleStep("permissionAdmins.Rebuild", err)
	}
	deps.permissionProbe = adminsvc.NewIssuingPermissionProbe(
		permAdmins, deps.repos.Permissions.HasAnyPermission).Probe

	// 共享产物一次构造，register* 只注入不构造。
	wireSharedServices(cfg, deps)

	// 步骤 6（factor 半步）：factor 注册表 + Terminal + 单引擎（§7）；pendingKinds
	// 内的第三方 / device 由 AssertComplete 显式排除。
	engine, _, registry, err := buildDomains(cfg, deps, users, creds, webauthnRepo)
	if err != nil {
		deps.close(context.Background())
		return nil, assembleStep("buildDomains", err)
	}
	deps.engine = engine
	deps.factors = registry

	// 步骤 6（OIDC 半步，§14.3）：启动期一次性解析 config.oidc.jwt_keys，非法 / 缺失 fail-fast。
	if deps.oidcJWT, err = oidc.NewJWT(cfg.OIDC.JWTKeys, strings.TrimSuffix(cfg.Authloft.Root, "/")); err != nil {
		deps.close(context.Background())
		return nil, assembleStep("oidc.NewJWT", fmt.Errorf("bootstrap: oidc jwt keys: %w", err))
	}

	return deps, nil
}

// closeWarn 资源释放失败只告警、不中断退出流程（此时已无法回滚）。
// 关闭期无请求上下文，按 CODE_GUIDE §3.8 用包级 slog；错误文本先脱敏。
func closeWarn(resource string, err error) {
	if err == nil {
		return
	}
	slog.Warn("bootstrap: resource close failed",
		"resource", resource,
		"error", logx.RedactText(err.Error()),
	)
}

// stopBackground 停止后台协程：先关 watcher，再优雅关闭队列（内部先 flush 再
// 停 worker）。须在 http.Server.Shutdown 之前调用；重复调用安全。
func (a *assembled) stopBackground(ctx context.Context) {
	if a == nil {
		return
	}
	if a.watcher != nil {
		closeWarn("settings.watcher", a.watcher.Close())
		a.watcher = nil
	}
	if a.queue != nil {
		closeWarn("asyncqueue", a.queue.Close(ctx))
		a.queue = nil
	}
}

// closeInfra 关闭 DB / Redis 连接（后台协程须已由 stopBackground 停止，nil 安全）。
func (a *assembled) closeInfra() {
	if a == nil {
		return
	}
	if a.db != nil {
		closeSQLDB(a.db)
		a.db = nil
	}
	if a.rdb != nil {
		closeWarn("redis", a.rdb.Close())
		a.rdb = nil
	}
}

// close 完整释放：stopBackground + closeInfra；HTTP Shutdown 需夹在两者之间（见 serve）。
func (a *assembled) close(ctx context.Context) {
	a.stopBackground(ctx)
	a.closeInfra()
}

// closeSQLDB 关闭 GORM 底层 *sql.DB；取不到或关闭失败均告警，不再静默跳过。
func closeSQLDB(db *gorm.DB) {
	if db == nil {
		return
	}
	sqlDB, err := db.DB()
	if err != nil {
		closeWarn("sql.DB()", err)
		return
	}
	closeWarn("sql.DB.Close", sqlDB.Close())
}

// serveErr 运行期致命错误带阶段标识后原样上抛：main.go 只有一条汇总日志，
// 不标阶段分不清是建 server / 监听 / Serve / 关闭哪一步。无请求上下文，
// 按 CODE_GUIDE §3.8 用包级 slog；错误文本先脱敏。
func serveErr(phase string, err error) error {
	if err == nil {
		return nil
	}
	slog.Error("authloft: serve failed",
		"phase", phase,
		"error", logx.RedactText(err.Error()),
	)
	return err
}

// serve 完成监听与优雅关闭：signal → 停 watcher / 队列（先 flush）→
// http.Server.Shutdown（超时 10s）→ 关 DB / Redis；启动期链路已由 assemble 完成。
func serve(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	deps, err := assemble(ctx, cfg)
	if err != nil {
		return err
	}

	// provider / factor 注册表已由 assemble 构造、适配器自注册经顶部 `_ import` 触发。
	// TODO(cron)：定时清理任务包尚未落地（§3.12），随 cron 接入。

	handler, _ := buildRouterWithSSO(cfg, deps)
	srv, err := newHTTPServer(cfg, handler)
	if err != nil {
		deps.close(context.Background())
		return serveErr("newHTTPServer", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- listenAndServe(cfg, srv) }()

	select {
	case err := <-errCh:
		// 监听自身出错（端口占用等）或外部已关闭：释放装配产物后原样上抛。
		deps.close(context.Background())
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return serveErr("listenAndServe", err)
	case <-ctx.Done():
		// 收到 SIGINT / SIGTERM：先停后台协程（watcher / 队列 worker，队列
		// Close 内部先 flush 剩余任务），再停止接收并等待在途请求，最后
		// 关 DB / Redis（§3.1 行 239 优雅关闭顺序）。
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		deps.stopBackground(shutdownCtx)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("authloft: http shutdown incomplete", "error", err)
		}
		deps.closeInfra()
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return serveErr("shutdown", err)
		}
		return nil
	}
}

// listenAndServe 按 server 段 TLS 配置选择监听模式（§3.1）：已配 cert+key → TLS
// 双协议，未配 → 明文 HTTP/1.1 + H2C；显式 Listen 便于启动日志打印真实监听地址。
func listenAndServe(cfg *config.Config, srv *http.Server) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	slog.Info("authloft listening", "addr", ln.Addr().String())
	if cfg.Server.TLSEnabled() {
		return srv.ServeTLS(ln, cfg.Server.CertFile, cfg.Server.KeyFile)
	}
	return srv.Serve(ln)
}

// setupMode 判定首次启动（§3.15）：配置文件不存在即 setup 模式。
func setupMode(configPath string) bool {
	_, err := os.Stat(configPath)
	return errors.Is(err, fs.ErrNotExist)
}

// buildRouter 从 *config.Config 构造生产顶层 handler（构造注入，测试可传自造实例）；
// 无 deps 时仅组链，正常模式走 buildRouterWithSSO。setup 路由不在本链注册。
func buildRouter(cfg *config.Config) (http.Handler, *gin.RouterGroup) {
	return buildHandler(cfg, connect.NewServer(defaultReadMaxBytes))
}

// buildRouterWithSSO 正常模式装配入口：额外注入登录单引擎并挂 SsoService handler；
// 保留 buildRouter 无依赖形态供测试自造 handler。
func buildRouterWithSSO(cfg *config.Config, deps *assembled) (http.Handler, *gin.RouterGroup) {
	return buildHandlerWithSSO(cfg, connect.NewServer(defaultReadMaxBytes), deps)
}

// buildHandler 顶层分流组装（§3.1）：Connect 各路由按路径前缀挂 mux（requestid →
// logger → metrics → origin），其余全部交给 gin；该分流链上禁挂 gzip / body-capture
// 类中间件（会破坏 h2c / 流式语义）。
// deps 为空时仅做无域 handler 的链路组装（测试口径），非空时注册已装配的域 handler。
func buildHandler(cfg *config.Config, csrv *connect.Server) (http.Handler, *gin.RouterGroup) {
	return buildHandlerWithSSO(cfg, csrv, nil)
}

// buildHandlerWithSSO 在 buildHandler 基础上挂已装配的域 handler、白名单动态源与 OIDC 路由。
func buildHandlerWithSSO(cfg *config.Config, csrv *connect.Server, deps *assembled) (http.Handler, *gin.RouterGroup) {
	// Referer 白名单动态源：已启用 wechat_mp / wechat_mp_scan 的 app_id 集合，
	// 随 provider 变更热更新。查询失败归一为 nil = 空表 → 保守 403；
	// deps == nil（测试口径）→ 来源为 nil，等效空表。
	var refererAllowlist middleware.AllowlistFunc
	if deps != nil && deps.providerWhitelist != nil {
		// 查询失败在每请求的 Origin 链上都会触发：首次必记、之后每 100 次
		// 记一条并带累计值，避免 DB 故障期间刷屏；logx.Warn(ctx, ...) 自动
		// 带 request_id。
		var allowlistFailures atomic.Uint64
		refererAllowlist = func(ctx context.Context) []string {
			ids, err := deps.providerWhitelist.AppIDs(ctx)
			if err != nil {
				n := allowlistFailures.Add(1)
				if n == 1 || n%100 == 0 {
					logx.Warn(ctx, "bootstrap: referer allowlist lookup failed",
						"failures", n,
						"error", logx.RedactText(err.Error()),
					)
				}
				return nil
			}
			return ids
		}
	}
	ginEngine, apiGroup := newRouter(cfg.Authloft.Root, refererAllowlist)

	if deps != nil {
		registerSSO(cfg, csrv, deps)
		registerAccount(cfg, csrv, deps)
		registerAdmin(cfg, csrv, deps)
		registerRPC(cfg, csrv, deps)
		// OIDC REST 端点（§4.1）：注册在 gin 链，不经 Connect、不套信封。
		registerOIDC(ginEngine, deps)
		// 网关 decode（§6）：/api 组下挂 /gateway 子组 + Gateway 中间件。
		registerGateway(apiGroup, deps)
		// 页面壳路由族（§2.9 / §8）：三端 SPA 空壳 + 登出 + sync_cookie 中转。
		registerPages(ginEngine, cfg, deps)
	}

	mux := http.NewServeMux()
	mux.Handle("/", ginEngine)
	// 静态资源 /assets/**：无鉴权恒在（CDN 回源与内网直连），不经 Connect / 中间件链。
	assets.Register(mux)
	for _, rt := range csrv.Routes() {
		mux.Handle(rt.Prefix, middleware.HTTPRequestID(
			middleware.HTTPLogger(
				middleware.HTTPMetrics(
					// Connect 前缀链 origin 用动态白名单形态（与 gin 版同一判定核心）；
					// requestinfo 记录的 XFF 可伪造，仅供审计、不作安全判定。
					middleware.HTTPOriginFunc(cfg.Authloft.Root, refererAllowlist, orchestrator.WithRequestInfoHandler(rt.Handler)),
				),
			),
		))
	}
	return mux, apiGroup
}

// ssoSessionTTL session_ttl 键缺失 / 非法时的回落值（默认 7 天）。
const ssoSessionTTL int64 = 604800

// newDomainSessionInterceptor 构造域级 session 拦截器：sso 与 account 两域共用同一
// 构造；Tokens / EpochStore 复用共享单例（与登录终点同源）。
func newDomainSessionInterceptor(cfg *config.Config, deps *assembled) connectrpc.UnaryInterceptorFunc {
	return connect.NewSessionInterceptor(
		session.NewVerifier(deps.sessionTokens, deps.epochStore),
		session.NewRenewer(deps.sessionTokens, ssoSessionTTLRaw(deps.settings)),
		newSessionCookie(cfg, deps),
		ssoCookieName(deps),
	)
}

// ssoCookieName 会话 Cookie 名动态源（settings 键 cookie_name 每请求读取，缺失由 session.NewCookie 落回默认）。
func ssoCookieName(deps *assembled) func() string {
	return func() string {
		v, _ := deps.settings.GetString(settings.KeyCookieName)
		return v
	}
}

// ssoHTTPSMode https_deployment 三态动态源：每请求读取、禁止进程内缓存死值，
// 全部 Cookie 下发点（session.Cookie 与 thirdparty）同一三态源。
func ssoHTTPSMode(deps *assembled) func() string {
	return func() string {
		v, _ := deps.settings.GetString(settings.KeyHttpsDeployment)
		return v
	}
}

// newSessionCookie 构造会话 Cookie 属性构造器：名 / 根域 / TTL / Secure 三态均同源
// 于 settings；拦截器续期与 sso 登录终点共用本构造，不另造第二套。
func newSessionCookie(cfg *config.Config, deps *assembled) *session.Cookie {
	return session.NewCookie(ssoCookieName(deps)(), rootHost(cfg.Authloft.Root),
		ssoSessionTTLRaw(deps.settings), session.WithHTTPSMode(ssoHTTPSMode(deps)))
}

// registerSSO 注册 SsoService handler：挂 session 拦截器（LoginDefault 免鉴权），
// 注入会话 Cookie 构造器、三方登录 / 扫码 / 写票 / step-up service。
func registerSSO(cfg *config.Config, csrv *connect.Server, deps *assembled) {
	path, h := ssov1connect.NewSsoServiceHandler(
		// 扫码 / 写票 / step-up service：GetLoginTicket 建会话与登录终点同一写出出口。
		ssohandler.New(deps.engine, deps.imageCaptcha, deps.sessionSvc.Cookie, deps.thirdparty, deps.qrcode, deps.verification).WithLoginTicket(deps.loginTicket),
		csrv.HandlerOptions(deps.sessionSvc.Interceptor)...,
	)
	csrv.Register(path, h)
}

// registerAccount 注册 AccountService handler：挂同一 session 拦截器（全接口需用户
// 会话，无 LoginDefault 式豁免，无会话由 handler 返回 unauthenticated）；
// 各 service 由 buildDomains / wireSharedServices 构造，本函数只注入。
func registerAccount(cfg *config.Config, csrv *connect.Server, deps *assembled) {
	path, h := accountv1connect.NewAccountServiceHandler(
		accounthandler.NewWithServices(
			deps.repos.Users,
			deps.repos.Creds,
			deps.settings,
			deps.repos.Providers,
			deps.gate,
			deps.accountThirdparty,
			deps.accountWebauthn,
			deps.accountProfile,
			deps.accountAvatar,
			deps.accountPassword,
			deps.accountBindContact,
			deps.accountMfa,
			deps.accountEvents,
			deps.sessionSvc.Cookie,
			deps.admin.Permission.ListPermissions,
			deps.verification,
		),
		csrv.HandlerOptions(deps.sessionSvc.Interceptor)...,
	)
	csrv.Register(path, h)
}

// bindContactPair 换绑族双渠道组合（§3.4）：两实例依赖全同、仅 Sender 分渠道，
// handler 侧 ContactBinder 单注入位由此适配。
type bindContactPair struct {
	phone *accountsvc.BindContactService
	email *accountsvc.BindContactService
}

func (p bindContactPair) BindPhone(ctx context.Context, uid int64, in accountsvc.BindPhoneInput) error {
	return p.phone.BindPhone(ctx, uid, in)
}

func (p bindContactPair) BindEmail(ctx context.Context, uid int64, in accountsvc.BindEmailInput) error {
	return p.email.BindEmail(ctx, uid, in)
}

// registerAdmin 注册 AdminService handler：session 拦截器在外、admin 拦截器在内
// 权限探针故障须 fail-closed，不回落 404（§3.14）；错误包装挂链最内层。
// 读路径直连 ProviderRepo；写族 / 用户 / 客户端 / 系统配置各族走 service/admin，
// epoch / settings / 审计 / 编解码器复用共享单例。
func registerAdmin(cfg *config.Config, csrv *connect.Server, deps *assembled) {
	path, h := adminv1connect.NewAdminServiceHandler(
		adminhandler.New(
			deps.repos.Providers,
			deps.admin.Providers,
			deps.admin.Users,
			deps.admin.Clients,
			deps.admin.Templates,
			deps.admin.Settings,
			deps.admin.Permission.ListPermissions,
		),
		csrv.HandlerOptions(deps.sessionSvc.Interceptor, connect.NewAdminInterceptor(deps.admin.Permission.HasAnyPermission))...,
	)
	csrv.Register(path, h)
}

// registerRPC 注册 rpc 域两个 handler：鉴权 = rpc HMAC 拦截器（session 步归端点自身），
// 一律经 csrv.RegisterRPC 注册（强制 CaptureRawBody，漏挂按 internal fail-closed）；
// Verifier / Renewer 复用共享单例，TTL 与会话拦截器同源。
func registerRPC(cfg *config.Config, csrv *connect.Server, deps *assembled) {
	// rpc 域两 service 共享同一 UserRepo 实例（同一数据面，不重复构造）。
	users := deps.repos.Users
	path, h := rpcv1connect.NewUserServiceHandler(
		rpchandler.NewUserHandler(users),
		csrv.HandlerOptions(deps.infra.HMAC)...,
	)
	csrv.RegisterRPC(path, h)

	path, h = rpcv1connect.NewTokenServiceHandler(
		rpchandler.NewTokenHandler(
			deps.sessionSvc.Verifier,
			deps.sessionSvc.Renewer,
			users,
		),
		csrv.HandlerOptions(deps.infra.HMAC)...,
	)
	csrv.RegisterRPC(path, h)
}

// registerOIDC 注册 OIDC REST 端点（§4.1）：五件套全部由装配产物注入——JWT /
// CodeIssuer / Epoch 均复用共享单例，不得各写一份；repo wrapper 按端点就近构造。
func registerOIDC(r gin.IRouter, deps *assembled) {
	clients := deps.repos.Clients
	refreshTokens := deps.repos.OidcTokens
	users := deps.repos.Users
	oidchandler.Register(r, oidchandler.Deps{
		JWT: deps.oidcJWT,
		Tokens: &oidc.TokenService{
			JWT:     deps.oidcJWT,
			Clients: clients,
			Codes:   deps.codeIssuer,
			Tokens:  refreshTokens,
			Epoch:   deps.epochStore,
		},
		Revoker: &oidc.Revoker{
			Clients: clients,
			Tokens:  refreshTokens,
		},
		UserInfo: &oidc.UserInfoService{
			JWT:      deps.oidcJWT,
			Users:    users,
			Profiles: users,
			Epoch:    deps.epochStore,
		},
	})
}

// registerGateway 注册 `ANY /api/gateway/decode`（§6）：Gateway 中间件先于 handler，
// tokens 动态源每请求读取 settings、Verifier / Cookie 名与 session 拦截器同源。
func registerGateway(api gin.IRouter, deps *assembled) {
	gw := api.Group("/gateway")
	gw.Use(middleware.Gateway(gatewayTokensSource(deps.settings)))
	gatewayhandler.Register(gw, gatewayhandler.Deps{
		Verify: deps.sessionSvc.Verifier,
		CookieName: func() string {
			v, _ := deps.settings.GetString(settings.KeyCookieName)
			return v
		},
	})
}

// gatewayTokensSource gateway_tokens 动态源：每请求读 settings 快照（写方立即生效、
// 跨实例经 watcher 热更）；st 为 nil 时返回 nil func，中间件按「缺配置保守拒绝」处理。
func gatewayTokensSource(st *settings.Store) func() []string {
	if st == nil {
		return nil
	}
	return func() []string {
		v, _ := st.GetStringSlice(settings.KeyGatewayTokens)
		return v
	}
}

// ssoSessionTTLRaw 读取 session_ttl。
func ssoSessionTTLRaw(st *settings.Store) time.Duration {
	if st != nil {
		if v, ok := st.GetInt64(settings.KeySessionTtl); ok && v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return time.Duration(ssoSessionTTL) * time.Second
}

// registerPages 注册页面壳路由族（§8 / §2.9）：三端 SPA 空壳、登出 / 同步中转、
// OIDC 授权入口。路由组挂 middleware.CSP()：每请求 nonce + 基线 CSP 头，并追加
// static_base CDN 源与 captchaCatalog 贡献源（与 Gate 下发配置同实例同源）；
// 依赖全部复用 assemble 共享单例。
func registerPages(r gin.IRouter, cfg *config.Config, deps *assembled) {
	pages.Register(r.Group("", middleware.CSP(
		pages.StaticBaseCSPSupporter(deps.settings),
		deps.captchaCatalog,
	)), pages.Deps{
		Root:       cfg.Authloft.Root,
		RootDomain: rootHost(cfg.Authloft.Root),
		Settings:   deps.settings,
		Loader:     deps.providerLoader,
		Factors:    deps.factors,
		Gate:       deps.gate,
		Sync:       deps.sessionSvc.Sync,
		Codec:      deps.codecs.SyncPayload,
		JWT:        deps.oidcJWT,
		Clients:    deps.repos.Clients,
		Sessions:   deps.sessionSvc.Verifier,
		Codes:      deps.codeIssuer,
		Audit:      deps.infra.Events,
		Templates:  deps.admin.Templates,
		SsoClients: deps.repos.Clients,
	})
}

// rootHost 从 authloft.root 取根域供 Cookie Domain；非法 / 空值回落空串。
func rootHost(root string) string {
	u, err := url.Parse(root)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// newHTTPServer 构造 http.Server：监听地址与协议取自 server 段（与 setup 同口径）；
// min_tls_version 非法值在此 fail-fast，防测试自造实例绕过 config.Validate。
func newHTTPServer(cfg *config.Config, handler http.Handler) (*http.Server, error) {
	srv := &http.Server{Handler: handler}
	if err := cfg.Server.ConfigureHTTPServer(srv); err != nil {
		return nil, err
	}
	return srv, nil
}
