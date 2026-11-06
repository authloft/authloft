// bootstrap.go 按 docs/后端架构.md §3.1 行 237 的固定顺序装配启动链：
// config → DB → 迁移检查（migrate up，幂等）→ Redis → 密钥 → provider/factor
// 注册表 → settings 预热 → 队列 worker → cron → router。已落地 config /
// DB / migrate / Redis 四步，并接入五把密钥、settings 预热 + watcher、
// 队列 + 事件日志 sink 与优雅关闭；factor 注册表、Terminal 与登录单引擎
// 已接入；provider 注册表与 cron 仍为 TODO。
//
// 启动分支（§3.1 行 253）：configs/config.yaml 不存在 → setup 模式
//——不加载 config、不初始化 DB / Redis、不起业务链路，只启动 internal/setup
//（§3.15）；存在 → 正常装配（保持既有结构）。
//
// 顶层分流与监听（§3.1 行 241-247）：标准库 http.ServeMux
// 顶层——Connect handler 按路径前缀挂 mux（requestid / logger / metrics /
// origin 等效链），其余全部交给 gin；监听由 server 段
// TLS 配置决定（Go 1.26 标准库原生 http.Server.Protocols：未配 cert+key
// → HTTP/1.1 + H2C；已配 → TLS 双协议 + min_tls_version），不引 x/net。

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
	"authloft/internal/middleware"
	"authloft/internal/migrate"
	"authloft/internal/oidc"
	core "authloft/internal/otp"
	"authloft/internal/pages"
	"authloft/internal/provider"
	// §3.1 行 237：注册表导入在此处统一触发 init() 自注册——
	// wechat_mp 适配器 init() 向 provider 渠道注册表登记工厂（§12.2 / §15.3）；
	// smtp / aliyun_sms 向消息域注册表登记 Sender（§15.2 / §15.3）。
	_ "authloft/internal/provider/email/smtp"
	_ "authloft/internal/provider/oauth/wechat_mp"
	_ "authloft/internal/provider/sms/aliyun_sms"
	// wechat_mp_scan 具名导入：init() 自注册（第二处渠道注册），
	// 装配期另需 SetAccessTokenCache 注入共享 access_token 缓存（§3.4 行
	// 469 cache/wxacode，Redis 就绪后调用）。
	wechatmpscan "authloft/internal/provider/oauth/wechat_mp_scan"
	"authloft/internal/qrcode"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service"
	accountsvc "authloft/internal/service/account"
	adminsvc "authloft/internal/service/admin"
	"authloft/internal/service/orchestrator"
	"authloft/internal/session"
	"authloft/internal/settings"
	"authloft/internal/setup"
	"authloft/internal/storage"
)

// defaultReadMaxBytes Connect 域请求体上限默认值（docs/后端架构.md §1.6
// 行 86、§3.14 行 478：由装配层经 connect.NewServer 注入，包自身不读 config）。
const defaultReadMaxBytes = 1 << 20

// run 装配并阻塞运行 HTTP 服务（§3.1 行 248）。装配与运行错误原样上抛，
// 由 main 转 exit 非 0（fail-fast）；setup 模式下安装完成的退出走 Run 的
// nil 返回（exit 0，由部署环境拉起，§13.4）。
func run(configPath string) error {
	if setupMode(configPath) {
		return setup.NewServer(configPath).Run()
	}
	// 步骤 1 config：启动期一次读取 + env 覆盖 + Validate，任一失败即
	// fail-fast（§3.2 行 289）。sign_key 只在安装流程生成（§3.15），
	// 文件存在但缺项 / 非法一律 fail-fast，不自动补写（§3.2 约定 4）。
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	return serve(cfg)
}

// shutdownTimeout HTTP 优雅关闭上限（与队列 CloseTimeout 同口径 10s，§5.2
// 行 892：超时后不再等待在途请求 / 批次）。
const shutdownTimeout = 10 * time.Second

// assembled 正常模式装配产物（§3.1 行 237 启动链）：DB / Redis / 五把密钥编解码
// / settings 快照与热更新 watcher / 延迟写入队列与事件日志 sink / 登录单引擎 /
// provider 加载链与 Referer 白名单来源 / OIDC JWT 与共享单例。cron 仍为 TODO
// （§3.12，随 cron 卡接入）。
type assembled struct {
	db       *gorm.DB
	rdb      *redis.Client
	codecs   *codecs
	settings *settings.Store
	watcher  *settings.Watcher
	queue    *asyncqueue.Queue
	sink     *service.LoginEventWriter
	engine   *orchestrator.Engine

	// provider 链（§3.9 / §15.3 / §13.0）：Loader 供后续 thirdparty
	// 登录卡按 provider_key 取实例；Whitelist 是 origin 中间件 Referer 白
	// 名单的唯一动态来源（已启用 wechat_mp / wechat_mp_scan 的 app_id 集合）。
	// providerCache 与 Loader 共用同一 *cache.ProviderCache 实例：
	// admin 写路径的写后失效（§15.3 行 1734 固定三步）与读路径的整行缓存
	// / 版本号共用键空间，双实例会造成失效与回写各说各话。
	providerLoader    *provider.Loader
	providerWhitelist *provider.Whitelist
	providerCache     *cache.ProviderCache

	// 会话 / 令牌共享单例（消除 registerSSO 与 buildEngine
	// 的重复构造）：sessionTokens 供 sso 会话拦截器与 Terminal SessionWriter
	// 共用；epochStore 供会话校验与 OIDC 令牌 epoch 校验共用；codeIssuer 供
	// Terminal（sso 登录终点）与 OIDC token 端点共用同一授权码签发者。
	sessionTokens *session.Tokens
	epochStore    *cache.EpochStore
	codeIssuer    *oidc.CodeIssuer

	// oidcJWT OIDC RS256 签发密钥集（§3.2 约定 6 / §14.3：启动期一次性解析
	// config.oidc.jwt_keys，首项签发、全列表发 JWKS；iss = authloft.root）。
	oidcJWT *oidc.JWT

	// captcha 链（§9）：Gate 是登录引擎人机校验唯一拦截点（engine
	// 六步之四，§9.3 行 1110）；imageCaptcha 供 sso 域 CreateCaptchaImage
	// 生成自绘图形码。catalog / verifier 每次 Evaluate 现算（§9.1 行 1094
	// 不缓存），provider 行源走 repo 直查（不与 Loader 的 60s LRU 共用，
	// 保证「每次生成时重新判定」）。catalog 同实例兼任 CSP
	// supporter（§9.4：CSP 贡献与下发配置、拦截校验同源），registerPages
	// 页面路由组的 CSP 中间件追加注入。
	gate           *captcha.Gate
	captchaCatalog *captcha.Catalog
	imageCaptcha   *captcha.ImageCaptcha

	// factors 因子注册表（§3.8）：buildEngine 构造后挂入，供页面壳
	// methods 快照按 settings.login_methods 过滤读取（接口文档 §2.1 / §8）。
	factors *factor.Registry

	// thirdparty 三方登录通道 service（§3.9 / §12.4-§12.5）：buildEngine
	// 内构造（复用 Terminal / MFA / State 共享 codec），registerSSO 注入
	// SsoService handler；SetPass.Thirdparty（免密建号）复用同一实例。
	thirdparty *service.Thirdparty

	// qrcode 扫码三桩 service（§3.9 / §13.2 / §2.8）：buildEngine 内
	// 构造（复用 State / Terminal / provider Loader / captcha Gate），经
	// cache.TicketStore 读写 al:ticket（sealer = protojson 整值加密，
	// §11.6.5），registerSSO 注入 SsoService handler。
	qrcode *service.QRCode

	// accountThirdparty account 域三方绑定族 service（§12.6 绑定内核 /
	// 接口文档 §3.7）：buildEngine 内构造（复用 provider Loader / cache.TicketStore
	// / ticket / cookie 两把 codec / eventlog 延迟队列审计），registerAccount
	// 注入 AccountService handler。
	accountThirdparty *accountsvc.ThirdpartyService

	// accountWebauthn account 域通行密钥族 service（接口文档 §3.6 /
	// 后端架构 §8.3 行 1070-1075）：buildEngine 内构造（注册内核复用 webauthn
	// 因子同一实例、审计走 eventlog 延迟队列），registerAccount 注入
	// AccountService handler。Factor 注入 nil 时 service 五路 fail-closed
	//（启动降级窗口，§8.3 行 1071）。
	accountWebauthn *accountsvc.WebauthnService

	// account 五族 service（接口文档 §3.2-§3.7）：avatar
	//（头像直传）/ password（改密）/ mfa（两步验证族）/
	// events（本人事件日志）四族 buildEngine 内构造（依赖复用
	// users / creds / webauthnRepo / settings / epochStore / provider Loader /
	// storage Resolver / eventlog 延迟队列审计，同款挂 deps 模式），
	// registerAccount 经 NewWithServices 注入 AccountService handler。
	accountAvatar   *accountsvc.AvatarService
	accountPassword *accountsvc.PasswordService
	accountMfa      *accountsvc.MfaService
	accountEvents   *accountsvc.EventsService

	// accountBindContact 换绑族双渠道组合（接口文档 §3.4）：BindPhone
	// / BindEmail 各持一个 BindContactService 实例——OTP / captcha Gate /
	// 限流 Config / 审计依赖全同（与登录因子共享同一 otp 单例，purpose=bind
	// 键空间独立），仅 Sender 按渠道分注（sms 桥 / email 桥；
	// BindCodeSender「装配方按渠道注入」的落地）；handler 侧 ContactBinder
	// 单注入位由 bindContactPair 适配，registerAccount 注入。
	accountBindContact accounthandler.ContactBinder
}

// codecs 五场景独立编解码器（§1.4 / §11.6.1）：session / login / ticket /
// cookie / sync_payload 各持一把密钥，互不复用。
type codecs struct {
	Session     *security.Codec
	Login       *security.Codec
	Ticket      *security.Codec
	Cookie      *security.Codec
	SyncPayload *security.Codec
}

// buildCodecs 把 cfg.SignKey 五把 KeyMaterial 逐把转成 security.Codec
// （§3.1 步骤 5、§1.4 / §11.6.1）。base64 解码与 kid 范围在任何一步非法即
// 返回错误，由 serve 转 fail-fast；密钥长度由 security.NewKeyStore 校验
// （AES-256 恰 32 字节）。每把独立构造 KeyStore，绝不共用。
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
	return &c, nil
}

// eventLogExecutor 延迟写入队列的执行器（§5.2 行 886）：把攒批后的任务落到
// 已落地的 repo——model.EventLog 走 EventLogRepo.BatchInsert，last_login_at
// 走 UserRepo.UpdateLastLogin。执行失败只记日志（队列骨架不重试、不影响登录
// 主链路，§5.2 行 893）；真实重试策略归后续执行器卡。
type eventLogExecutor struct {
	logs  *repo.EventLogRepo
	users *repo.UserRepo
}

func (e *eventLogExecutor) Execute(ctx context.Context, tasks []asyncqueue.Task) {
	var rows []model.EventLog
	for _, task := range tasks {
		switch v := task.Value.(type) {
		case model.EventLog:
			rows = append(rows, v)
		case eventlog.LastLoginTask:
			if err := e.users.UpdateLastLogin(ctx, v.UserID, v.At); err != nil {
				slog.Warn("asyncqueue: update last_login_at failed", "user_id", v.UserID, "error", err)
			}
		}
	}
	if len(rows) == 0 {
		return
	}
	if err := e.logs.BatchInsert(ctx, rows); err != nil {
		slog.Warn("asyncqueue: batch insert event_log failed", "rows", len(rows), "error", err)
	}
}

// combinedExecutor 把同一批任务分发给多个执行器：每个执行器只消费自己
// 认识的任务类型（event_log / last_login 与 webauthn sign_count 互不干扰），
// 满足 asyncqueue 单执行器构造口径（§5.2 行 872、§8.3 行 1049）。
type combinedExecutor []asyncqueue.Executor

func (c combinedExecutor) Execute(ctx context.Context, tasks []asyncqueue.Task) {
	for _, exec := range c {
		exec.Execute(ctx, tasks)
	}
}

// mfaCredentialReader 组合 credential / webauthn 两个 repo，满足编排层
// MFACredentialReader（mfa.go 行 21-24）；不修改 repo 公共接口。
type mfaCredentialReader struct {
	creds    *repo.CredentialRepo
	webauthn *repo.WebauthnRepo
}

func (r mfaCredentialReader) FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error) {
	return r.creds.FindByUserAndKind(ctx, userID, kind)
}

func (r mfaCredentialReader) ListWebauthn(ctx context.Context, userID int64) ([]model.UserCredentialWebauthn, error) {
	return r.webauthn.ListByUser(ctx, userID)
}

// captchaProviderSource 把 provider 表行转成 captcha 包窄投影
// （captcha.ProviderSource，§3.11 行 446：captcha 包不自持 DB 句柄；与
// mfaCredentialReader 同款组合模式，不修改 repo 公共接口）。ext 编解码
// 唯一出口 repo.ParseProviderExt（§12.1：site_key=client_id、
// secret=client_secret、endpoint=自定义校验地址）；未命中唯一键按
// 「无此行」返回 nil,nil，其余错误原样上抛。
type captchaProviderSource struct {
	providers *repo.ProviderRepo
}

func (s captchaProviderSource) Find(ctx context.Context, providerKey string) (*captcha.ProviderRecord, error) {
	if providerKey == "" {
		return nil, nil
	}
	row, err := s.providers.FindByKey(ctx, providerKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return nil, err
	}
	return &captcha.ProviderRecord{
		ProviderKey: row.ProviderKey,
		Category:    row.Category,
		Type:        row.Type,
		Enabled:     row.IsEnabled != 0,
		SiteKey:     ext.GetClientId(),
		Secret:      ext.GetClientSecret(),
		VerifyURL:   ext.GetEndpoint(),
	}, nil
}

// buildEngine 构造因子注册表（§3.8）、登录终点 Terminal（§7.3）与单引擎
// Engine（§7.2-§7.4），供 assemble 注入。返回 terminal / registry 便于装配单测
// 直接核对注入完整性，不进入 assembled 字段。
func buildEngine(cfg *config.Config, deps *assembled, users *repo.UserRepo,
	creds *repo.CredentialRepo, webauthnRepo *repo.WebauthnRepo,
) (*orchestrator.Engine, *orchestrator.Terminal, *factor.Registry, error) {
	// sessionTokens / epochStore / codeIssuer 由 assemble 构造为共享
	// 单例（registerSSO 与 OIDC 端点复用同一实例，不再各自构造第二份）。
	// otp 因子的发送桥还需 providerLoader（settings 键 → Loader →
	// NewSender，§15.3 行 1735）。
	if deps == nil || deps.codecs == nil || deps.settings == nil || deps.queue == nil || deps.sink == nil ||
		deps.sessionTokens == nil || deps.epochStore == nil || deps.codeIssuer == nil || deps.providerLoader == nil {
		return nil, nil, nil, errors.New("bootstrap: engine deps not fully assembled")
	}

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

	// 引擎读计数与因子写计数共用同一 user_ref 推导——同一 Users /
	// IPResolver 实例注入两侧，键口径唯一定义在 factor/password
	// UserRefResolver / UserRefOf。TODO(§8.1)：IPResolver 实现归后续实现
	//（暂不并入），双侧共用 nil → "unknown" 兜底；落地时改此一处
	// 即两侧同步生效。
	var pwIP factorpassword.IPResolver
	pwUserRef := factorpassword.UserRefResolver{Users: users, IP: pwIP}

	registry := factor.NewRegistry()
	// password.New 对 ResetQueue nil 安全（跳过清零 / user_ref 回退 "unknown"）。
	if err := registry.Register(factor.FactorPassword, factorpassword.New(users, fails, nil, pwIP, pwOpts)); err != nil {
		return nil, nil, nil, err
	}
	// 注册令牌复用 login 域密钥（§1.4 五把密钥未单列 webauthn；purpose
	// 作为 AAD 保证跨场景隔离，§11.6.1）。启动期初始化失败降级（§8.3 行
	// 1069，2026-11-05 定稿）：rp_id 为 IP / 非法域名导致库 RPID
	// 校验失败（must be a domain and not an IP）时禁用 webauthn 因子——
	// 不注册进注册表（登录方式列表与 MFA 开放集合随之不含 webauthn：
	// dispatch 对未注册 kind 返回 method_disabled），打 WARN 日志（含失败
	// 原因），程序不退出、其余功能可用；已绑定凭据的用户改走其余登录 /
	// MFA 方式。AssertComplete 以降级清单显式放行该 kind。
	wa, waErr := webauthn.New(deps.codecs.Login, webauthnRepo, deps.queue, webauthn.Options{
		RPID:      cfg.Authloft.RpID,
		RPOrigins: []string{cfg.Authloft.Root},
	})
	var degraded []factor.FactorKind
	if waErr != nil {
		slog.Warn("bootstrap: webauthn factor disabled (init failed, degrading; webauthn login/mfa unavailable, other factors continue)", "err", waErr)
		degraded = append(degraded, factor.FactorWebAuthn)
	} else if err := registry.Register(factor.FactorWebAuthn, wa); err != nil {
		return nil, nil, nil, err
	}
	if err := registry.Register(factor.FactorTOTP, totp.New()); err != nil {
		return nil, nil, nil, err
	}
	if err := registry.Register(factor.FactorRecovery, recovery.New()); err != nil {
		return nil, nil, nil, err
	}
	// OTP 发送（§8.2 行 1051 / §15.2）：otp_sms / otp_email 共用因子实现，验证码
	// 参数按 settings 快照注入（§5.6 行 1303-1311，热更新口径同 password 先例
	// ——启动期快照）；发送桥 = settings 键 → Loader → NewSender → asyncqueue
	// 异步投递（provider/sender.go）。IPResolver 尚未落地（暂不并入），
	// 传 nil 走 §8.2 的 "unknown" 兜底，与 password 因子 nil 先例一致。
	otpCfg, codeOpts := otpParamsFromSettings(deps.settings)
	otpSvc := core.NewService(cache.NewCodeStore(deps.rdb, codeOpts), otpCfg)
	smsSender, err := provider.NewCodeBridge(deps.settings, deps.providerLoader, deps.queue,
		settings.KeySmsProviderKey, provider.CategorySMS)
	if err != nil {
		return nil, nil, nil, err
	}
	emailSender, err := provider.NewCodeBridge(deps.settings, deps.providerLoader, deps.queue,
		settings.KeyEmailProviderKey, provider.CategoryEmail)
	if err != nil {
		return nil, nil, nil, err
	}
	otpSMS, err := factorotp.New(factor.FactorOTPSMS, otpSvc, smsSender, nil, otpCfg)
	if err != nil {
		return nil, nil, nil, err
	}
	otpEmail, err := factorotp.New(factor.FactorOTPEmail, otpSvc, emailSender, nil, otpCfg)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := registry.Register(factor.FactorOTPSMS, otpSMS); err != nil {
		return nil, nil, nil, err
	}
	if err := registry.Register(factor.FactorOTPEmail, otpEmail); err != nil {
		return nil, nil, nil, err
	}
	if err := registry.AssertComplete(degraded...); err != nil {
		return nil, nil, nil, err
	}

	// 会话 / epoch / 授权码共享单例（assemble 构造，消除冗余）：
	// Terminal 的 SessionWriter 与 sso 会话拦截器、OIDC token 端点各自复用，
	// 不再构造第二份 EpochStore / Tokens / CodeIssuer。
	sessions := service.NewSessionWriter(deps.sessionTokens, deps.epochStore, deps.settings)
	terminal := orchestrator.NewTerminal(
		sessions,
		deps.codeIssuer,
		deps.sink,
		service.NewSyncCookieURLBuilder(deps.codecs.SyncPayload),
		deps.settings,
	)
	loginState := orchestrator.NewState(deps.codecs.Login)
	mfa := orchestrator.NewMFABuilder(users, mfaCredentialReader{creds: creds, webauthn: webauthnRepo}, deps.settings)
	// MFA 开放集合联动启动降级（§8.3 行 1069）——注入同一
	// registry（与页面壳 Factors 同源；webauthn 降级未注册时 Build 的
	// webauthn case 跳过注入 methods）。
	mfa.Factors = registry

	// 三方登录通道 service（§3.9 / §12.4-§12.5）：State / MFA /
	// Terminal 复用引擎同一实例（同一 login 密钥与终点链路），绑定写入走
	// BindRepo.CreateWithUnion（§12.7 行 1548 创建方向同事务），auto_bind
	// 目标匹配走 UserRepo；HTTPSMode 注入 https_deployment 三态源
	// （al_login_state 的 Secure 属性随驱动，与 newSessionCookie 同一源）；
	// 扫码 ticket 分支：Tickets（al:ticket 结果读写）与 TicketPayloads
	//（al:ticket:payload 快照）与下方扫码域共用同一实例（同一
	// sign_key.ticket 密钥与封装）。挂入 assembled 供 registerSSO 注入
	// handler，SetPass.Thirdparty（免密建号 §12.5 行 1501）复用同一实例。
	tickets := cache.NewTicketStore(deps.rdb, service.NewTicketResultSealer(deps.codecs.Ticket), cache.TicketOptions{})
	ticketPayloads := cache.NewTicketPayloadStore(deps.rdb, service.NewTicketPayloadSealer(deps.codecs.Ticket))
	deps.thirdparty = service.NewThirdparty(service.ThirdpartyDeps{
		Loader:         deps.providerLoader,
		Binds:          repo.NewBindRepo(deps.db),
		Users:          users,
		NewAdapter:     provider.NewAdapter,
		State:          loginState,
		MFA:            mfa,
		Terminal:       terminal,
		Tickets:        tickets,
		TicketPayloads: ticketPayloads,
		CookieCodec:    deps.codecs.Cookie,
		HTTPSMode:      ssoHTTPSMode(deps),
	})

	// 扫码三桩 service（§13.2 / §2.8）：State / Terminal 复用引擎同一
	// 实例（同一 login 密钥与终点链路）；al:ticket 读写走 cache.TicketStore
	//（sealer = protojson 整值加密 + purpose=ticket，§11.6.5）；拉码
	// 同步写快照键 al:ticket:payload（cache.TicketPayloadStore，§5.1 行 863），
	// 与 Thirdparty 侧读取共用同一实例；storage 解析走 internal/storage
	// Resolver（§15.1）；码图自动删除投递复用延迟队列（执行器挂
	// combinedExecutor，§13.3）；Confirm 会话校验复用共享单例
	// sessionTokens / epochStore（与 sso 拦截器同源）。挂入 assembled 供
	// registerSSO 注入 handler。
	deps.qrcode = service.NewQRCode(service.QRCodeDeps{
		Loader:         deps.providerLoader,
		NewAdapter:     provider.NewAdapter,
		Gate:           deps.gate,
		TicketCodec:    deps.codecs.Ticket,
		Tickets:        tickets,
		TicketPayloads: ticketPayloads,
		Storage:        storage.NewResolver(deps.providerLoader),
		Queue:          deps.queue,
		Sessions:       session.NewVerifier(deps.sessionTokens, deps.epochStore),
		State:          loginState,
		Terminal:       terminal,
	})

	// account 域三方绑定族 service（§12.6 / 接口文档 §3.7）：绑定内核
	// 两通道共用（redirect 解 al_login_state 用 codecs.Cookie；扫码轮询解
	// ticket 用 codecs.Ticket、结果读写与 thirdparty / qrcode 共用同一
	// cache.TicketStore 实例）；available 列表数据源复用 provider Loader（与
	// §2.7.1 登录快照同构）；解绑判定查 CredentialRepo；审计走 eventlog.Writer
	// 延迟队列（registerAdmin 同款链）。挂入 assembled 供 registerAccount
	// 注入 handler。
	deps.accountThirdparty = accountsvc.NewThirdpartyService(accountsvc.Deps{
		Loader:      deps.providerLoader,
		Providers:   repo.NewProviderRepo(deps.db),
		Binds:       repo.NewBindRepo(deps.db),
		Creds:       repo.NewCredentialRepo(deps.db),
		NewAdapter:  provider.NewAdapter,
		Tickets:     tickets,
		TicketCodec: deps.codecs.Ticket,
		CookieCodec: deps.codecs.Cookie,
		Audit:       eventlog.NewWriter(deps.queue),
	})

	// account 域通行密钥族 service（接口文档 §3.6 / 后端架构 §8.3
	// 行 1070-1075）：注册两态内核复用上方 webauthn 因子同一实例（同一
	// RPID / origins / 独立原子 token 密钥——login 域密钥 + AAD purpose
	// 隔离）；user_credential / user_credential_webauthn 读写注入两 repo；
	// webauthn_register 审计走 eventlog 延迟队列。**fail-closed 关键**：
	// wa 为 nil（启动初始化失败降级，上方 waErr 分支）时必须注入 nil 接口
	// 而非 nil *webauthn.Factor（typed-nil 会绕过 Factor==nil 判定），
	// service 四方法据此一律 method_disabled（§8.3 行 1071-1075）。
	var accountWebauthnFactor accountsvc.WebauthnFactor
	if wa != nil {
		accountWebauthnFactor = wa
	}
	deps.accountWebauthn = accountsvc.NewWebauthnService(accountsvc.WebauthnDeps{
		Factor:   accountWebauthnFactor,
		Webauthn: webauthnRepo,
		Creds:    creds,
		Audit:    eventlog.NewWriter(deps.queue),
	})

	// account 域五族 service 构造（接口文档 §3.2-§3.7）：四族
	// 单实例直挂 deps；换绑族双渠道各一实例（见 bindContactPair）。审计统一
	// 走 eventlog.Writer 延迟队列（accountThirdparty / accountWebauthn 同款
	// 链）；Now / Rand 缺省（time.Now / crypto/rand.Reader，service 构造内
	// 落回）。mfa 的 Rand 显式注入 crypto/rand.Reader（MfaDeps 字段语义，
	// 与缺省同值——留显式注入便于阅读）。
	deps.accountAvatar = accountsvc.NewAvatarService(accountsvc.AvatarDeps{
		Settings:  deps.settings,
		Providers: repo.NewProviderRepo(deps.db),
		Users:     users,
		// storage Resolver 与扫码域（deps.qrcode）同源同构造的装配
		// 惯例，presign / commit 共用 provider Loader 行缓存。
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
		Users:    users,
		Creds:    creds,
		Webauthn: webauthnRepo,
		Settings: deps.settings,
		Audit:    eventlog.NewWriter(deps.queue),
		Rand:     rand.Reader,
	})
	deps.accountEvents = accountsvc.NewEventsService(repo.NewEventLogRepo(deps.db))

	// 换绑族双渠道（§3.4）：两实例共用同一 OTP 单例（purpose=bind
	// 键空间与登录因子隔离，§10.1）/ captcha Gate / 限流 Config（与 factor/
	// otp 双注入同值，otpParamsFromSettings 启动期快照）——仅 Sender 分渠道
	//（BindCodeSender「装配方按渠道注入」）。
	bindContactBase := accountsvc.BindContactDeps{
		Users:  users,
		OTP:    otpSvc,
		Gate:   deps.gate,
		Config: otpCfg,
		Audit:  eventlog.NewWriter(deps.queue),
	}
	bindPhoneDeps := bindContactBase
	bindPhoneDeps.Sender = smsSender
	bindEmailDeps := bindContactBase
	bindEmailDeps.Sender = emailSender
	deps.accountBindContact = bindContactPair{
		phone: accountsvc.NewBindContactService(bindPhoneDeps),
		email: accountsvc.NewBindContactService(bindEmailDeps),
	}

	engine := orchestrator.NewEngine(orchestrator.EngineDeps{
		State:      loginState,
		Dispatcher: &orchestrator.Dispatcher{Registry: registry, Settings: deps.settings},
		// captcha Gate（§9.3 行 1110 唯一拦截点）：装配层构造
		// 真实 Gate；测试夹具未注入时为 nil，engine.go:209 对 nil 安全。
		Gate:     deps.gate,
		MFA:      mfa,
		Terminal: terminal,
		Failures: fails,
		// 引擎读计数键经与因子写入侧同源的 user_ref 解析器（见上方
		// pwUserRef 装配注释）。
		UserRef: pwUserRef,
		Factor: orchestrator.FactorDeps{
			Users:       users,
			Credentials: creds,
		},
		// set_password 步写入依赖（§7.4）：repo.UserRepo /
		// repo.CredentialRepo 天然满足窄接口；epoch 同步复用共享单例
		// EpochStore；审计经 resetAuditSink 走延迟队列；Thirdparty 三方
		// 免密建号（§12.5 行 1501）复用上方 deps.thirdparty。
		SetPass: &orchestrator.SetPassDeps{
			Users:       users,
			Credentials: creds,
			Epoch:       deps.epochStore,
			Audit:       resetAuditSink{logs: eventlog.NewWriter(deps.queue)},
			Settings:    deps.settings,
			Thirdparty:  deps.thirdparty,
		},
	})
	return engine, terminal, registry, nil
}

// resetAuditSink 把重置密码审计事件投递到延迟队列（docs/后端架构.md §7.4
// 行 1026「异步写审计」）：事件形态复用 eventlog 既有任务——
// EventResetPassword + DetailPwdEpoch（§4.6 行 770/799），实现
// orchestrator.ResetAuditSink（装配接线）。
type resetAuditSink struct {
	logs *eventlog.Writer
}

// RecordReset 非阻塞投递；队列满 / 关闭由 eventlog.Writer 静默降级（§5.2
// 行 893），不影响重置主链路。
func (s resetAuditSink) RecordReset(_ context.Context, uid int64, epoch int16, amr []string) {
	if s.logs == nil {
		return
	}
	s.logs.PushEvent(model.EventLog{
		Event:     eventlog.EventResetPassword,
		ActorType: eventlog.ActorTypeUser,
		ActorID:   uid,
		UserID:    uid,
		AMR:       strings.Join(amr, ","),
		Detail:    eventlog.DetailPwdEpoch(int64(epoch)),
		CreatedAt: time.Now(),
	})
}

// otpParamsFromSettings 验证码五参数启动期快照（接口文档 §5.6 行 1303-1311
// 为键名与默认值的唯一定义处）。core.Config 供因子 Judge 与表单渲染，
// cache.CodeOptions 供 cache.CodeStore 限流判定；零值各自回落默认（两处
// 默认值同源 §10.3，一致）。
func otpParamsFromSettings(st *settings.Store) (core.Config, cache.CodeOptions) {
	var cfg core.Config
	if st == nil {
		return cfg, cache.CodeOptions{}
	}
	if v, ok := st.GetInt64(settings.KeyOtpTtl); ok && v > 0 {
		cfg.TTL = time.Duration(v) * time.Second
	}
	if v, ok := st.GetInt64(settings.KeyOtpResendInterval); ok && v > 0 {
		cfg.Cooldown = time.Duration(v) * time.Second
	}
	if v, ok := st.GetInt64(settings.KeyOtpMaxAttempts); ok && v > 0 {
		cfg.MaxAttempts = int(v)
	}
	if v, ok := st.GetInt64(settings.KeyOtpDailyLimitTarget); ok && v > 0 {
		cfg.TargetDailyLimit = int(v)
	}
	if v, ok := st.GetInt64(settings.KeyOtpDailyLimitIP); ok && v > 0 {
		cfg.IPDailyLimit = int(v)
	}
	return cfg, cache.CodeOptions{
		TTL:              cfg.TTL,
		Cooldown:         cfg.Cooldown,
		TargetDailyLimit: cfg.TargetDailyLimit,
		IPDailyLimit:     cfg.IPDailyLimit,
		MaxAttempts:      cfg.MaxAttempts,
	}
}

// assemble 正常模式装配步骤 2-8（§3.1 行 237）：DB → 迁移检查（migrate up，
// 幂等——版本已最新时只读版本表秒过，§3.16 行 553-555：连上 DB 之后、
// settings 预热之前）→ Redis → 五把密钥 → settings 预热 + watcher → 队列
// worker 与事件日志 sink → factor 注册表 + Terminal + 登录单引擎。
// provider 注册表（步骤 6）与 cron 仍为 TODO。
// 任一步失败都先释放已建资源再原样上抛（serve 转 fail-fast）。
func assemble(ctx context.Context, cfg *config.Config) (*assembled, error) {
	db, err := repo.Open(cfg)
	if err != nil {
		return nil, err
	}
	if err := migrate.Up(ctx, cfg.DB.DSN); err != nil {
		closeSQLDB(db)
		return nil, err
	}
	rdb, err := cache.NewClient(ctx, cfg)
	if err != nil {
		closeSQLDB(db)
		return nil, err
	}

	deps := &assembled{db: db, rdb: rdb}

	// 步骤 5：五把 sign_key 逐把构造 KeyStore + Codec。
	if deps.codecs, err = buildCodecs(cfg); err != nil {
		deps.closeInfra()
		return nil, err
	}

	// 步骤 6（provider 半步，§3.1 行 237、§3.9 / §15.3 / §13.0）：
	// provider 加载链 = repo 行源 + Redis 整行缓存（版本失效）→ Loader
	//（本地 LRU + singleflight，TTL 60s）→ Whitelist（已启用 wechat_mp /
	// wechat_mp_scan 的 Ext.app_id 集合，供 origin Referer 白名单热更新）。
	// Loader 挂入 assembled，供后续 thirdparty 登录卡按 provider_key 取实例。
	// NewLoader 对 nil src panic（程序错误，等同 fail-fast）；rdb 此处必非 nil。
	// providerCache 同实例挂入 assembled（admin 写路径写后失效用）。
	deps.providerCache = cache.NewProviderCache(rdb)
	deps.providerLoader = provider.NewLoader(
		repo.NewProviderRepo(db), deps.providerCache, provider.LoaderOptions{})
	deps.providerWhitelist = provider.NewWhitelist(deps.providerLoader)

	// 步骤 7：settings 全量预热（缺失键补齐，fail-fast）→ watcher 订阅热更新。
	store := settings.NewStore(repo.NewSettingsRepo(db), rdb)
	if err := store.Preload(ctx); err != nil {
		deps.closeInfra()
		return nil, err
	}
	watcher := settings.NewWatcher(rdb, store)
	if err := watcher.Start(ctx); err != nil {
		deps.closeInfra()
		return nil, err
	}
	deps.settings = store
	deps.watcher = watcher

	// 步骤 7.5（captcha 链，§9）：Gate = settings 阈值 + catalog
	//（settings 键 → provider 表生效行，每次现算不缓存，§9.1 行 1094）
	// + verifier（image GETDEL 一次性 + 三家第三方 siteverify）。同一
	// CaptchaStore 同时供 verifier 的 image 校验与 CreateCaptchaImage 生成
	//（al:cap:{id} 单一键空间，§9.2）。provider 行源走 repo 直查（避免
	// 并行占用 provider 包，不引入 Loader）。catalog 提为共享单例
	//——Gate 与 registerPages 的 CSP supporter 复用同一实例（§9.4 行
	// 1134「CSP 贡献与下发配置、拦截校验同源」）。
	captchaStore := cache.NewCaptchaStore(rdb)
	captchaSrc := captchaProviderSource{providers: repo.NewProviderRepo(db)}
	deps.captchaCatalog = captcha.NewCatalog(store, captchaSrc)
	deps.gate = captcha.NewGate(store,
		deps.captchaCatalog,
		captcha.NewVerifier(captchaSrc, captchaStore, captcha.VerifierOptions{}))
	deps.imageCaptcha = captcha.NewImageCaptcha(captchaStore)

	// 步骤 8：延迟写入队列（§5.2）与登录事件 sink（§4.6）。队列执行器同时
	// 消费 event_log / last_login 与 webauthn sign_count（合并且取最大值）；
	// 增码图自动删除执行器（§13.3：消费 qrcode.DeleteTask，失败只
	// WARN，不影响登录）。
	users := repo.NewUserRepo(db)
	creds := repo.NewCredentialRepo(db)
	webauthnRepo := repo.NewWebauthnRepo(db)
	deps.queue = asyncqueue.New(combinedExecutor{
		&eventLogExecutor{logs: repo.NewEventLogRepo(db), users: users},
		webauthn.NewSignCountExecutor(webauthnRepo),
		// otp_sms / otp_email 的消息投递（SendJob，§15.2 行 1726），
		// 只消费 SendJob 任务，其余任务类型原样忽略。
		provider.SendExecutor{},
		// 码图自动删除（DeleteTask，§13.3）。
		qrcode.NewDeleteExecutor(storage.NewResolver(deps.providerLoader)),
	}, asyncqueue.DefaultOptions())
	deps.sink = service.NewLoginEventWriter(eventlog.NewWriter(deps.queue))

	// 微信服务端 access_token 跨实例共享缓存
	// （cache/wxacode，键 al:wxacode:*）注入 wechat_mp_scan 适配器——
	// Redis 就绪后、接受请求前一次完成；适配器按请求构造，读当前注入值。
	wechatmpscan.SetAccessTokenCache(cache.NewWxacodeStore(rdb))

	// 会话 / 令牌共享单例：sessionTokens / epochStore /
	// codeIssuer 各只构造一份，buildEngine（Terminal / SessionWriter）、
	// registerSSO（会话拦截器）与 OIDC token 端点复用同一实例——授权码
	// 复用 sign_key.ticket（票据族，purpose AAD 隔离，§11.6.1）。
	deps.sessionTokens = session.NewTokens(deps.codecs.Session)
	deps.epochStore = cache.NewEpochStore(deps.rdb, func(ctx context.Context, uid int64) (int64, error) {
		u, err := users.FindByID(ctx, uid)
		if err != nil {
			return 0, err
		}
		return int64(u.Epoch), nil
	})
	deps.codeIssuer = oidc.NewCodeIssuer(cache.NewOIDCCodeStore(deps.rdb), deps.codecs.Ticket)

	// 步骤 6（factor 半步）：factor 注册表（password / webauthn / totp /
	// recovery / otp_sms / otp_email，§3.8）+ Terminal + 单引擎（§7）。
	// pendingKinds 内的 thirdparty / device 尚无装配依赖，由
	// registry.AssertComplete 显式排除。注册表挂入 assembled，
	// 供页面壳 methods 快照按 login_methods 过滤读取（§2.1）。
	engine, _, registry, err := buildEngine(cfg, deps, users, creds, webauthnRepo)
	if err != nil {
		deps.close(context.Background())
		return nil, err
	}
	deps.engine = engine
	deps.factors = registry

	// 步骤 6（OIDC 半步，§14.3 行 1647）：启动期一次性解析 config.oidc.jwt_keys
	//（首项签发、全列表发 JWKS），iss = authloft.root 去尾 /（§14.1 行 1626）；
	// 非法 / 缺失 fail-fast（§3.2 约定 6），不生成临时密钥、不回退对称算法。
	if deps.oidcJWT, err = oidc.NewJWT(cfg.OIDC.JWTKeys, strings.TrimSuffix(cfg.Authloft.Root, "/")); err != nil {
		deps.close(context.Background())
		return nil, fmt.Errorf("bootstrap: oidc jwt keys: %w", err)
	}

	return deps, nil
}

// stopBackground 停止后台协程：先关 settings watcher，再优雅关闭队列
// （Queue.Close 内部先 flush 剩余任务、再等 worker 退出，§5.2 行 892）。
// 须在 http.Server.Shutdown 之前调用；重复调用安全。
func (a *assembled) stopBackground(ctx context.Context) {
	if a == nil {
		return
	}
	if a.watcher != nil {
		_ = a.watcher.Close()
		a.watcher = nil
	}
	if a.queue != nil {
		_ = a.queue.Close(ctx)
		a.queue = nil
	}
}

// closeInfra 关闭 DB / Redis 连接（后台协程须已由 stopBackground 停止）。
// nil 安全，供装配失败清理与优雅关闭复用。
func (a *assembled) closeInfra() {
	if a == nil {
		return
	}
	if a.db != nil {
		closeSQLDB(a.db)
		a.db = nil
	}
	if a.rdb != nil {
		_ = a.rdb.Close()
		a.rdb = nil
	}
}

// close 后台协程 + 基础设施的完整释放（装配失败清理与测试用）；HTTP
// Shutdown 需夹在两者之间，由 serve 直接分两步调用。
func (a *assembled) close(ctx context.Context) {
	a.stopBackground(ctx)
	a.closeInfra()
}

// closeSQLDB 关闭 GORM 底层 *sql.DB（取不到时静默跳过）。
func closeSQLDB(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// serve 正常模式装配链（§3.1 行 237）：config（run 已加载）→ DB → migrate
// up → Redis → 密钥 → provider/factor 注册表 → settings 预热 → 队列
// worker → cron → router → http.Server。启动期链路已由 assemble 完成；
// 本函数负责监听与优雅关闭：signal（SIGINT/SIGTERM）→ 停 watcher / 队列
// （先 flush 再停 worker）→ http.Server.Shutdown（超时 10s）→ 关 DB / Redis。
func serve(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	deps, err := assemble(ctx, cfg)
	if err != nil {
		return err
	}

	// provider 注册表已由 assemble 构造、适配器自注册经顶部 `_ import`
	// 触发（§3.1 行 237）；factor 注册表在 assemble 内构造。
	// TODO(cron)：定时清理任务包尚未落地（§3.12 行 457），随 cron 卡接入。

	handler, _ := buildRouterWithSSO(cfg, deps)
	srv, err := newHTTPServer(cfg, handler)
	if err != nil {
		deps.close(context.Background())
		return err
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
		return err
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
			return err
		}
		return nil
	}
}

// listenAndServe 按 server 段 TLS 配置选择监听模式（§3.1 行 244）：已配
// cert+key → 同端口 HTTP/1.1(TLS) + H2(TLS)（证书路径经 Validate 已校验
// 可读）；未配 → 明文 HTTP/1.1 + H2C。
func listenAndServe(cfg *config.Config, srv *http.Server) error {
	if cfg.Server.TLSEnabled() {
		return srv.ListenAndServeTLS(cfg.Server.CertFile, cfg.Server.KeyFile)
	}
	return srv.ListenAndServe()
}

// setupMode 判定首次启动（§3.1 行 253 / §3.15）：configs/config.yaml
// 不存在即 setup 模式。纯文件存在性判定，不含其他启发式。
func setupMode(configPath string) bool {
	_, err := os.Stat(configPath)
	return errors.Is(err, fs.ErrNotExist)
}

// buildRouter 从 *config.Config 构造生产顶层 handler（§3.2 约定 1：构造注入，
// 测试可传自造实例，§20）。rootOrigin 取 authloft.root（{al_root}，接口文档
// §1.1 行 76）；无 deps 时仅组链（测试口径），正常模式走 buildRouterWithSSO
// 注册域 handler（sso 域挂 session 拦截器，admin / rpc HMAC 拦截器随各自域
// handler 注册注入）。setup 路由不在本链注册——仅 setup 模式的独立链路
//（§3.15），正常模式下 /setup 与 /api.setup/** 一律 404（§13）。
func buildRouter(cfg *config.Config) (http.Handler, *gin.RouterGroup) {
	return buildHandler(cfg, connect.NewServer(defaultReadMaxBytes))
}

// buildRouterWithSSO 正常模式装配入口：与 buildRouter 同链，额外注入
// 登录单引擎并把 SsoService Connect handler 挂入顶层 ServeMux 前缀（§3.1
// 行 243）。保留 buildRouter 无依赖形态供测试自造 handler。
func buildRouterWithSSO(cfg *config.Config, deps *assembled) (http.Handler, *gin.RouterGroup) {
	return buildHandlerWithSSO(cfg, connect.NewServer(defaultReadMaxBytes), deps)
}

// buildHandler 顶层分流组装（§3.1 行 243：标准库 http.ServeMux）：
//   - Connect 各路由按路径前缀挂 mux——前缀链与 gin 全局链等效（§3.3
//     行 304 挂载顺序，recover 由 connect-go WithRecover 在 handler 内
//     等效、不进本链）：http 版 requestid（X-Request-Id 全响应回写）→
//     logger（访问日志）→ metrics（defer 累加，Connect 域流量同样计入
//     /metrics）→ origin（跨站 403）→ handler；中间件两版与 gin 版共用
//     同一实现（middleware/httpmw.go——requestid/origin 共用纯函数、
//     logger 共用 logAccess、metrics 共用同一组包级原子变量）；
//   - 其余全部 mux.Handle("/", ginEngine)：页面 / 静态 / OIDC / gateway /
//     未注册路径（含未注册的 connect 形态路径）→ gin 原生 404 兜底
//     （不再经 gin.NoRoute 桥，404 残留缺陷结构性消除）；
//   - 该分流链上禁挂 gzip / body-capture 类中间件（§3.1 行 246，破坏
//     h2c / 流式语义）。
//
// deps 为空时仅做无域 handler 的链路组装（测试口径）；非空时注册已装配的
// SsoService handler。
func buildHandler(cfg *config.Config, csrv *connect.Server) (http.Handler, *gin.RouterGroup) {
	return buildHandlerWithSSO(cfg, csrv, nil)
}

// buildHandlerWithSSO 在 buildHandler 基础上挂已装配的域 handler，同步接入
// provider 白名单动态来源与 OIDC REST 路由。
func buildHandlerWithSSO(cfg *config.Config, csrv *connect.Server, deps *assembled) (http.Handler, *gin.RouterGroup) {
	// Referer 白名单动态来源（§13.0 行 1570）：
	// 已启用 wechat_mp / wechat_mp_scan provider 的 Ext.app_id 集合，由
	// Whitelist 查询并随 provider 变更热更新（60s 缓存 + al:prov:ver 版本
	// 失效）。查询失败归一为 nil = 空表 → 保守 403（§13.0 行 1569
	//「Referer 校验按失败处理」+ origin.go 空表恒 false 口径）；Whitelist
	// 内部已有「版本读取失败且有未过期缓存则降级用旧值」的一级降级。
	// deps == nil（测试口径）→ 来源为 nil，等效空表。
	var refererAllowlist middleware.AllowlistFunc
	if deps != nil && deps.providerWhitelist != nil {
		refererAllowlist = func(ctx context.Context) []string {
			ids, err := deps.providerWhitelist.AppIDs(ctx)
			if err != nil {
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
		// OIDC REST 端点（§4.1）：注册在 gin 链（/.well-known/** 与 /api/oidc/**
		// 按绝对路径），不经 Connect、不套 §1.0 信封（§1.0 豁免清单）；
		// origin 对 /api/oidc/** 免检（接口文档 §1.1 行 79 例外），GET 端点
		// 为安全方法不受校验。
		registerOIDC(ginEngine, deps)
		// 网关 decode（§6）：挂 /api 组的 /gateway 子组 + Gateway 中间件
		//（REST 豁免域）。
		registerGateway(apiGroup, deps)
		// 页面壳路由族（接口文档 §8 行 1414-1439 + §2.9）：三端
		// SPA 空壳 + /sso/logout + /sso/sync_cookie 中转，全部挂 gin 链。
		registerPages(ginEngine, cfg, deps)
	}

	mux := http.NewServeMux()
	mux.Handle("/", ginEngine)
	// 静态资源 /assets/**：无鉴权恒在（CDN 回源与内网直连，
	// §3.13），挂 mux 子树与 gin 链平级——不经 Connect/中间件链。
	assets.Register(mux)
	for _, rt := range csrv.Routes() {
		mux.Handle(rt.Prefix, middleware.HTTPRequestID(
			middleware.HTTPLogger(
				middleware.HTTPMetrics(
					// Connect 前缀链 origin 用动态白名单形态（与 gin 版同一
					// 判定核心；静态 HTTPOrigin 保留兼容存量调用方）。
					middleware.HTTPOriginFunc(cfg.Authloft.Root, refererAllowlist, connectRequestInfo(rt.Handler)),
				),
			),
		))
	}
	return mux, apiGroup
}

// connectRequestInfo 给 connect 前缀链注入请求侧信息：http 挂载层
// 是唯一能同时拿到 RemoteAddr 与头信息的层（connect 链 AnyRequest 只暴露
// Header——session.RequestSignal 只采头、拿不到来源 IP 的先例），登录成功
// 事件经 ctx 带到 orchestrator.Terminal.Complete，落 event_log.ip / ua
//（§4.6 行 776-777）。所有 connect 域统一注入，消费点只有登录终点。
func connectRequestInfo(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(orchestrator.WithRequestInfo(r.Context(), orchestrator.RequestInfo{
			IP: clientIPFromRequest(r),
			UA: r.UserAgent(),
		})))
	})
}

// clientIPFromRequest 来源 IP（审计用途 event_log.ip，非安全判定依据）：
// 反代链优先 X-Forwarded-For 首段，次选 X-Real-IP，直连回落 RemoteAddr
// host 段。直连场景客户端可伪造 XFF / X-Real-IP，如实记录——部署方负责
// 在反代清洗入站头（§1.1 明文部署风险自负的同款口径）。
func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		return strings.TrimSpace(xff)
	}
	if rip := strings.TrimSpace(r.Header.Get("X-Real-IP")); rip != "" {
		return rip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// ssoSessionTTL session_ttl 键缺失 / 非法时的回落值（接口文档 §1.9、§5.6：
// 默认 7 天）。
const ssoSessionTTL int64 = 604800

// newDomainSessionInterceptor 构造域级 session 拦截器（§3.14 行 494）：
// 会话 Tokens / EpochStore 复用 assemble 构造的共享单例（与 buildEngine
// 同源）。sso 域（LoginDefault 免鉴权、匿名放行）与
// account 域（§1.2 行 96：全接口需 al_session，无会话由 handler 判定 401）
// 共用同一构造，不再各写一份。
func newDomainSessionInterceptor(cfg *config.Config, deps *assembled) connectrpc.UnaryInterceptorFunc {
	return connect.NewSessionInterceptor(
		session.NewVerifier(deps.sessionTokens, deps.epochStore),
		session.NewRenewer(deps.sessionTokens, ssoSessionTTLRaw(deps.settings)),
		newSessionCookie(cfg, deps),
		ssoCookieName(deps),
	)
}

// ssoCookieName 会话 Cookie 名动态源（settings 键 cookie_name 每请求读取，
// 缺失回落空串由 session.NewCookie 落回默认 al_session）。
func ssoCookieName(deps *assembled) func() string {
	return func() string {
		v, _ := deps.settings.GetString(settings.KeyCookieName)
		return v
	}
}

// ssoHTTPSMode https_deployment 三态动态源（§1.9 行 299-310：键
// 缺失回落空串、判定侧按 auto 缺省——与 ssoCookieName 同款每请求读取，
// 沿 cookie_name 热更口径，禁止进程内缓存死值）。喂 session.Cookie 与
// thirdparty（al_login_state）——全部 Cookie 下发点同一三态源，随
// al:settings:chg watcher 热更对后续请求生效。
func ssoHTTPSMode(deps *assembled) func() string {
	return func() string {
		v, _ := deps.settings.GetString(settings.KeyHttpsDeployment)
		return v
	}
}

// newSessionCookie 构造会话 Cookie 属性构造器（§1.9 行 288）：名 / 根域 /
// TTL 同源于 settings（cookie_name、authloft.root 根域、session_ttl）；
// Secure/SameSite 三态源同注入（https_deployment：HTTPS 判定 →
// Secure; SameSite=None；明文 → 省略 Secure、SameSite=Lax；auto 按请求
// 信号推断）。session 拦截器（续期下发）与 sso 登录终点（建会话
// Set-Cookie 下发）共用本构造——同名同属性，不另造第二套。
func newSessionCookie(cfg *config.Config, deps *assembled) *session.Cookie {
	return session.NewCookie(ssoCookieName(deps)(), rootHost(cfg.Authloft.Root),
		ssoSessionTTLRaw(deps.settings), session.WithHTTPSMode(ssoHTTPSMode(deps)))
}

// registerSSO 注册 SsoService Connect handler：挂 session 拦截器
// （§3.14 行 473；LoginDefault 免鉴权，未登录请求由拦截器放行匿名），
// 其余域拦截器 / 错误包装由 connect.Server.HandlerOptions 统一补齐。
// 注入会话 Cookie 属性构造器：LoginDefault / Register / ResetPassword
// 终点建会话后经引擎写点下发 Set-Cookie: al_session（§1.9 行 288）。
// 注入三方登录通道 service：Authorize / LoginOauth（§2.7.2 / §2.7.4），
// al_login_state 的 Set-Cookie 与浏览器终点 al_session 共用 CallInfo 写头。
func registerSSO(cfg *config.Config, csrv *connect.Server, deps *assembled) {
	path, h := ssov1connect.NewSsoServiceHandler(
		// 注入扫码三桩 service（CreateQrcode / GetLoginTicket /
		// ConfirmLoginTicket，§2.8）：GetLoginTicket 命中建会话后的
		// al_session 与登录终点同一写出出口。
		ssohandler.New(deps.engine, deps.imageCaptcha, newSessionCookie(cfg, deps), deps.thirdparty, deps.qrcode),
		csrv.HandlerOptions(newDomainSessionInterceptor(cfg, deps))...,
	)
	csrv.Register(path, h)
}

// registerAccount 注册 AccountService Connect handler（GetProfile /
// GetConfig + 三方绑定族四方法 + 通行密钥族四方法）：挂同一 session 拦截器
// （§1.2 行 96：/api.account.v1.AccountService/** 全接口需用户会话，无 LoginDefault
// 式豁免——无有效会话请求由 handler 返回 unauthenticated）。GetConfig 依赖：
// CredentialRepo（hasPassword / mfaPolicy）、settings.Store（mfa_enabled /
// avatar_storage_provider）、ProviderRepo（storage 行）、captcha Gate
// （§9.1 行 1094 三处共用出口现算，降级一致）。三方绑定族
// （GetThirdpartyBindings / UnbindThirdparty / ThirdpartyOauth /
// GetThirdpartyTicket，接口文档 §3.7 / §3.7.1）走 service/account.
// ThirdpartyService；通行密钥族（GetWebauthnCredentials /
// RegisterWebauthn 两态 / RenameWebauthnCredential /
// DeleteWebauthnCredential，接口文档 §3.6）走 service/account.
// WebauthnService（均 buildEngine 内构造的共享单例）；UpdateProfile
//（接口文档 §3.2 行 837）走 service/account.ProfileService——单依赖
// UserRepo，无跨 service 共享需求，本函数内就地构造（UserRepo 本就地
// new，同款口径）。五族 service（avatar / password / bindcontact /
// mfa / events，接口文档 §3.2-§3.7）经 NewWithServices 注入——buildEngine
// 内构造的共享单例（bindcontact 为双渠道组合 bindContactPair）；cookies
// 注入 newSessionCookie（ChangePassword 清 al_session 用，与 session 拦截
// 器 / sso 登录终点同一构造器）。
func registerAccount(cfg *config.Config, csrv *connect.Server, deps *assembled) {
	path, h := accountv1connect.NewAccountServiceHandler(
		accounthandler.NewWithServices(
			repo.NewUserRepo(deps.db),
			repo.NewCredentialRepo(deps.db),
			deps.settings,
			repo.NewProviderRepo(deps.db),
			deps.gate,
			deps.accountThirdparty,
			deps.accountWebauthn,
			accountsvc.NewProfileService(repo.NewUserRepo(deps.db)),
			deps.accountAvatar,
			deps.accountPassword,
			deps.accountBindContact,
			deps.accountMfa,
			deps.accountEvents,
			newSessionCookie(cfg, deps),
		),
		csrv.HandlerOptions(newDomainSessionInterceptor(cfg, deps))...,
	)
	csrv.Register(path, h)
}

// bindContactPair 换绑族双渠道 ContactBinder 组合（§3.4）：BindPhone
// / BindEmail 各持各自渠道的 BindContactService 实例（buildEngine 构造——
// 依赖全同，仅 Sender 按 sms / email 渠道分注，BindCodeSender「装配
// 方按渠道注入」的落地）；handler 侧 ContactBinder 单注入位由此适配。
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

// registerAdmin 注册 AdminService Connect handler（读路径 + 写族
// + 用户管理族 + 客户端管理族 + 系统配置 / 事件 / 工具族）：
// session 拦截器在外（注入会话身份），connect.NewAdminInterceptor 在内
// （uid==1 判定，接口文档 §5 行 1145-1146：无会话 401 / 非管理员 404 掩护），
// 错误包装由 connect.Server.HandlerOptions 统一补最内层。读路径
// （ListProviders / GetProvider / GetProviderSchema——详情为全站唯一明文凭证
// 出口，访问日志不打印 body）直连 ProviderRepo；写族 7 方法走
// service/admin/provider.go；用户管理族 8 方法走 service/admin/user.go（业务
// 校验 + IncEpoch/al:pwdep 失效链 + 审计投递 + Union 连带 + 解锁键清除，
// §18 行 1792 分层）——epoch 同步复用共享单例 deps.epochStore，审计经
// eventlog.Writer 走 deps.queue（resetAuditSink 同款链）；解锁用的 PwFailStore
// 就地构造（BanTTL 仅影响 Ban 写路径，删除 / SCAN 不受其影响）；客户端管理族
// 10 方法走 service/admin/client.go（secret 服务端生成、client_id 生成/不可改、
// redirect_uris 校验、OIDC scopes/TTL 值域，§5.5）；settings/事件/工具族
// 5 方法走 service/admin/settings.go（GetSettings/SetSettings 经共享单例
// deps.settings——SetMany 落库 + PUBLISH 热更；ListEvents 走 EventLogRepo.List；
// DecodeToken 用 deps.codecs 三场景独立编解码器（§1.4，cookie 装配位已备）；
// GetStatus 读 deps.queue 三指标；审计同走 eventlog.Writer → deps.queue），
// 33 方法全部实装。
func registerAdmin(cfg *config.Config, csrv *connect.Server, deps *assembled) {
	providers := repo.NewProviderRepo(deps.db)
	clients := repo.NewClientRepo(deps.db)
	path, h := adminv1connect.NewAdminServiceHandler(
		adminhandler.New(
			providers,
			adminsvc.NewService(providers, deps.providerCache),
			adminsvc.NewUserService(
				repo.NewUserRepo(deps.db),
				repo.NewCredentialRepo(deps.db),
				repo.NewBindRepo(deps.db),
				providers,
				repo.NewEventLogRepo(deps.db),
				deps.epochStore,
				cache.NewPwFailStore(deps.rdb, cache.PwFailOptions{}),
				eventlog.NewWriter(deps.queue),
				deps.settings,
			),
			adminsvc.NewClientService(clients),
			adminsvc.NewSettingsService(
				deps.settings,
				repo.NewEventLogRepo(deps.db),
				eventlog.NewWriter(deps.queue),
				adminsvc.TokenCodecs{
					Session: deps.codecs.Session,
					Login:   deps.codecs.Login,
					Cookie:  deps.codecs.Cookie,
				},
				deps.queue,
			),
		),
		csrv.HandlerOptions(newDomainSessionInterceptor(cfg, deps), connect.NewAdminInterceptor())...,
	)
	csrv.Register(path, h)
}

// registerRPC 注册 rpc 域两个 Connect handler（接口文档 §7 行
// 1366-1393）：鉴权 = rpc HMAC 拦截器（三头齐全 → 写接口 nonce 去重 →
// client 查询 → 五项签名，§7 行 1383 校验顺序；session 步归端点自身，
// 不挂 session 拦截器）。两个 service 一律经 csrv.RegisterRPC 注册——强制
// 包 CaptureRawBody（拦截器读 ctx 原始请求体字节，漏挂按 internal
// fail-closed，connect/server.go 行 91 口径）。Verifier / Renewer 复用
// assemble 共享单例（sessionTokens / epochStore，口径不新造第二套）；
// TTL 与会话拦截器同源（settings 键 session_ttl，缺失回落 7 天）。
func registerRPC(cfg *config.Config, csrv *connect.Server, deps *assembled) {
	// SecretLookup（§7 行 1376：X-Client-ID → sso_client.client_secret）：
	// 未命中 / 已禁用（is_enabled=0）/ 查询失败统一 ok=false——与签名错误
	// 同响应 403，不区分以防探测（拦截器既有口径，interceptors.go 行
	// 298-301）；禁用判定对齐 oidc findClient 先例（oidc/token.go 行
	// 243-254）。SecretLookup 签名无错误通道，查询故障只能并入未注册口径。
	clients := repo.NewClientRepo(deps.db)
	lookup := func(ctx context.Context, clientID string) (string, bool) {
		c, err := clients.FindSsoClientByClientID(ctx, clientID)
		if err != nil || c == nil || c.IsEnabled == 0 {
			return "", false
		}
		return c.ClientSecret, true
	}
	hmac := connect.NewRPCHMACInterceptor(cache.NewNonceStore(deps.rdb), lookup)

	// rpc 域两 service 共享同一 UserRepo 实例（GetUserProfiles 批量读
	// 与 DecodeSession include_user_info 单读走同一数据面，不重复构造）。
	users := repo.NewUserRepo(deps.db)
	path, h := rpcv1connect.NewUserServiceHandler(
		rpchandler.NewUserHandler(users),
		csrv.HandlerOptions(hmac)...,
	)
	csrv.RegisterRPC(path, h)

	path, h = rpcv1connect.NewTokenServiceHandler(
		rpchandler.NewTokenHandler(
			session.NewVerifier(deps.sessionTokens, deps.epochStore),
			session.NewRenewer(deps.sessionTokens, ssoSessionTTLRaw(deps.settings)),
			users,
		),
		csrv.HandlerOptions(hmac)...,
	)
	csrv.RegisterRPC(path, h)
}

// registerOIDC 注册 OIDC REST 端点到 gin 链（接口文档 §4.1 行
// 1049-1057）：token / revoke / userinfo / get_user_info + discovery / JWKS，
// 不经 Connect、不套 §1.0 信封（§1.0 行 65 豁免）。五件套全部由装配产物
// 注入——JWT 复用 assemble 构造的 RS256 密钥集（iss = authloft.root）、
// Codes 复用 Terminal 同一 CodeIssuer（§14.2 行 1639「两条路径共用同一
// 注入的 OIDCCodeIssuer，不得各写一份」）、Epoch 复用会话校验同一 epoch
// 源，均不构造第二份；Clients / Tokens / Users / Profiles 为 repo 无状态
// wrapper，按端点就近构造。
func registerOIDC(r gin.IRouter, deps *assembled) {
	clients := repo.NewClientRepo(deps.db)
	refreshTokens := repo.NewOidcTokenRepo(deps.db)
	users := repo.NewUserRepo(deps.db)
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

// registerGateway 注册网关域唯一端点 `ANY /api/gateway/decode`（接口文档 §6、
// 后端架构 §17 行 1768 / §3.3 行 314）：/api 组（REST 豁免
// 端点组，router.go）上挂 /gateway 子组，Gateway 中间件先于 handler
// （X-Gateway-Token 无效 403 空体归中间件，§1.5 行 188）；decode 恒 200
// 纯响应头无响应体（§1.0 行 66）。tokens 动态源 = settings 键
// gateway_tokens 每请求快照读取（§5.6 行 1338，默认 []，热更对后续请求
// 生效——口径同 Referer 白名单动态源）；Verifier 复用 assemble
// 共享单例（sessionTokens / epochStore，§11.1 四步不新造第二套）；Cookie
// 名口径同 session 拦截器（settings 键 cookie_name 每请求读取，缺失回落
// al_session 由 handler 兜底）。
func registerGateway(api gin.IRouter, deps *assembled) {
	gw := api.Group("/gateway")
	gw.Use(middleware.Gateway(gatewayTokensSource(deps.settings)))
	gatewayhandler.Register(gw, gatewayhandler.Deps{
		Verify: session.NewVerifier(deps.sessionTokens, deps.epochStore),
		CookieName: func() string {
			v, _ := deps.settings.GetString(settings.KeyCookieName)
			return v
		},
	})
}

// gatewayTokensSource gateway_tokens 动态源：每请求经 settings 快照读取
// （§5.6 行 1338，Store 写方立即生效 / 跨实例经 watcher 热更生效）。
// settings 为 nil（未装配）时返回 nil func——middleware.Gateway 按
// 「缺配置保守拒绝」口径处理（gateway.go 行 25-26）。
func gatewayTokensSource(st *settings.Store) func() []string {
	if st == nil {
		return nil
	}
	return func() []string {
		v, _ := st.GetStringSlice(settings.KeyGatewayTokens)
		return v
	}
}

// ssoSessionTTLRaw 读取 session_ttl（接口文档 §1.9 / §5.6）。
func ssoSessionTTLRaw(st *settings.Store) time.Duration {
	if st != nil {
		if v, ok := st.GetInt64(settings.KeySessionTtl); ok && v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return time.Duration(ssoSessionTTL) * time.Second
}

// registerPages 注册页面壳路由族（接口文档 §8 行 1414-1439 +
// §2.9，增挂 §4.2 /auth/authorize）：/sso/login、/sso/register、
// /sso/reset、/sso/oauth/callback/{provider_key}（login entry 空壳）、
// /account/**、/admin/**（account / admin entry 空壳）、/sso/logout
// （清 Cookie + 多域同步 + 白名单回跳）、/sso/sync_cookie（多域同步中转
// 接收端）、/auth/authorize（OIDC 授权入口：校验矩阵 + 有会话 302 签码 +
// 无会话渲染登录空壳注入 __AUTHLOFT_INIT__.oidc）。挂 gin 链（§8 Go 渲染
// 页面路由），GET 安全方法不受 origin 校验；路由组挂 middleware.CSP()
// （§3.3 行 314 csp.go 条目接线——中间件已测未接）：每请求
// nonce 写 ctx（renderShell 消费）+ 输出基线 CSP 头（不破坏前端加载）；
// 阶段 C 起 CSP() 挂 pages.StaticBaseCSPSupporter——static_base 为 CDN
// 绝对地址时每请求向 script / style / font 三条资源类指令追加 CDN 源
// （§3.13 行 488；script-src CDN 源仅为 CSP2 回退）；追加第二个
// supporter = deps.captchaCatalog（§9.4 provider 贡献源：按「当前启用
// 且已配置」的 captcha Provider 贡献 frame/connect/style 源，与 Gate
// 下发配置同实例同源；中间件按指令名聚合去重单条输出，未启用零写入）。
// 依赖全部复用
// assemble 共享单例：settings / provider Loader / factor
// 注册表 / captcha Gate / sync_payload Codec / OIDC JWT / ClientRepo；
// 登出同步首跳构造复用 service.SyncCookieURLBuilder（与登录终点 Terminal
// 同一实现，§11.2 发起端）。authorize 侧：会话校验复用
// sessionTokens / epochStore 共享单例（与 sso 拦截器同源）、签发复用
// deps.codeIssuer（与 Terminal 共用同一实例，§14.2 行 1642 不得各写
// 一份）、审计走 eventlog.Writer → deps.queue（resetAuditSink 同款链）。
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
		Sync:       service.NewSyncCookieURLBuilder(deps.codecs.SyncPayload),
		Codec:      deps.codecs.SyncPayload,
		JWT:        deps.oidcJWT,
		Clients:    repo.NewClientRepo(deps.db),
		Sessions:   session.NewVerifier(deps.sessionTokens, deps.epochStore),
		Codes:      deps.codeIssuer,
		Audit:      eventlog.NewWriter(deps.queue),
	})
}

// rootHost 从 authloft.root（{al_root}，完整 URL）取根域，供会话 Cookie 的
// Domain 属性（§11.1 行 1165）。非法 / 空值回落空串（Cookie 按主机名限定）。
func rootHost(root string) string {
	u, err := url.Parse(root)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// newHTTPServer 从 *config.Config 构造 http.Server：监听地址与协议
// （Protocols / TLSConfig，Go 1.26 标准库原生 http.Server.Protocols——
// h2c 或 TLS 双模式，§3.1 行 244-245）取自 server 段，经
// ServerConfig.ConfigureHTTPServer 映射（与 setup 同口径，§3.15）；
// min_tls_version 非法取值在此 fail-fast（正常路径已在 config.Validate
// 拦截，防测试自造实例绕过）。
func newHTTPServer(cfg *config.Config, handler http.Handler) (*http.Server, error) {
	srv := &http.Server{Handler: handler}
	if err := cfg.Server.ConfigureHTTPServer(srv); err != nil {
		return nil, err
	}
	return srv, nil
}
