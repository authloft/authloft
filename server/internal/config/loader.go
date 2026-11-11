package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrNotExist 配置文件不存在（§3.1 启动分支判据 / §3.15 setup 模式）：
// Load 不再自动生成写回（已移除首启路径——sign_key 只在安装流程 §3.15
// 中生成），bootstrap 用 errors.Is 判定后转 setup 模式。链到 fs.ErrNotExist
// （包内 ReadFile 的原始判定语义保持可判）。
var ErrNotExist = fmt.Errorf("config: file does not exist: %w", fs.ErrNotExist)

// Load 读取 YAML 启动配置（docs/后端架构.md §3.2 职责表）：
//
//  1. 文件存在：解析 → 应用环境变量覆盖（环境变量优先）→ Validate；
//     任一步失败即返回 error，fail-fast，不提供运行期兜底默认值；
//  2. 文件不存在：返回包装 ErrNotExist 的错误（§3.15 安装决策：缺文件即
//     首次启动，由 bootstrap 转 setup 模式，不在此生成）；
//  3. 其他读错误（权限等）原样返回。
//
// 错误信息不回显密钥——env / Validate 的报错只含字段路径与原因（§3.2 约定 3）。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parseAndValidate(data)
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("config: %s: %w", path, ErrNotExist)
	default:
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
}

// parseAndValidate 文件存在路径：解析 → env 覆盖 → Validate，三步全在启动期一次完成。
func parseAndValidate(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	if err := applyEnvOverrides(&c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: invalid: %w", err)
	}
	return &c, nil
}

// DefaultConfig 构造全量默认值结构（与 authloft.yml.example 同源），
// sign_key 七场景现场随机生成（crypto/rand 32 字节 → std base64，kid=1，
// 互不复用），oidc.jwt_keys 现场生成一把 RSA 2048（PKCS#8 PEM → std base64，
// kid="1"）。供安装流程消费（§3.15 writer.go：全新安装生成完整 config；
// §3.2 约定 4 / 约定 6——密钥只在安装流程中生成，loader 不再自动生成写回）。
func DefaultConfig() (*Config, error) {
	c := Config{
		Server: ServerConfig{
			Listen:        ":8080",
			MinTLSVersion: "",
			CertFile:      "",
			KeyFile:       "",
		},
		DB: DBConfig{
			DSN:             "authloft:pass@tcp(127.0.0.1:3306)/authloft?charset=utf8mb4&parseTime=true&loc=Local",
			MaxOpenConns:    50,
			MaxIdleConns:    10,
			ConnMaxLifetime: Duration{time.Hour},
		},
		Redis: RedisConfig{
			Addr:     "127.0.0.1:6379",
			Password: "",
			DB:       0,
			PoolSize: 50,
		},
		Authloft: AuthloftConfig{
			Root:          "https://authloft.example.com",
			RpID:          "authloft.example.com",
			RPDisplayName: DefaultRPDisplayName,
		},
		Argon2: Argon2Config{Time: 3, Memory: 65536, Threads: 4, KeyLen: 32},
		Log:    LogConfig{Level: "info", Format: "text"},
	}
	for _, km := range []*KeyMaterial{
		&c.SignKey.Session,
		&c.SignKey.Login,
		&c.SignKey.Ticket,
		&c.SignKey.Cookie,
		&c.SignKey.SyncPayload,
		&c.SignKey.Challenge,
		&c.SignKey.Verification,
	} {
		k, err := generateKeyMaterial()
		if err != nil {
			return nil, err
		}
		*km = k
	}
	oidcKey, err := generateOIDCKey()
	if err != nil {
		return nil, err
	}
	c.OIDC.JWTKeys = []OIDCKey{oidcKey}
	return &c, nil
}

// generateKeyMaterial 生成单场景密钥：crypto/rand 32 字节 → std base64，kid=1
// （§3.2 约定 4；多 kid 轮换由部署方改配置实现，生成期固定 kid=1）。
func generateKeyMaterial() (KeyMaterial, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return KeyMaterial{}, fmt.Errorf("crypto/rand: %w", err)
	}
	return KeyMaterial{Key: base64.StdEncoding.EncodeToString(buf), Kid: 1}, nil
}

// generateOIDCKey 生成一把 OIDC RS256 签名密钥（§3.2 约定 6 / §3.15）：
// RSA 2048 → PKCS#8 → PEM → std base64，kid 固定 "1"（每套安装一把）。
// 私钥只落盘到 config，调用方不得打印（§3.2 约定 3）。
func generateOIDCKey() (OIDCKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return OIDCKey{}, fmt.Errorf("config: generate OIDC RSA key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return OIDCKey{}, fmt.Errorf("config: marshal OIDC PKCS#8 key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if pemBytes == nil {
		return OIDCKey{}, errors.New("config: encode OIDC PEM")
	}
	return OIDCKey{Kid: "1", PrivateKeyPEM: base64.StdEncoding.EncodeToString(pemBytes)}, nil
}

// envBinding 一条环境变量 → 字段的绑定。
type envBinding struct {
	key string
	set func(*Config, string) error
}

// setDuration / setInt 把字符串 env 值解析为对应类型（非法即 fail-fast）；
// 字符串字段直接赋值不设 wrapper。
func setDuration(set func(*Config, Duration)) func(*Config, string) error {
	return func(c *Config, v string) error {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		set(c, Duration{d})
		return nil
	}
}

func setInt(set func(*Config, int)) func(*Config, string) error {
	return func(c *Config, v string) error {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid integer: %w", err)
		}
		set(c, n)
		return nil
	}
}

// serverEnvBindings server 段的 env 覆盖（既定全字段显式表的 server 部分，
// §3.2 约定 5：AUTHLOFT_SERVER_LISTEN / MIN_TLS_VERSION / CERT_FILE /
// KEY_FILE 四条）。独立成表供 DefaultServerConfig（setup 模式只读 server 段，
// §3.15）与全量 envBindings 共用，避免两处维护。
var serverEnvBindings = []envBinding{
	{"AUTHLOFT_SERVER_LISTEN", func(c *Config, v string) error { c.Server.Listen = v; return nil }},
	{"AUTHLOFT_SERVER_MIN_TLS_VERSION", func(c *Config, v string) error { c.Server.MinTLSVersion = v; return nil }},
	{"AUTHLOFT_SERVER_CERT_FILE", func(c *Config, v string) error { c.Server.CertFile = v; return nil }},
	{"AUTHLOFT_SERVER_KEY_FILE", func(c *Config, v string) error { c.Server.KeyFile = v; return nil }},
}

// envBindings 环境变量覆盖表：AUTHLOFT_<SECTION>_<FIELD>（大写下划线），由文档
// 明写的 AUTHLOFT_DB_DSN、AUTHLOFT_REDIS_ADDR（§3.2 职责表）按同模式推导为
// 全字段口径（含 sign_key 十四字段与 AUTHLOFT_AUTHLOFT_* 双前缀）。显式表而非反射：
// 无运行时魔法、逐条可测。未知 AUTHLOFT_* 变量忽略；空值视为未设置跳过
// （CI 常见空变量）；已设且非空的值非法（整数 / 时长解析失败）即 fail-fast。
var envBindings = slices.Concat(serverEnvBindings, []envBinding{
	{"AUTHLOFT_DB_DSN", func(c *Config, v string) error { c.DB.DSN = v; return nil }},
	{"AUTHLOFT_DB_MAX_OPEN_CONNS", setInt(func(c *Config, n int) { c.DB.MaxOpenConns = n })},
	{"AUTHLOFT_DB_MAX_IDLE_CONNS", setInt(func(c *Config, n int) { c.DB.MaxIdleConns = n })},
	{"AUTHLOFT_DB_CONN_MAX_LIFETIME", setDuration(func(c *Config, d Duration) { c.DB.ConnMaxLifetime = d })},

	{"AUTHLOFT_REDIS_ADDR", func(c *Config, v string) error { c.Redis.Addr = v; return nil }},
	{"AUTHLOFT_REDIS_PASSWORD", func(c *Config, v string) error { c.Redis.Password = v; return nil }},
	{"AUTHLOFT_REDIS_DB", setInt(func(c *Config, n int) { c.Redis.DB = n })},
	{"AUTHLOFT_REDIS_POOL_SIZE", setInt(func(c *Config, n int) { c.Redis.PoolSize = n })},

	{"AUTHLOFT_AUTHLOFT_ROOT", func(c *Config, v string) error { c.Authloft.Root = v; return nil }},
	{"AUTHLOFT_AUTHLOFT_RP_ID", func(c *Config, v string) error { c.Authloft.RpID = v; return nil }},
	{"AUTHLOFT_AUTHLOFT_RP_DISPLAY_NAME", func(c *Config, v string) error { c.Authloft.RPDisplayName = v; return nil }},

	{"AUTHLOFT_SIGN_KEY_SESSION_KEY", func(c *Config, v string) error { c.SignKey.Session.Key = v; return nil }},
	{"AUTHLOFT_SIGN_KEY_SESSION_KID", setInt(func(c *Config, n int) { c.SignKey.Session.Kid = n })},
	{"AUTHLOFT_SIGN_KEY_LOGIN_KEY", func(c *Config, v string) error { c.SignKey.Login.Key = v; return nil }},
	{"AUTHLOFT_SIGN_KEY_LOGIN_KID", setInt(func(c *Config, n int) { c.SignKey.Login.Kid = n })},
	{"AUTHLOFT_SIGN_KEY_TICKET_KEY", func(c *Config, v string) error { c.SignKey.Ticket.Key = v; return nil }},
	{"AUTHLOFT_SIGN_KEY_TICKET_KID", setInt(func(c *Config, n int) { c.SignKey.Ticket.Kid = n })},
	{"AUTHLOFT_SIGN_KEY_COOKIE_KEY", func(c *Config, v string) error { c.SignKey.Cookie.Key = v; return nil }},
	{"AUTHLOFT_SIGN_KEY_COOKIE_KID", setInt(func(c *Config, n int) { c.SignKey.Cookie.Kid = n })},
	{"AUTHLOFT_SIGN_KEY_SYNC_PAYLOAD_KEY", func(c *Config, v string) error { c.SignKey.SyncPayload.Key = v; return nil }},
	{"AUTHLOFT_SIGN_KEY_SYNC_PAYLOAD_KID", setInt(func(c *Config, n int) { c.SignKey.SyncPayload.Kid = n })},
	{"AUTHLOFT_SIGN_KEY_CHALLENGE_KEY", func(c *Config, v string) error { c.SignKey.Challenge.Key = v; return nil }},
	{"AUTHLOFT_SIGN_KEY_CHALLENGE_KID", setInt(func(c *Config, n int) { c.SignKey.Challenge.Kid = n })},
	{"AUTHLOFT_SIGN_KEY_VERIFICATION_KEY", func(c *Config, v string) error { c.SignKey.Verification.Key = v; return nil }},
	{"AUTHLOFT_SIGN_KEY_VERIFICATION_KID", setInt(func(c *Config, n int) { c.SignKey.Verification.Kid = n })},

	{"AUTHLOFT_ARGON2_TIME", setInt(func(c *Config, n int) { c.Argon2.Time = n })},
	{"AUTHLOFT_ARGON2_MEMORY", setInt(func(c *Config, n int) { c.Argon2.Memory = n })},
	{"AUTHLOFT_ARGON2_THREADS", setInt(func(c *Config, n int) { c.Argon2.Threads = n })},
	{"AUTHLOFT_ARGON2_KEY_LEN", setInt(func(c *Config, n int) { c.Argon2.KeyLen = n })},

	{"AUTHLOFT_LOG_LEVEL", func(c *Config, v string) error { c.Log.Level = v; return nil }},
	{"AUTHLOFT_LOG_FORMAT", func(c *Config, v string) error { c.Log.Format = v; return nil }},
})

// applyEnvOverrides 按全字段表应用环境变量覆盖（环境变量优先于文件值）。
// 错误只报 env 变量名与原因，不回显值——密钥类 env（SIGN_KEY_*_KEY）也不进日志。
func applyEnvOverrides(c *Config) error { return applyEnv(c, envBindings) }

// applyEnv 按 bindings 逐条应用环境变量覆盖（applyEnvOverrides 的参数化
// 内核，DefaultServerConfig 复用 server 段子表）。
func applyEnv(c *Config, bindings []envBinding) error {
	for _, b := range bindings {
		v, ok := os.LookupEnv(b.key)
		if !ok || v == "" {
			continue
		}
		if err := b.set(c, v); err != nil {
			return fmt.Errorf("config: env %s: %w", b.key, err)
		}
	}
	return nil
}

// DefaultServerConfig setup 模式的 server 段取值（§3.1 行 247 / §3.15：
// 无 config.yaml 可加载，取值 = §3.2 默认值 + env 覆盖，只读 server 段
// ——AUTHLOFT_SERVER_LISTEN / MIN_TLS_VERSION / CERT_FILE / KEY_FILE，
// 其他段一概不读）。listen 默认 ":8080"，TLS 字段默认空；非法 env 值 /
// 单边 cert / 不可读路径 fail-fast（§3.2 约定 5 同口径）。
func DefaultServerConfig() (ServerConfig, error) {
	c := Config{Server: ServerConfig{Listen: ":8080"}}
	if err := applyEnv(&c, serverEnvBindings); err != nil {
		return ServerConfig{}, err
	}
	if errs := c.Server.validate(); len(errs) > 0 {
		return ServerConfig{}, fmt.Errorf("config: invalid: %w", errors.Join(errs...))
	}
	return c.Server, nil
}
