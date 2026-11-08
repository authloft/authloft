// Package config 提供 Authloft YAML 启动配置（docs/后端架构.md §3.2）。
//
// 整份配置只在启动时读取一次，运行期不可变；需要热更新的项（开关、阈值、
// Cookie 名与 TTL、队列参数）一律走 settings（接口文档 §5.6），不进本包。
// 业务代码不直接读本包全局变量，*Config 由装配层构造注入（§3.2 约定 1）。
package config

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration 是 time.Duration 的 YAML 包装类型：yaml.v3 不直接把 "30s" 这类
// Go 时长字面量解析成 time.Duration，统一经本类型的 UnmarshalYAML 走
// time.ParseDuration 转换；写回 YAML 时输出
// time.Duration.String() 形式（如 "30s"、"1h0m0s"），人类可读且可再解析。
type Duration struct{ time.Duration }

// UnmarshalYAML 实现 yaml.v3 接口：节点必须是带单位的时长字面量（"30s"、"1h"），
// 裸数字（如 `30`）报错——fail-fast，逼迫书写者写明单位。
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("want duration literal like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

// MarshalYAML 实现 yaml.v3 接口：写回人类可读、可再解析的时长字面量。
func (d Duration) MarshalYAML() (any, error) { return d.Duration.String(), nil }

// Config 与 docs/后端架构.md §3.2 行 258-284 的 YAML schema 一一对应
// （yaml 标签 snake_case）；新增字段必须同步 authloft.yml.example 与默认值说明。
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	DB       DBConfig       `yaml:"db"`
	Redis    RedisConfig    `yaml:"redis"`
	Authloft AuthloftConfig `yaml:"authloft"`
	SignKey  SignKeyConfig  `yaml:"sign_key"`
	OIDC     OIDCConfig     `yaml:"oidc"`
	Argon2   Argon2Config   `yaml:"argon2"`
	Log      LogConfig      `yaml:"log"`
}

// ServerConfig HTTP 监听与 TLS（docs/后端架构.md §3.2 行 254-258）。
type ServerConfig struct {
	Listen        string `yaml:"listen"`
	MinTLSVersion string `yaml:"min_tls_version"`
	CertFile      string `yaml:"cert_file"`
	KeyFile       string `yaml:"key_file"`
}

// TLSEnabled 判定是否启用 TLS 监听（§3.2 约定 5：cert_file + key_file
// 成对配置即启用；两者未同时配置 → 不启用 TLS，min_tls_version 不生效）。
func (s ServerConfig) TLSEnabled() bool { return s.CertFile != "" && s.KeyFile != "" }

// TLSMinVersion 把 min_tls_version 字符串映射为 crypto/tls 版本常量
// （§3.2 约定 5："1.2" → tls.VersionTLS12、"1.3" → tls.VersionTLS13、
// 空串 / 未配置 → 0（标准库默认，不设最低版本）；非法取值返回 error
// ——正常启动路径已在 Validate 拦截，此处兜底供装配层 fail-fast）。
func (s ServerConfig) TLSMinVersion() (uint16, error) {
	switch s.MinTLSVersion {
	case "":
		return 0, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf(`server.min_tls_version: want "1.2"|"1.3"|""`)
	}
}

// DBConfig MariaDB 连接参数（GORM）。
type DBConfig struct {
	DSN             string   `yaml:"dsn"`
	MaxOpenConns    int      `yaml:"max_open_conns"`
	MaxIdleConns    int      `yaml:"max_idle_conns"`
	ConnMaxLifetime Duration `yaml:"conn_max_lifetime"`
}

// RedisConfig Redis 连接参数；password 允许为空（内网 / 测试部署）。
type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	PoolSize int    `yaml:"pool_size"`
}

// AuthloftConfig 站点主域（al_root，拼回调 / 多域名同步地址）与 WebAuthn RP ID。
type AuthloftConfig struct {
	Root string `yaml:"root"`
	RpID string `yaml:"rp_id"`
}

// KeyMaterial 单场景对称密钥材料：AES-256-GCM 单密钥（§3.2 约定 4，非密钥对）。
// key 为 std base64，解码后恰 32 字节；kid 供多 kid 轮换。
type KeyMaterial struct {
	Key string `yaml:"key"`
	Kid int    `yaml:"kid"`
}

// SignKeyConfig 五类令牌 / 载荷的独立密钥（§1.4）：互不复用，泄露一枚不殃及其余。
type SignKeyConfig struct {
	Session     KeyMaterial `yaml:"session"`      // session token
	Login       KeyMaterial `yaml:"login"`        // login token
	Ticket      KeyMaterial `yaml:"ticket"`       // ticket（含 al:ticket 存储值，§11.4）
	Cookie      KeyMaterial `yaml:"cookie"`       // al_login_state（§11.6.1）
	SyncPayload KeyMaterial `yaml:"sync_payload"` // 多域名同步载荷（§11.2）
}

// OIDCConfig OIDC RS256 签名密钥集（§3.2 约定 6 / §14.3）：与顶层 sign_key
// （AES-256-GCM 对称单密钥）严格分离，两者不得互用。列表首项为当前签发密钥。
type OIDCConfig struct {
	JWTKeys []OIDCKey `yaml:"jwt_keys"`
}

// OIDCKey 单把 OIDC 签名密钥：kid 非空且列表内唯一；private_key_pem 为
// base64 编码的 PKCS#8 RSA 私钥 PEM（2048/3072/4096 位）。oidc 段不参与
// AUTHLOFT_<SECTION>_<FIELD> env 注入（§3.2 约定 6：私钥不经 env 传递）。
type OIDCKey struct {
	Kid           string `yaml:"kid"`
	PrivateKeyPEM string `yaml:"private_key_pem"`
}

// Argon2Config argon2id 密码哈希参数。
type Argon2Config struct {
	Time    int `yaml:"time"`
	Memory  int `yaml:"memory"`
	Threads int `yaml:"threads"`
	KeyLen  int `yaml:"key_len"`
}

// LogConfig 日志级别与格式（slog）。
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Validate 校验全部关键项（fail-fast：任一项缺失 / 非法即配置不可用），
// 汇总所有错误一次返回（errors.Join）。错误信息只含字段路径与原因，
// 不回显字段值——密钥类内容不得进日志（§3.2 约定 3）。
func (c *Config) Validate() error {
	var errs []error
	errs = append(errs, c.Server.validate()...)
	errs = append(errs, c.DB.validate()...)
	errs = append(errs, c.Redis.validate()...)
	errs = append(errs, c.Authloft.validate()...)
	errs = append(errs, c.SignKey.validate()...)
	errs = append(errs, c.OIDC.validate()...)
	errs = append(errs, c.Argon2.validate()...)
	errs = append(errs, c.Log.validate()...)
	return errors.Join(errs...)
}

func (s ServerConfig) validate() []error {
	var errs []error
	switch {
	case s.Listen == "":
		errs = append(errs, errors.New("server.listen: required"))
	default:
		// 支持 :port（空 host = 全部接口）、IPv4:port、[IPv6]:port。
		// 裸 IPv6 不带方括号会被 net.SplitHostPort 判为 too many colons，
		// 归入 invalid address 错误；缺端口 / 端口非数字 / 越界分别报错，
		// 不静默回落默认值（fail-fast）。
		_, port, err := net.SplitHostPort(s.Listen)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("server.listen: invalid address %q: want [host:]port (IPv6 must be [host]:port)", s.Listen))
		case port == "":
			errs = append(errs, fmt.Errorf("server.listen: missing port in %q", s.Listen))
		default:
			if p, perr := strconv.Atoi(port); perr != nil || p < 1 || p > 65535 {
				errs = append(errs, fmt.Errorf("server.listen: port %q out of range (1-65535)", port))
			}
		}
	}
	// min_tls_version 取值合法性恒校验（§3.2 约定 5：「非法取值启动
	// fail-fast」独立于是否启用 TLS——生效性才受 cert/key 配置影响）。
	if _, err := s.TLSMinVersion(); err != nil {
		errs = append(errs, err)
	}
	// cert_file / key_file 必须成对配置且路径可读；单边配置 / 不可读
	// fail-fast（§3.2 约定 5）。
	if (s.CertFile == "") != (s.KeyFile == "") {
		errs = append(errs, errors.New("server.cert_file/server.key_file: must be configured pairwise"))
	} else if s.TLSEnabled() {
		errs = append(errs, checkReadable(s.CertFile, "server.cert_file")...)
		errs = append(errs, checkReadable(s.KeyFile, "server.key_file")...)
	}
	return errs
}

// checkReadable 校验启动期文件路径可读（目录不可用）。错误只含字段路径
// 与系统原因——证书 / 私钥内容不回显（§3.2 约定 3 的 fail-fast 出口口径）。
func checkReadable(path, field string) []error {
	f, err := os.Open(path)
	if err != nil {
		return []error{fmt.Errorf("%s: not readable: %w", field, err)}
	}
	fi, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil {
		return []error{fmt.Errorf("%s: not readable: %w", field, statErr)}
	}
	if closeErr != nil {
		return []error{fmt.Errorf("%s: not readable: %w", field, closeErr)}
	}
	if fi.IsDir() {
		return []error{fmt.Errorf("%s: is a directory", field)}
	}
	return nil
}

func (d DBConfig) validate() []error {
	var errs []error
	errs = append(errs, validateDSN(d.DSN))
	if d.MaxOpenConns <= 0 {
		errs = append(errs, errors.New("db.max_open_conns: must be > 0"))
	}
	if d.MaxIdleConns <= 0 {
		errs = append(errs, errors.New("db.max_idle_conns: must be > 0"))
	}
	if d.ConnMaxLifetime.Duration <= 0 {
		errs = append(errs, errors.New("db.conn_max_lifetime: must be > 0"))
	}
	return errs
}

// validateDSN 对 DSN 做轻量结构校验（不 import 驱动，连接留给装配层）：
// 要求 "user[:pass]@tcp(host:port)/name[?params]" 或 "@unix(/path)/name"
// 的承载结构；只验形不验账密——账密错误由 DB 连接期暴露。
func validateDSN(dsn string) error {
	if dsn == "" {
		return errors.New("db.dsn: required")
	}
	rest := ""
	if at := strings.LastIndex(dsn, "@"); at >= 0 {
		rest = dsn[at+1:]
	}
	switch {
	case strings.HasPrefix(rest, "tcp("), strings.HasPrefix(rest, "unix("):
		if !strings.Contains(rest, ")/") {
			return errors.New(`db.dsn: want "user:pass@tcp(host:port)/name" form`)
		}
		return nil
	default:
		return errors.New(`db.dsn: want "user:pass@tcp(host:port)/name" form`)
	}
}

func (r RedisConfig) validate() []error {
	var errs []error
	if r.Addr == "" {
		errs = append(errs, errors.New("redis.addr: required"))
	} else if _, portStr, err := net.SplitHostPort(r.Addr); err != nil {
		errs = append(errs, errors.New(`redis.addr: want "host:port" form`))
	} else if port, err := strconv.Atoi(portStr); err != nil || port < 1 || port > 65535 {
		errs = append(errs, errors.New("redis.addr: port out of range (1-65535)"))
	}
	if r.DB < 0 {
		errs = append(errs, errors.New("redis.db: must be >= 0"))
	}
	if r.PoolSize <= 0 {
		errs = append(errs, errors.New("redis.pool_size: must be > 0"))
	}
	return errs
}

// validate 校验 authloft 段。root 允许 http://（后端架构 §3.2 约定 7、
// 接口文档 §1.1 行 76「明文 HTTP 部署为一等公民」）：只
// 校验「可解析 URL 且 scheme 为 http 或 https 且 host 非空」，不强制
// HTTPS。明文部署适用内网 / 测试 / 反代 TLS 终止后明文直连；公网明文
// 部署存在会话令牌被窃听风险，由部署方自行负责（安全提示见 §1.1）。
// 会话 Cookie 的 Secure 属性由 settings 键 https_deployment 驱动
//（接口文档 §5.6 / §1.9），与本字段无耦合；HTTP→HTTPS 强制跳转与
// HSTS 由网关层负责，Authloft 不提供（写死不做）。
func (a AuthloftConfig) validate() []error {
	var errs []error
	if u, err := url.Parse(a.Root); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		errs = append(errs, errors.New(`authloft.root: want http(s) URL like "https://authloft.example.com"`))
	}
	if a.RpID == "" {
		errs = append(errs, errors.New("authloft.rp_id: required"))
	}
	return errs
}

func (s SignKeyConfig) validate() []error {
	scenarios := []struct {
		field string
		km    KeyMaterial
	}{
		{"sign_key.session", s.Session},
		{"sign_key.login", s.Login},
		{"sign_key.ticket", s.Ticket},
		{"sign_key.cookie", s.Cookie},
		{"sign_key.sync_payload", s.SyncPayload},
	}
	var errs []error
	for _, sc := range scenarios {
		errs = append(errs, sc.km.validate(sc.field)...)
	}
	return errs
}

func (k KeyMaterial) validate(field string) []error {
	var errs []error
	switch {
	case k.Key == "":
		errs = append(errs, errors.New(field+".key: required"))
	default:
		raw, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			errs = append(errs, errors.New(field+".key: want std base64"))
		} else if len(raw) != 32 {
			// 只报长度不报内容——密钥不出日志（§3.2 约定 3）。
			errs = append(errs, fmt.Errorf("%s.key: must decode to 32 bytes (AES-256-GCM), got %d", field, len(raw)))
		}
	}
	if k.Kid <= 0 {
		errs = append(errs, errors.New(field+".kid: must be > 0"))
	}
	return errs
}

// validate OIDC 密钥集（§3.2 约定 6）：列表非空、kid 非空且列表内唯一、
// 每把 private_key_pem 为 base64(PKCS#8 RSA 私钥 PEM) 且位数为
// 2048/3072/4096。任一失败即不可启动（fail-fast）——不回退对称 sign_key、
// 不自动补写。
func (o OIDCConfig) validate() []error {
	if len(o.JWTKeys) == 0 {
		return []error{errors.New("oidc.jwt_keys: required (non-empty list)")}
	}
	var errs []error
	seen := make(map[string]struct{}, len(o.JWTKeys))
	for i, k := range o.JWTKeys {
		field := fmt.Sprintf("oidc.jwt_keys[%d]", i)
		switch {
		case k.Kid == "":
			errs = append(errs, errors.New(field+".kid: required"))
		default:
			if _, dup := seen[k.Kid]; dup {
				errs = append(errs, errors.New(field+".kid: duplicate (must be unique within oidc.jwt_keys)"))
			} else {
				seen[k.Kid] = struct{}{}
			}
		}
		errs = append(errs, validateOIDCPrivateKey(k.PrivateKeyPEM, field+".private_key_pem")...)
	}
	return errs
}

// validateOIDCPrivateKey 校验一把 OIDC 签名私钥：base64 解码 → PEM 解码 →
// ParsePKCS8PrivateKey → 断言 *rsa.PrivateKey → 位数 2048/3072/4096。
// 错误只报字段路径与原因，不回显密钥内容（§3.2 约定 3）。
func validateOIDCPrivateKey(encoded, field string) []error {
	if encoded == "" {
		return []error{errors.New(field + ": required")}
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return []error{errors.New(field + ": want std base64")}
	}
	block, _ := pem.Decode(der)
	if block == nil || block.Type != "PRIVATE KEY" {
		return []error{errors.New(field + `: want PEM block "PRIVATE KEY" (PKCS#8)`)}
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return []error{errors.New(field + ": want PKCS#8 RSA private key")}
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return []error{errors.New(field + ": must be an RSA private key")}
	}
	switch rsaKey.N.BitLen() {
	case 2048, 3072, 4096:
		return nil
	default:
		return []error{fmt.Errorf("%s: RSA key size must be 2048/3072/4096 bits, got %d", field, rsaKey.N.BitLen())}
	}
}

func (a Argon2Config) validate() []error {
	var errs []error
	if a.Time <= 0 {
		errs = append(errs, errors.New("argon2.time: must be > 0"))
	}
	if a.Memory <= 0 {
		errs = append(errs, errors.New("argon2.memory: must be > 0"))
	}
	if a.Threads <= 0 {
		errs = append(errs, errors.New("argon2.threads: must be > 0"))
	}
	if a.KeyLen <= 0 {
		errs = append(errs, errors.New("argon2.key_len: must be > 0"))
	}
	return errs
}

func (l LogConfig) validate() []error {
	var errs []error
	switch l.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, errors.New("log.level: want one of debug|info|warn|error"))
	}
	switch l.Format {
	case "json", "text":
	default:
		errs = append(errs, errors.New("log.format: want json|text"))
	}
	return errs
}
