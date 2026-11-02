package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Load 读取 YAML 启动配置（docs/后端架构.md §3.2 职责表）：
//
//  1. 文件存在：解析 → 应用环境变量覆盖（环境变量优先）→ Validate；
//     任一步失败即返回 error，fail-fast，不提供运行期兜底默认值；
//  2. 文件不存在（唯一例外，§3.2 约定 4）：生成全部 sign_key（五场景
//     AES-256-GCM 对称单密钥：crypto/rand 32 字节 → std base64，kid=1），
//     连同默认值结构写回 YAML 后正常启动；
//  3. 其他读错误（权限等）原样返回。
//
// 日志只记录事件与路径，绝不输出密钥值（§3.2 约定 3）；错误信息亦不回显
// 密钥——env / Validate 的报错只含字段路径与原因。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parseAndValidate(data)
	case errors.Is(err, fs.ErrNotExist):
		return firstRun(path)
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

// firstRun 配置文件不存在且首次运行：生成 sign_key + 默认值结构写回 YAML 后正常
// 启动。写回发生在 env 覆盖之前——env 是进程级注入不落盘，文件保持纯默认值，
// 下次无 env 启动仍可用。
func firstRun(path string) (*Config, error) {
	c, err := defaultConfig()
	if err != nil {
		return nil, fmt.Errorf("config: generate sign keys: %w", err)
	}
	out, err := yaml.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("config: marshal default yaml: %w", err)
	}
	// 0600：文件含对称密钥，仅属主可读。
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, fmt.Errorf("config: write %s: %w", path, err)
	}
	slog.Info("config: file missing, generated default config with fresh sign keys", "path", path)
	if err := applyEnvOverrides(c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: invalid: %w", err)
	}
	return c, nil
}

// defaultConfig 构造全量默认值结构（与 configs/config.yaml.example 同源），
// sign_key 五场景现场生成，互不复用。
func defaultConfig() (*Config, error) {
	c := Config{
		Server: ServerConfig{
			Listen:       ":8080",
			ReadTimeout:  Duration{30 * time.Second},
			WriteTimeout: Duration{30 * time.Second},
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
			Root: "https://authloft.example.com",
			RpID: "authloft.example.com",
		},
		Argon2: Argon2Config{Time: 3, Memory: 65536, Threads: 4, KeyLen: 32},
		Log:    LogConfig{Level: "info", Format: "json"},
	}
	for _, km := range []*KeyMaterial{
		&c.SignKey.Session,
		&c.SignKey.Login,
		&c.SignKey.Ticket,
		&c.SignKey.Cookie,
		&c.SignKey.SyncPayload,
	} {
		k, err := generateKeyMaterial()
		if err != nil {
			return nil, err
		}
		*km = k
	}
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

// envBindings 环境变量覆盖表：AUTHLOFT_<SECTION>_<FIELD>（大写下划线），由文档
// 明写的 AUTHLOFT_DB_DSN、AUTHLOFT_REDIS_ADDR（§3.2 职责表）按同模式推导为
// 全字段口径（含 sign_key 十字段与 AUTHLOFT_AUTHLOFT_* 双前缀）。显式表而非反射：
// 无运行时魔法、逐条可测。未知 AUTHLOFT_* 变量忽略；空值视为未设置跳过
// （CI 常见空变量）；已设且非空的值非法（整数 / 时长解析失败）即 fail-fast。
var envBindings = []envBinding{
	{"AUTHLOFT_SERVER_LISTEN", func(c *Config, v string) error { c.Server.Listen = v; return nil }},
	{"AUTHLOFT_SERVER_READ_TIMEOUT", setDuration(func(c *Config, d Duration) { c.Server.ReadTimeout = d })},
	{"AUTHLOFT_SERVER_WRITE_TIMEOUT", setDuration(func(c *Config, d Duration) { c.Server.WriteTimeout = d })},

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

	{"AUTHLOFT_ARGON2_TIME", setInt(func(c *Config, n int) { c.Argon2.Time = n })},
	{"AUTHLOFT_ARGON2_MEMORY", setInt(func(c *Config, n int) { c.Argon2.Memory = n })},
	{"AUTHLOFT_ARGON2_THREADS", setInt(func(c *Config, n int) { c.Argon2.Threads = n })},
	{"AUTHLOFT_ARGON2_KEY_LEN", setInt(func(c *Config, n int) { c.Argon2.KeyLen = n })},

	{"AUTHLOFT_LOG_LEVEL", func(c *Config, v string) error { c.Log.Level = v; return nil }},
	{"AUTHLOFT_LOG_FORMAT", func(c *Config, v string) error { c.Log.Format = v; return nil }},
}

// applyEnvOverrides 按表应用环境变量覆盖（环境变量优先于文件值）。
// 错误只报 env 变量名与原因，不回显值——密钥类 env（SIGN_KEY_*_KEY）也不进日志。
func applyEnvOverrides(c *Config) error {
	for _, b := range envBindings {
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
