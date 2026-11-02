package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// testKeyB64 是 32 字节的 std base64 编码（合法 AES-256-GCM 密钥形态）。
var testKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA5}, 32))

// exampleKeyPlaceholder 必须与 configs/config.yaml.example 的密钥占位符逐字一致：
// example 同步测试靠它把占位符替换成真密钥后整份加载，验证示例与 Config schema 同步。
const exampleKeyPlaceholder = "<base64-32B，首次运行自动生成>"

// testValidYAML 是全字段齐全的合法配置模板；"<KEY>" 占位在加载前替换为 testKeyB64。
const testValidYAML = `
server: { listen: ":8080", read_timeout: 30s, write_timeout: 30s }
db:
  dsn: "authloft:pass@tcp(10.0.0.2:3306)/authloft?charset=utf8mb4&parseTime=true&loc=Local"
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 1h
redis: { addr: "127.0.0.1:6379", password: "redis-pass", db: 3, pool_size: 50 }
authloft: { root: "https://sso.example.com", rp_id: "sso.example.com" }
sign_key:
  session:      { key: "<KEY>", kid: 1 }
  login:        { key: "<KEY>", kid: 1 }
  ticket:       { key: "<KEY>", kid: 1 }
  cookie:       { key: "<KEY>", kid: 1 }
  sync_payload: { key: "<KEY>", kid: 1 }
argon2: { time: 3, memory: 65536, threads: 4, key_len: 32 }
log: { level: info, format: json }
`

// filledTestYAML 返回密钥已填充的合法 YAML 文本（loader 测试用）。
func filledTestYAML() string {
	return strings.ReplaceAll(testValidYAML, "<KEY>", testKeyB64)
}

// validTestConfig 加载一份合法 Config（Validate 必过），供表驱动测试 mutate。
func validTestConfig(t *testing.T) *Config {
	t.Helper()
	var c Config
	if err := yaml.Unmarshal([]byte(filledTestYAML()), &c); err != nil {
		t.Fatalf("unmarshal valid yaml: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("fixture must be valid: %v", err)
	}
	return &c
}

func TestDurationYAML(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"30s", 30 * time.Second, true},
		{"1h", time.Hour, true},
		{"1h30m", 90 * time.Minute, true},
		{"250ms", 250 * time.Millisecond, true},
		{"abc", 0, false},
		{"30", 0, false}, // 裸数字必须报错——fail-fast 逼书写者写明单位
	}
	for _, tc := range cases {
		var d Duration
		err := yaml.Unmarshal([]byte(tc.in), &d)
		if tc.ok {
			if err != nil || d.Duration != tc.want {
				t.Errorf("Unmarshal(%q) = %v, %v; want %v, nil", tc.in, d.Duration, err, tc.want)
			}
		} else if err == nil {
			t.Errorf("Unmarshal(%q): want error, got nil", tc.in)
		}
	}
}

func TestDurationMarshalRoundTrip(t *testing.T) {
	d := Duration{90 * time.Minute}
	out, err := yaml.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var d2 Duration
	if err := yaml.Unmarshal(out, &d2); err != nil {
		t.Fatalf("remarshal output must reparse: %v", err)
	}
	if d2.Duration != d.Duration {
		t.Errorf("round trip = %v, want %v", d2.Duration, d.Duration)
	}
}

func TestValidateAcceptsFullConfig(t *testing.T) {
	if err := validTestConfig(t).Validate(); err != nil {
		t.Fatalf("want valid, got %v", err)
	}
}

func TestValidateRejectsInvalidFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"listen empty", func(c *Config) { c.Server.Listen = "" }, "server.listen"},
		{"listen bare port", func(c *Config) { c.Server.Listen = "8080" }, "server.listen"},
		{"listen port overflow", func(c *Config) { c.Server.Listen = ":70000" }, "server.listen"},
		{"listen port non numeric", func(c *Config) { c.Server.Listen = ":http" }, "server.listen"},
		{"read_timeout zero", func(c *Config) { c.Server.ReadTimeout = Duration{} }, "server.read_timeout"},
		{"write_timeout negative", func(c *Config) { c.Server.WriteTimeout = Duration{-time.Second} }, "server.write_timeout"},

		{"dsn empty", func(c *Config) { c.DB.DSN = "" }, "db.dsn"},
		{"dsn no at", func(c *Config) { c.DB.DSN = "tcp(1.2.3.4:3306)/db" }, "db.dsn"},
		{"dsn wrong net", func(c *Config) { c.DB.DSN = "u:p@http(1.2.3.4:3306)/db" }, "db.dsn"},
		{"dsn no db name", func(c *Config) { c.DB.DSN = "u:p@tcp(1.2.3.4:3306)" }, "db.dsn"},
		{"max_open_conns zero", func(c *Config) { c.DB.MaxOpenConns = 0 }, "db.max_open_conns"},
		{"max_idle_conns negative", func(c *Config) { c.DB.MaxIdleConns = -1 }, "db.max_idle_conns"},
		{"conn_max_lifetime zero", func(c *Config) { c.DB.ConnMaxLifetime = Duration{} }, "db.conn_max_lifetime"},

		{"redis addr empty", func(c *Config) { c.Redis.Addr = "" }, "redis.addr"},
		{"redis addr no port", func(c *Config) { c.Redis.Addr = "127.0.0.1" }, "redis.addr"},
		{"redis addr bad port", func(c *Config) { c.Redis.Addr = "127.0.0.1:port" }, "redis.addr"},
		{"redis db negative", func(c *Config) { c.Redis.DB = -1 }, "redis.db"},
		{"pool_size zero", func(c *Config) { c.Redis.PoolSize = 0 }, "redis.pool_size"},

		{"root empty", func(c *Config) { c.Authloft.Root = "" }, "authloft.root"},
		{"root http", func(c *Config) { c.Authloft.Root = "http://sso.example.com" }, "authloft.root"},
		{"root no host", func(c *Config) { c.Authloft.Root = "https://" }, "authloft.root"},
		{"rp_id empty", func(c *Config) { c.Authloft.RpID = "" }, "authloft.rp_id"},

		{"key empty", func(c *Config) { c.SignKey.Session.Key = "" }, "sign_key.session.key"},
		{"key not base64", func(c *Config) { c.SignKey.Session.Key = "!!!not-base64!!!" }, "sign_key.session.key"},
		{"key wrong length", func(c *Config) { c.SignKey.Ticket.Key = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)) }, "sign_key.ticket.key"},
		{"kid zero", func(c *Config) { c.SignKey.Cookie.Kid = 0 }, "sign_key.cookie.kid"},
		{"kid negative", func(c *Config) { c.SignKey.SyncPayload.Kid = -1 }, "sign_key.sync_payload.kid"},

		{"argon2 time zero", func(c *Config) { c.Argon2.Time = 0 }, "argon2.time"},
		{"argon2 memory zero", func(c *Config) { c.Argon2.Memory = 0 }, "argon2.memory"},
		{"argon2 threads zero", func(c *Config) { c.Argon2.Threads = 0 }, "argon2.threads"},
		{"argon2 key_len zero", func(c *Config) { c.Argon2.KeyLen = 0 }, "argon2.key_len"},

		{"log level bogus", func(c *Config) { c.Log.Level = "verbose" }, "log.level"},
		{"log format bogus", func(c *Config) { c.Log.Format = "logfmt" }, "log.format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validTestConfig(t)
			tc.mutate(c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestValidateErrorsDoNotEchoKeyValues 密钥不出错误信息（§3.2 约定 3 的 fail-fast
// 出口）：报错只含字段路径与原因（长度），绝不回显密钥内容。
func TestValidateErrorsDoNotEchoKeyValues(t *testing.T) {
	c := validTestConfig(t)
	badKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xB}, 31)) // 31 字节 → 长度错
	c.SignKey.Login.Key = badKey
	c.SignKey.Cookie.Kid = 0
	err := c.Validate()
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "sign_key.login.key") {
		t.Errorf("want sign_key.login.key error, got %v", err)
	}
	if !strings.Contains(err.Error(), "sign_key.cookie.kid") {
		t.Errorf("want sign_key.cookie.kid error, got %v", err)
	}
	if strings.Contains(err.Error(), badKey) {
		t.Error("validate error echoes key value")
	}
}

// TestExampleFileMatchesSchema 验证 config.yaml.example 与 Config schema 同步
// （§3.2 职责表：新增字段必须同步 example）：把占位密钥替换成真密钥后，
// example 必须能整份解析并通过 Validate。
func TestExampleFileMatchesSchema(t *testing.T) {
	raw, err := os.ReadFile("../../configs/config.yaml.example")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	if !bytes.Contains(raw, []byte(exampleKeyPlaceholder)) {
		t.Fatal("example lost key placeholder")
	}
	filled := bytes.ReplaceAll(raw, []byte(exampleKeyPlaceholder), []byte(testKeyB64))
	var c Config
	if err := yaml.Unmarshal(filled, &c); err != nil {
		t.Fatalf("example out of sync with schema: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("example must be a valid config after keys filled: %v", err)
	}
}
