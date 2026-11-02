package config

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfigFile 把 YAML 文本写进临时目录，返回路径。
func writeConfigFile(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return path
}

// missingScenarioYAML 合法配置但 sign_key 只写了 session——其余四场景缺失，
// 用于验证「文件已存在但缺项 → fail-fast，不自动补写」（§3.2 约定 4）。
const missingScenarioYAML = `
server: { listen: ":8080", read_timeout: 30s, write_timeout: 30s }
db:
  dsn: "authloft:pass@tcp(127.0.0.1:3306)/authloft"
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 1h
redis: { addr: "127.0.0.1:6379", password: "", db: 0, pool_size: 50 }
authloft: { root: "https://sso.example.com", rp_id: "sso.example.com" }
sign_key:
  session: { key: "<KEY>", kid: 1 }
argon2: { time: 3, memory: 65536, threads: 4, key_len: 32 }
log: { level: info, format: json }
`

// TestLoadFirstRunGeneratesAndWritesBackSignKeys 唯一例外路径（§3.2 约定 4）：
// 配置文件不存在 → 自动生成 5 场景密钥写回 YAML 后正常启动；写回的文件可再次
// 加载且密钥一致（不是每次 Load 重新生成）。
func TestLoadFirstRunGeneratesAndWritesBackSignKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}

	cfgReloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload written-back file: %v", err)
	}
	if cfgReloaded.SignKey != cfg.SignKey {
		t.Fatal("reloading regenerated sign keys; written-back file must be reused")
	}

	scenarios := []struct {
		name string
		km   KeyMaterial
	}{
		{"session", cfg.SignKey.Session},
		{"login", cfg.SignKey.Login},
		{"ticket", cfg.SignKey.Ticket},
		{"cookie", cfg.SignKey.Cookie},
		{"sync_payload", cfg.SignKey.SyncPayload},
	}
	seen := make(map[string]bool, len(scenarios))
	for _, sc := range scenarios {
		raw, err := base64.StdEncoding.DecodeString(sc.km.Key)
		if err != nil {
			t.Errorf("%s key: invalid base64: %v", sc.name, err)
			continue
		}
		if len(raw) != 32 {
			t.Errorf("%s key: decodes to %d bytes, want 32", sc.name, len(raw))
		}
		if sc.km.Kid != 1 {
			t.Errorf("%s kid = %d, want 1", sc.name, sc.km.Kid)
		}
		if seen[sc.km.Key] {
			t.Errorf("duplicated %s key; five scenarios must be independent keys", sc.name)
		}
		seen[sc.km.Key] = true
	}

	if cfg.Server.Listen != ":8080" || cfg.Log.Level != "info" || cfg.Log.Format != "json" ||
		cfg.Argon2.Time != 3 || cfg.Argon2.KeyLen != 32 || cfg.Redis.PoolSize != 50 {
		t.Errorf("first run returned non-default config: server=%+v log=%+v argon2=%+v redis=%+v",
			cfg.Server, cfg.Log, cfg.Argon2, cfg.Redis)
	}
	if cfg.Server.ReadTimeout.Duration != 30*time.Second || cfg.DB.ConnMaxLifetime.Duration != time.Hour {
		t.Errorf("first run returned non-default durations: read=%v lifetime=%v",
			cfg.Server.ReadTimeout, cfg.DB.ConnMaxLifetime)
	}
}

// TestLoadFirstRunEnvOverridesWithoutPersisting env 覆盖生效但不写回文件：
// 首启写回的是纯默认值结构，env 是进程级注入。
func TestLoadFirstRunEnvOverridesWithoutPersisting(t *testing.T) {
	t.Setenv("AUTHLOFT_SERVER_LISTEN", ":9999")
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if cfg.Server.Listen != ":9999" {
		t.Errorf("listen = %q, want :9999 from env", cfg.Server.Listen)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), ":8080") {
		t.Error("written-back file must keep default listen value")
	}
	if strings.Contains(string(data), "9999") {
		t.Error("env value must not be persisted to file")
	}
}

// TestLoadEnvOverridesFileValues 环境变量优先于文件值（§3.2 职责表）：
// 字符串 / 整数 / 时长 / kid / 密钥各验一条。
func TestLoadEnvOverridesFileValues(t *testing.T) {
	path := writeConfigFile(t, filledTestYAML())
	envKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xC3}, 32))
	t.Setenv("AUTHLOFT_DB_DSN", "env:secret@tcp(db-env:3306)/authloft")
	t.Setenv("AUTHLOFT_REDIS_ADDR", "redis-env:6379")
	t.Setenv("AUTHLOFT_SERVER_READ_TIMEOUT", "45s")
	t.Setenv("AUTHLOFT_REDIS_DB", "7")
	t.Setenv("AUTHLOFT_SIGN_KEY_SESSION_KID", "2")
	t.Setenv("AUTHLOFT_SIGN_KEY_TICKET_KEY", envKey)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.DB.DSN != "env:secret@tcp(db-env:3306)/authloft" {
		t.Errorf("dsn = %q, want env value", cfg.DB.DSN)
	}
	if cfg.Redis.Addr != "redis-env:6379" {
		t.Errorf("redis addr = %q, want env value", cfg.Redis.Addr)
	}
	if cfg.Server.ReadTimeout.Duration != 45*time.Second {
		t.Errorf("read_timeout = %v, want 45s from env", cfg.Server.ReadTimeout)
	}
	if cfg.Redis.DB != 7 {
		t.Errorf("redis db = %d, want 7 from env", cfg.Redis.DB)
	}
	if cfg.SignKey.Session.Kid != 2 {
		t.Errorf("session kid = %d, want 2 from env", cfg.SignKey.Session.Kid)
	}
	if cfg.SignKey.Ticket.Key != envKey {
		t.Errorf("ticket key not overridden by env")
	}
}

// TestLoadEnvInvalidValueFails env 值非法（整数解析失败）→ fail-fast。
func TestLoadEnvInvalidValueFails(t *testing.T) {
	path := writeConfigFile(t, filledTestYAML())
	t.Setenv("AUTHLOFT_DB_MAX_OPEN_CONNS", "fifty")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "AUTHLOFT_DB_MAX_OPEN_CONNS") {
		t.Errorf("want fail-fast on invalid env int, got %v", err)
	}
}

// TestLoadEnvInvalidDurationFails env 时长非法 → fail-fast。
func TestLoadEnvInvalidDurationFails(t *testing.T) {
	path := writeConfigFile(t, filledTestYAML())
	t.Setenv("AUTHLOFT_SERVER_READ_TIMEOUT", "soon")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "AUTHLOFT_SERVER_READ_TIMEOUT") {
		t.Errorf("want fail-fast on invalid env duration, got %v", err)
	}
}

// TestLoadIgnoresUnknownAuthloftEnv 未知 AUTHLOFT_* 变量不报错（覆盖口径只认已知表）。
func TestLoadIgnoresUnknownAuthloftEnv(t *testing.T) {
	path := writeConfigFile(t, filledTestYAML())
	t.Setenv("AUTHLOFT_NOT_A_FIELD", "whatever")
	if _, err := Load(path); err != nil {
		t.Errorf("unknown env must be ignored, got %v", err)
	}
}

// TestLoadMissingSectionFails 文件存在但 db 段缺失 → fail-fast（零值被 Validate 拦截）。
func TestLoadMissingSectionFails(t *testing.T) {
	noDB := `
server: { listen: ":8080", read_timeout: 30s, write_timeout: 30s }
redis: { addr: "127.0.0.1:6379", password: "", db: 0, pool_size: 50 }
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
	path := writeConfigFile(t, strings.ReplaceAll(noDB, "<KEY>", testKeyB64))
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "db.dsn") {
		t.Errorf("want fail-fast on missing db section, got %v", err)
	}
}

// TestLoadMissingSignKeyScenarioFailsNoRewrite 文件已存在但 sign_key 缺场景：
// fail-fast 退出且不自动补写（§3.2 约定 4），文件内容必须原样未动。
func TestLoadMissingSignKeyScenarioFailsNoRewrite(t *testing.T) {
	path := writeConfigFile(t, strings.ReplaceAll(missingScenarioYAML, "<KEY>", testKeyB64))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "sign_key.login.key") {
		t.Fatalf("want fail-fast on missing sign_key scenario, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("existing file with missing key must not be rewritten")
	}
}

// TestLoadInvalidDSNFails 文件存在但 DSN 非法 → fail-fast。
func TestLoadInvalidDSNFails(t *testing.T) {
	bad := strings.Replace(filledTestYAML(),
		`dsn: "authloft:pass@tcp(10.0.0.2:3306)/authloft?charset=utf8mb4&parseTime=true&loc=Local"`,
		`dsn: "garbage"`, 1)
	path := writeConfigFile(t, bad)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "db.dsn") {
		t.Errorf("want fail-fast on invalid dsn, got %v", err)
	}
}

// TestLoadBareNumberDurationFails 时长写裸数字（30 而非 30s）→ 解析期 fail-fast。
func TestLoadBareNumberDurationFails(t *testing.T) {
	bad := strings.Replace(filledTestYAML(), "read_timeout: 30s", "read_timeout: 30", 1)
	path := writeConfigFile(t, bad)
	_, err := Load(path)
	if err == nil {
		t.Error("want fail-fast on bare-number duration, got nil")
	}
}

// TestLoadReadErrorFails 读错误（如路径是目录）原样失败，不得误判为首启去生成文件。
func TestLoadReadErrorFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("reading a directory must fail, not trigger first-run generation")
	}
}

// TestSignKeysNeverLogged 密钥不出日志（§3.2 约定 3）：捕获首启 slog 输出，
// 断言生成了日志行但其中不含任何 sign_key 值；错误路径不回显密钥。
func TestSignKeysNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	logged := buf.String()
	if !strings.Contains(logged, "generated default config") {
		t.Fatalf("expected first-run log line, got %q", logged)
	}
	for name, km := range map[string]KeyMaterial{
		"session":      cfg.SignKey.Session,
		"login":        cfg.SignKey.Login,
		"ticket":       cfg.SignKey.Ticket,
		"cookie":       cfg.SignKey.Cookie,
		"sync_payload": cfg.SignKey.SyncPayload,
	} {
		if strings.Contains(logged, km.Key) {
			t.Errorf("sign key %q leaked into log output", name)
		}
	}
}
