package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
server: { listen: ":8080", min_tls_version: "", cert_file: "", key_file: "" }
db:
  dsn: "authloft:pass@tcp(127.0.0.1:3306)/authloft"
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 1h
redis: { addr: "127.0.0.1:6379", password: "", db: 0, pool_size: 50 }
authloft: { root: "https://sso.example.com", rp_id: "sso.example.com", rp_display_name: "Authloft" }
sign_key:
  session: { key: "<KEY>", kid: 1 }
argon2: { time: 3, memory: 65536, threads: 4, key_len: 32 }
log: { level: info, format: text }
`

// TestLoadMissingFileReturnsErrNotExist 文件不存在（已移除首启自动生成
// 路径后的新语义，§3.15 安装决策）：返回可被 errors.Is 判定的 ErrNotExist
// （供 bootstrap 转 setup 模式），且不创建文件、不生成任何内容。
func TestLoadMissingFileReturnsErrNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("missing file must fail, got nil")
	}
	if !errors.Is(err, ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ErrNotExist must chain fs.ErrNotExist, got %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("Load must not create the file, stat = %v", statErr)
	}
}

// TestDefaultConfigValidAndKeysIndependent DefaultConfig（安装流程的默认值
// 来源，§3.15 writer.go）：整体通过 Validate；sign_key 五场景独立、解码 32
// 字节、kid=1；两次调用生成不同密钥（每次现场随机）。
func TestDefaultConfigValidAndKeysIndependent(t *testing.T) {
	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("default config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config must pass Validate: %v", err)
	}
	seen := make(map[string]bool, 5)
	for name, km := range map[string]KeyMaterial{
		"session":      cfg.SignKey.Session,
		"login":        cfg.SignKey.Login,
		"ticket":       cfg.SignKey.Ticket,
		"cookie":       cfg.SignKey.Cookie,
		"sync_payload": cfg.SignKey.SyncPayload,
	} {
		raw, err := base64.StdEncoding.DecodeString(km.Key)
		if err != nil {
			t.Errorf("%s key: invalid base64: %v", name, err)
			continue
		}
		if len(raw) != 32 {
			t.Errorf("%s key: decodes to %d bytes, want 32", name, len(raw))
		}
		if km.Kid != 1 {
			t.Errorf("%s kid = %d, want 1", name, km.Kid)
		}
		if seen[km.Key] {
			t.Errorf("duplicated %s key; five scenarios must be independent keys", name)
		}
		seen[km.Key] = true
	}
	other, err := DefaultConfig()
	if err != nil {
		t.Fatalf("second default config: %v", err)
	}
	if other.SignKey.Session.Key == cfg.SignKey.Session.Key {
		t.Error("two DefaultConfig calls must generate independent keys")
	}
}

// TestLoadEnvOverridesFileValues 环境变量优先于文件值（§3.2 职责表）：
// 字符串 / 整数 / 时长 / kid / 密钥各验一条。
func TestLoadEnvOverridesFileValues(t *testing.T) {
	path := writeConfigFile(t, filledTestYAML())
	envKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xC3}, 32))
	t.Setenv("AUTHLOFT_DB_DSN", "env:secret@tcp(db-env:3306)/authloft")
	t.Setenv("AUTHLOFT_REDIS_ADDR", "redis-env:6379")
	t.Setenv("AUTHLOFT_SERVER_MIN_TLS_VERSION", "1.3")
	t.Setenv("AUTHLOFT_REDIS_DB", "7")
	t.Setenv("AUTHLOFT_SIGN_KEY_SESSION_KID", "2")
	t.Setenv("AUTHLOFT_SIGN_KEY_TICKET_KEY", envKey)
	t.Setenv("AUTHLOFT_AUTHLOFT_RP_DISPLAY_NAME", "Env Corp SSO")

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
	if cfg.Server.MinTLSVersion != "1.3" {
		t.Errorf("min_tls_version = %q, want \"1.3\" from env", cfg.Server.MinTLSVersion)
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
	if cfg.Authloft.RPDisplayName != "Env Corp SSO" {
		t.Errorf("rp_display_name = %q, want env value", cfg.Authloft.RPDisplayName)
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
	t.Setenv("AUTHLOFT_DB_CONN_MAX_LIFETIME", "soon")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "AUTHLOFT_DB_CONN_MAX_LIFETIME") {
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
server: { listen: ":8080", min_tls_version: "", cert_file: "", key_file: "" }
redis: { addr: "127.0.0.1:6379", password: "", db: 0, pool_size: 50 }
authloft: { root: "https://sso.example.com", rp_id: "sso.example.com", rp_display_name: "Authloft" }
sign_key:
  session:      { key: "<KEY>", kid: 1 }
  login:        { key: "<KEY>", kid: 1 }
  ticket:       { key: "<KEY>", kid: 1 }
  cookie:       { key: "<KEY>", kid: 1 }
  sync_payload: { key: "<KEY>", kid: 1 }
argon2: { time: 3, memory: 65536, threads: 4, key_len: 32 }
log: { level: info, format: text }
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

// TestLoadBareNumberDurationFails 时长写裸数字（30 而非 30h）→ 解析期 fail-fast。
func TestLoadBareNumberDurationFails(t *testing.T) {
	bad := strings.Replace(filledTestYAML(), "conn_max_lifetime: 1h", "conn_max_lifetime: 30", 1)
	path := writeConfigFile(t, bad)
	_, err := Load(path)
	if err == nil {
		t.Error("want fail-fast on bare-number duration, got nil")
	}
}

// TestDefaultServerConfig setup 模式的 server 段取值（§3.1 行 247 / §3.15：
// 默认值 + env 覆盖、只读 server 段）：
//   - 无 env：listen 默认 ":8080"、TLS 字段空；
//   - 四条 server env 覆盖生效；
//   - 其他段 env（db 等）一概不读；
//   - 非法 listen / 非法 min_tls_version / 单边 cert → fail-fast。
func TestDefaultServerConfig(t *testing.T) {
	sc, err := DefaultServerConfig()
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if sc.Listen != ":8080" {
		t.Errorf("default listen = %q, want :8080", sc.Listen)
	}
	if sc.MinTLSVersion != "" || sc.CertFile != "" || sc.KeyFile != "" {
		t.Errorf("default TLS fields = %q/%q/%q, want all empty", sc.MinTLSVersion, sc.CertFile, sc.KeyFile)
	}

	t.Run("env overrides server section", func(t *testing.T) {
		// cert/key 成对且可读才能过校验（§3.2 约定 5）：用临时文件。
		dir := t.TempDir()
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AUTHLOFT_SERVER_LISTEN", ":19099")
		t.Setenv("AUTHLOFT_SERVER_MIN_TLS_VERSION", "1.3")
		t.Setenv("AUTHLOFT_SERVER_CERT_FILE", certPath)
		t.Setenv("AUTHLOFT_SERVER_KEY_FILE", keyPath)
		sc, err := DefaultServerConfig()
		if err != nil {
			t.Fatalf("env overrides: %v", err)
		}
		if sc.Listen != ":19099" || sc.MinTLSVersion != "1.3" || sc.CertFile != certPath || sc.KeyFile != keyPath {
			t.Errorf("server env not applied: %+v", sc)
		}
	})

	t.Run("ignores other section env", func(t *testing.T) {
		t.Setenv("AUTHLOFT_DB_DSN", "env:secret@tcp(db:3306)/authloft")
		t.Setenv("AUTHLOFT_REDIS_ADDR", "redis-env:6379")
		sc, err := DefaultServerConfig()
		if err != nil {
			t.Fatalf("other env must be ignored, got %v", err)
		}
		if sc.Listen != ":8080" {
			t.Errorf("server value polluted by other env: %+v", sc)
		}
	})

	t.Run("invalid listen fails fast", func(t *testing.T) {
		t.Setenv("AUTHLOFT_SERVER_LISTEN", "19099")
		if _, err := DefaultServerConfig(); err == nil || !strings.Contains(err.Error(), "server.listen") {
			t.Errorf("want fail-fast on bare-port listen, got %v", err)
		}
	})

	t.Run("invalid min_tls_version fails fast", func(t *testing.T) {
		t.Setenv("AUTHLOFT_SERVER_MIN_TLS_VERSION", "1.1")
		if _, err := DefaultServerConfig(); err == nil || !strings.Contains(err.Error(), "server.min_tls_version") {
			t.Errorf("want fail-fast on bogus min_tls_version, got %v", err)
		}
	})

	t.Run("single-side cert fails fast", func(t *testing.T) {
		t.Setenv("AUTHLOFT_SERVER_CERT_FILE", "cert.pem")
		if _, err := DefaultServerConfig(); err == nil || !strings.Contains(err.Error(), "server.cert_file") {
			t.Errorf("want fail-fast on single-side cert, got %v", err)
		}
	})
}

// TestLoadReadErrorFails 读错误（如路径是目录）原样失败，不得误判为首启语义
// （返回的错误不得链到 ErrNotExist——目录不是「文件不存在」）。
func TestLoadReadErrorFails(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Fatal("reading a directory must fail")
	}
	if errors.Is(err, ErrNotExist) {
		t.Errorf("directory read error must not chain ErrNotExist, got %v", err)
	}
}
