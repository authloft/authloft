package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// testKeyB64 是 32 字节的 std base64 编码（合法 AES-256-GCM 密钥形态）。
var testKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA5}, 32))

// exampleKeyPlaceholder 必须与 configs/config.yaml.example 的密钥占位符逐字一致：
// example 同步测试靠它把占位符替换成真密钥后整份加载，验证示例与 Config schema 同步。
const exampleKeyPlaceholder = "<base64-32B，首次运行自动生成>"

// testValidYAML 是全字段齐全的合法配置模板；"<KEY>" 占位在加载前替换为
// testKeyB64，"<RSA_KEY>" 替换为 testOIDCKey（合法 OIDC 私钥）。
const testValidYAML = `
server: { listen: ":8080", min_tls_version: "", cert_file: "", key_file: "" }
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
oidc:
  jwt_keys:
    - kid: "1"
      private_key_pem: "<RSA_KEY>"
argon2: { time: 3, memory: 65536, threads: 4, key_len: 32 }
log: { level: info, format: json }
`

// testOIDCKey 返回一次现场生成并缓存的合法 OIDC 私钥
// （base64(PKCS#8 RSA 2048 PEM)），避免每个子用例重复生成 RSA 密钥。
func testOIDCKey() string {
	testOIDCKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			testOIDCKeyErr = err
			return
		}
		testOIDCKeyVal, testOIDCKeyErr = encodeOIDCKey(k)
	})
	if testOIDCKeyErr != nil {
		panic(testOIDCKeyErr)
	}
	return testOIDCKeyVal
}

var (
	testOIDCKeyOnce sync.Once
	testOIDCKeyVal  string
	testOIDCKeyErr  error
)

// encodeOIDCKey 把任意私钥编码为 base64(PKCS#8 PEM)（测试夹具）。
func encodeOIDCKey(key any) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// testECDSAKey 返回非 RSA 的 PKCS#8 私钥（base64 PEM），供「非 RSA」用例。
func testECDSAKey(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	s, err := encodeOIDCKey(k)
	if err != nil {
		t.Fatalf("encode ecdsa key: %v", err)
	}
	return s
}

// testRSAKeyBits 返回指定位数的 PKCS#8 RSA 私钥（base64 PEM），供「位数不足」用例。
func testRSAKeyBits(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate rsa-%d key: %v", bits, err)
	}
	s, err := encodeOIDCKey(k)
	if err != nil {
		t.Fatalf("encode rsa key: %v", err)
	}
	return s
}

// testPKCS1Key 返回 PKCS#1（"RSA PRIVATE KEY"）PEM 的 base64，供「非 PKCS#8」用例。
func testPKCS1Key(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	return base64.StdEncoding.EncodeToString(pemBytes)
}

// filledTestYAML 返回密钥已填充的合法 YAML 文本（loader 测试用）。
func filledTestYAML() string {
	s := strings.ReplaceAll(testValidYAML, "<RSA_KEY>", testOIDCKey())
	return strings.ReplaceAll(s, "<KEY>", testKeyB64)
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
	ecKey := testECDSAKey(t)
	smallKey := testRSAKeyBits(t, 1024)
	pkcs1Key := testPKCS1Key(t)
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"listen empty", func(c *Config) { c.Server.Listen = "" }, "server.listen"},
		{"listen bare port", func(c *Config) { c.Server.Listen = "8080" }, "server.listen"},
		{"listen port overflow", func(c *Config) { c.Server.Listen = ":70000" }, "server.listen"},
		{"listen port non numeric", func(c *Config) { c.Server.Listen = ":http" }, "server.listen"},
		{"min_tls_version bogus", func(c *Config) { c.Server.MinTLSVersion = "1.1" }, "server.min_tls_version"},
		{"cert without key", func(c *Config) { c.Server.CertFile = "cert.pem" }, "server.cert_file"},
		{"key without cert", func(c *Config) { c.Server.KeyFile = "key.pem" }, "server.cert_file"},
		{"cert not readable", func(c *Config) {
			c.Server.CertFile = "no-such-cert.pem"
			c.Server.KeyFile = "no-such-key.pem"
		}, "server.cert_file"},

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
		{"root other scheme", func(c *Config) { c.Authloft.Root = "ftp://sso.example.com" }, "authloft.root"},
		{"root no host", func(c *Config) { c.Authloft.Root = "https://" }, "authloft.root"},
		{"root not url", func(c *Config) { c.Authloft.Root = "sso.example.com" }, "authloft.root"},
		{"rp_id empty", func(c *Config) { c.Authloft.RpID = "" }, "authloft.rp_id"},

		{"key empty", func(c *Config) { c.SignKey.Session.Key = "" }, "sign_key.session.key"},
		{"key not base64", func(c *Config) { c.SignKey.Session.Key = "!!!not-base64!!!" }, "sign_key.session.key"},
		{"key wrong length", func(c *Config) { c.SignKey.Ticket.Key = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)) }, "sign_key.ticket.key"},
		{"kid zero", func(c *Config) { c.SignKey.Cookie.Kid = 0 }, "sign_key.cookie.kid"},
		{"kid negative", func(c *Config) { c.SignKey.SyncPayload.Kid = -1 }, "sign_key.sync_payload.kid"},

		{"oidc keys missing", func(c *Config) { c.OIDC.JWTKeys = nil }, "oidc.jwt_keys"},
		{"oidc keys empty", func(c *Config) { c.OIDC.JWTKeys = []OIDCKey{} }, "oidc.jwt_keys"},
		{"oidc kid empty", func(c *Config) { c.OIDC.JWTKeys[0].Kid = "" }, "oidc.jwt_keys[0].kid"},
		{"oidc kid duplicate", func(c *Config) { c.OIDC.JWTKeys = append(c.OIDC.JWTKeys, c.OIDC.JWTKeys[0]) }, "oidc.jwt_keys[1].kid"},
		{"oidc key empty", func(c *Config) { c.OIDC.JWTKeys[0].PrivateKeyPEM = "" }, "oidc.jwt_keys[0].private_key_pem"},
		{"oidc key not base64", func(c *Config) { c.OIDC.JWTKeys[0].PrivateKeyPEM = "!!!not-base64!!!" }, "oidc.jwt_keys[0].private_key_pem"},
		{"oidc key not PEM", func(c *Config) {
			c.OIDC.JWTKeys[0].PrivateKeyPEM = base64.StdEncoding.EncodeToString([]byte("not a pem"))
		}, "oidc.jwt_keys[0].private_key_pem"},
		{"oidc key not PKCS8", func(c *Config) { c.OIDC.JWTKeys[0].PrivateKeyPEM = pkcs1Key }, "oidc.jwt_keys[0].private_key_pem"},
		{"oidc key not RSA", func(c *Config) { c.OIDC.JWTKeys[0].PrivateKeyPEM = ecKey }, "oidc.jwt_keys[0].private_key_pem"},
		{"oidc key too small", func(c *Config) { c.OIDC.JWTKeys[0].PrivateKeyPEM = smallKey }, "oidc.jwt_keys[0].private_key_pem"},

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

// TestValidateRootHTTPAccepted root 允许 http://（§3.2 约定 7 /
// 接口文档 §1.1 行 76「明文 HTTP 部署为一等公民」）：http 与 https 均通过
// Validate，其他 scheme 仍拒绝——既有校验（可解析 URL + host 非空）零回归。
func TestValidateRootHTTPAccepted(t *testing.T) {
	for _, root := range []string{
		"http://sso.example.com",     // 明文 HTTP 一等公民（内网/测试/反代 TLS 终止）
		"https://sso.example.com",    // 既有 HTTPS 形态零回归
		"http://sso.example.com:8080",// 带端口明文
	} {
		c := validTestConfig(t)
		c.Authloft.Root = root
		if err := c.Validate(); err != nil {
			t.Errorf("root %q 应通过 Validate（http 为一等公民）, got %v", root, err)
		}
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

// TestValidateCertPairReadable cert/key 成对且可读时通过（§3.2 约定 5 的
// 正面路径：单边 / 不可读 fail-fast 的反向用例）。
func TestValidateCertPairReadable(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := validTestConfig(t)
	c.Server.CertFile = certPath
	c.Server.KeyFile = keyPath
	c.Server.MinTLSVersion = "1.3"
	if err := c.Validate(); err != nil {
		t.Errorf("readable pairwise cert/key with valid min must pass, got %v", err)
	}

	// 目录不可用（路径可 open 但 IsDir）。
	c.Server.CertFile = dir
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "server.cert_file") {
		t.Errorf("directory as cert_file must fail, got %v", err)
	}
}

// TestConfigureHTTPServerListenModes 监听口径映射（§3.1 行 244-245，
// 生产 bootstrap 与 setup 共用）：
//   - 未配 cert+key：Protocols = HTTP/1.1 + H2C、TLSConfig nil（min 不生效）；
//   - 已配：Protocols = HTTP/1.1 + H2(TLS)、TLSConfig.MinVersion 按
//     min_tls_version（"1.2"/"1.3"/空）；非法取值 fail-fast。
func TestConfigureHTTPServerListenModes(t *testing.T) {
	newSrv := func(sc ServerConfig) *http.Server {
		srv := &http.Server{}
		if err := sc.ConfigureHTTPServer(srv); err != nil {
			t.Fatalf("ConfigureHTTPServer: %v", err)
		}
		return srv
	}

	// h2c：min_tls_version 非法取值也应在 Validate 拦（本函数不重复校验、
	// 不生效即不报错——映射层只看 cert/key）。
	srv := newSrv(ServerConfig{Listen: ":8080", MinTLSVersion: "1.3"})
	if srv.Addr != ":8080" {
		t.Errorf("Addr = %q, want :8080", srv.Addr)
	}
	if !srv.Protocols.HTTP1() || !srv.Protocols.UnencryptedHTTP2() || srv.Protocols.HTTP2() {
		t.Errorf("h2c: Protocols = HTTP1:%v UH2:%v H2:%v, want true/true/false", srv.Protocols.HTTP1(), srv.Protocols.UnencryptedHTTP2(), srv.Protocols.HTTP2())
	}
	if srv.TLSConfig != nil {
		t.Errorf("h2c: TLSConfig = %+v, want nil (min_tls_version 不生效)", srv.TLSConfig)
	}

	// TLS + min 1.3。
	srv = newSrv(ServerConfig{Listen: ":8443", MinTLSVersion: "1.3", CertFile: "c.pem", KeyFile: "k.pem"})
	if !srv.Protocols.HTTP1() || !srv.Protocols.HTTP2() || srv.Protocols.UnencryptedHTTP2() {
		t.Errorf("tls: Protocols = HTTP1:%v H2:%v UH2:%v, want true/true/false", srv.Protocols.HTTP1(), srv.Protocols.HTTP2(), srv.Protocols.UnencryptedHTTP2())
	}
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("tls 1.3: TLSConfig.MinVersion = %v, want VersionTLS13", srv.TLSConfig)
	}

	// TLS + min 1.2。
	srv = newSrv(ServerConfig{Listen: ":8443", MinTLSVersion: "1.2", CertFile: "c.pem", KeyFile: "k.pem"})
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("tls 1.2: TLSConfig.MinVersion = %v, want VersionTLS12", srv.TLSConfig)
	}

	// TLS + min 空：标准库默认（TLSConfig nil）。
	srv = newSrv(ServerConfig{Listen: ":8443", CertFile: "c.pem", KeyFile: "k.pem"})
	if srv.TLSConfig != nil {
		t.Errorf("tls default min: TLSConfig = %+v, want nil", srv.TLSConfig)
	}

	// 单边 cert：不启用 TLS（h2c 形态——Validate 会另行拦）。
	srv = newSrv(ServerConfig{Listen: ":8080", CertFile: "c.pem"})
	if !srv.Protocols.UnencryptedHTTP2() || srv.Protocols.HTTP2() {
		t.Errorf("single-side cert: Protocols must stay h2c (pairing enforced by Validate), got %s", srv.Protocols)
	}

	// 非法 min + TLS：fail-fast。
	if err := (ServerConfig{MinTLSVersion: "bogus", CertFile: "c.pem", KeyFile: "k.pem"}).ConfigureHTTPServer(&http.Server{}); err == nil {
		t.Error("bogus min_tls_version with TLS must fail-fast")
	}
}

// TestValidateListenForms server.listen 新口径：支持 :port、
// IPv4:port、[IPv6]:port；非法形态（缺端口、裸 IPv6 无方括号、端口越界 /
// 非数字）一律 fail-fast，不静默回落默认值。
func TestValidateListenForms(t *testing.T) {
	valid := []string{
		":8080",
		"0.0.0.0:8080",
		"127.0.0.1:8080",
		"[::1]:8080",
		"[::]:8080",
		"192.0.2.1:65535",
	}
	for _, in := range valid {
		c := validTestConfig(t)
		c.Server.Listen = in
		if err := c.Validate(); err != nil {
			t.Errorf("listen %q: want valid, got %v", in, err)
		}
	}

	invalid := []struct {
		in      string
		wantErr string
	}{
		{"", "server.listen: required"},
		{"8080", "want [host:]port"},
		{":http", "port"},
		{":70000", "out of range"},
		{":0", "out of range"},
		{"127.0.0.1", "want [host:]port"},
		{"127.0.0.1:", "missing port"},
		{"::1:8080", "IPv6 must be"},
		{"fe80::1:8080", "IPv6 must be"},
	}
	for _, tc := range invalid {
		c := validTestConfig(t)
		c.Server.Listen = tc.in
		err := c.Validate()
		if err == nil {
			t.Errorf("listen %q: want error containing %q, got nil", tc.in, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("listen %q: err = %v, want containing %q", tc.in, err, tc.wantErr)
		}
	}
}

// TestListenRealAddress 启动日志打印真实监听地址：net.Listen
// 落到 0.0.0.0 还是 [::] 由 OS 决定，只断言地址族与端口可解析、IPv6 输出
// 带方括号。端口取 0（随机）避免占用。
func TestListenRealAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Skipf("listen %q skipped (IPv6 不可用或环境限制): %v", addr, err)
		}
		got := ln.Addr().String()
		host, port, perr := net.SplitHostPort(got)
		if perr != nil {
			t.Fatalf("%s: Addr()=%q not host:port: %v", addr, got, perr)
		}
		if port == "0" || port == "" {
			t.Errorf("%s: port = %q, want real assigned port", addr, port)
		}
		if strings.Contains(addr, "[") {
			if host == "" || !strings.Contains(got, "[") {
				t.Errorf("%s: IPv6 Addr()=%q must bracket the host", addr, got)
			}
		}
		_ = ln.Close()
	}
}
