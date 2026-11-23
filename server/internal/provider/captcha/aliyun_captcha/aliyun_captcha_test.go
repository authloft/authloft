// aliyun_captcha_test.go 覆盖 aliyun_captcha 子包装配与校验全链路：注册表
// 注册（meta / Schema 差异字段 / CSP 登记）、RPC 请求构造（Action / Version /
// 公共参数 / CaptchaVerifyParam 原样透传 / SceneId 服务端下发）、签名复用
// 公共包在假端点独立重算验签（伪造签名过不去）、判定顺序 Success / Code /
// Result.VerifyResult 的成功与全部拒绝路径、构造期 fail-fast 与地域 endpoint
// 映射。httptest 假端点，不打真实服务；一律 fail-closed 的边界随用例固化。
package aliyun_captcha

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/aliyunrpc"
)

// passBody 厂商成功响应（Code=Success + Result.VerifyResult=true）。
const passBody = `{"RequestId":"req-1","Success":true,"Code":"Success","Message":"ok","Result":{"VerifyResult":true,"VerifyCode":"T001","CertifyID":"c-1"}}`

// fakeAliyun 假阿里云验证码端点：断言请求形态（POST / form 编码 / RPC 公共
// 参数齐 / CaptchaVerifyParam 与期望逐字节一致 / SceneId 为服务端配置值）并
// 用公共包独立重算签名验签——签名不符时按厂商语义回 API 级失败并记
// mismatch 标记（客户端签名链路可证伪）；响应体按用例切换。
type fakeAliyun struct {
	server   *httptest.Server
	secret   string
	token    string
	sceneID  string
	body     string
	status   int
	hits     int
	mismatch bool
	nonces   map[string]bool // 每次命中的 SignatureNonce（防重放唯一性取证）
}

func newFake(t *testing.T, secret, token, sceneID string) *fakeAliyun {
	t.Helper()
	f := &fakeAliyun{secret: secret, token: token, sceneID: sceneID, status: http.StatusOK, nonces: make(map[string]bool)}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits++
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want form-urlencoded", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		form := r.PostForm
		f.nonces[form.Get("SignatureNonce")] = true
		// RPC 公共参数与业务参数齐备（缺任一即厂商侧签名/参数错误）。
		for _, k := range []string{"Action", "Version", "AccessKeyId", "SignatureMethod",
			"SignatureVersion", "SignatureNonce", "Timestamp", "CaptchaVerifyParam", "SceneId"} {
			if form.Get(k) == "" {
				t.Errorf("form 缺公共/业务参数 %s", k)
			}
		}
		if form.Get("Action") != apiAction {
			t.Errorf("Action = %q, want %q", form.Get("Action"), apiAction)
		}
		if form.Get("Version") != apiVersion {
			t.Errorf("Version = %q, want %q（参与签名规范化，错值即 InvalidSignature）", form.Get("Version"), apiVersion)
		}
		if form.Get("SignatureMethod") != "HMAC-SHA1" || form.Get("SignatureVersion") != "1.0" {
			t.Errorf("签名声明 = %s/%s, want HMAC-SHA1/1.0", form.Get("SignatureMethod"), form.Get("SignatureVersion"))
		}
		if _, err := time.Parse("2006-01-02T15:04:05Z", form.Get("Timestamp")); err != nil {
			t.Errorf("Timestamp %q 非 UTC ISO8601: %v", form.Get("Timestamp"), err)
		}
		// captchaVerifyParam 原样透传：逐字节一致（V2 JSON 字符串含引号 /
		// unicode / 保留字，重组即破坏）。
		if got := form.Get("CaptchaVerifyParam"); got != f.token {
			t.Errorf("CaptchaVerifyParam 透传变形：got %q want %q", got, f.token)
		}
		// SceneId 来自服务端配置（Ext），不随 token 提交防篡改。
		if got := form.Get("SceneId"); got != f.sceneID {
			t.Errorf("SceneId = %q, want 服务端配置值 %q", got, f.sceneID)
		}
		// 公共包独立重算 V1.0 签名验签：算法 / 规范化 / 密钥拼接任一处
		// 不符即可证伪。
		want := aliyunrpc.SignRPCForm(form, f.secret)
		if form.Get("Signature") != want {
			f.mismatch = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"RequestId":"req-1","Success":false,"Code":"SignatureDoesNotMatch","Message":"sig mismatch"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		body := f.body
		if body == "" {
			body = passBody
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.server.Close)
	return f
}

// tokenV2 V2 架构形态的 captchaVerifyParam（JSON 对象字符串，含引号 /
// unicode / 保留字符，任何解析重组都会变形）。
const tokenV2 = `{"sceneId":"场景-1","certifyId":"cert+123","deviceToken":"tok 100%/=?#&x","data":"sig"}`

func newProvider(endpoint string) *provider.Provider {
	return &provider.Provider{
		Key:  "aliyun_row",
		Type: Type,
		Ext: &providerpb.Ext{
			ClientId:      "scene-1",
			ClientSecret:  "ak-secret-1",
			AccessKeyId:   "LTAI-ak-id",
			Region:        "cn",
			Endpoint:      endpoint,
			Prefix:        "aliyun-",
			EncryptKey:    "ekey-1",
			WidgetOptions: `{"mode":"popup"}`,
		},
	}
}

// TestAliyunCaptchaRegistered 注册表断言（§15.3）：meta 缺位即 blank import
// 被删；Schema 差异字段（access_key_id / region / prefix / encrypt_key /
// widget_options，按接口文档 §5.3 行序）与 CSP 登记（connect-src 两地域
// 域名）随实现声明。
func TestAliyunCaptchaRegistered(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("注册表缺 type %q——init 自注册未生效", Type)
	}
	if meta.Category != provider.CategoryCaptcha {
		t.Fatalf("category = %q, want %q", meta.Category, provider.CategoryCaptcha)
	}
	if meta.Schema == nil {
		t.Fatal("Schema 未声明（/schema 唯一数据源不得为空）")
	}
	fields := meta.Schema()
	got := make(map[string]provider.FieldMeta, len(fields))
	order := make([]string, 0, len(fields))
	for _, f := range fields {
		if _, dup := got[f.Key]; dup {
			t.Fatalf("字段 %q 重复声明", f.Key)
		}
		got[f.Key] = f
		order = append(order, f.Key)
	}
	wantOrder := []string{
		"provider_key", "display_name",
		"client_id", "access_key_id", "client_secret", "region", "prefix", "encrypt_key", "endpoint", "widget_options",
		"icon_url", "sort_order", "remark", "proxy_provider_key",
	}
	if len(order) != len(wantOrder) {
		t.Fatalf("字段数 = %d (%v), want %d", len(order), order, len(wantOrder))
	}
	for i, w := range wantOrder {
		if order[i] != w {
			t.Fatalf("字段序 = %v, want %v（Ext 按 §5.3 aliyun_captcha 行序）", order, wantOrder)
		}
	}
	aki := got["access_key_id"]
	if aki.Type != "text" || !aki.Required || aki.Section != "credential" || aki.Storage != provider.StorageExt {
		t.Errorf("access_key_id = %+v, want text 必填 credential 落 Ext", aki)
	}
	region := got["region"]
	if region.Type != "select" || !region.Required || region.Default != "cn" ||
		strings.Join(region.Options, ",") != "cn,sgp,ga" || region.Storage != provider.StorageExt {
		t.Errorf("region = %+v, want select 必填 cn/sgp/ga default cn 落 Ext", region)
	}
	ek := got["encrypt_key"]
	if ek.Type != "secret" || ek.Required || !ek.Advanced || ek.Storage != provider.StorageExt {
		t.Errorf("encrypt_key = %+v, want secret 可选 advanced 落 Ext", ek)
	}
	if got["prefix"].Required || got["endpoint"].Required || !got["endpoint"].Advanced {
		t.Errorf("prefix/endpoint 应可选且 endpoint advanced: %+v / %+v", got["prefix"], got["endpoint"])
	}
	wo := got["widget_options"]
	if wo.Required || !wo.Advanced || wo.Storage != provider.StorageExt {
		t.Errorf("widget_options = %+v, want 可选 advanced 落 Ext", wo)
	}
	if _, ok := got["is_enabled"]; ok {
		t.Error("is_enabled 是 auth 专属开关，captcha 类别不得声明")
	}
	src := meta.CSPSources["connect-src"]
	if len(src) != len(browserConnectSrc) {
		t.Errorf("connect-src 数量 = %d, want %d", len(src), len(browserConnectSrc))
	}
	for i, want := range browserConnectSrc {
		if i >= len(src) || src[i] != want {
			t.Errorf("connect-src[%d] = %v, want %s", i, src, want)
			break
		}
	}
	for _, serverOnly := range []string{endpointCN, endpointSGP, endpointGA} {
		for _, got := range src {
			if got == serverOnly {
				t.Errorf("connect-src 含服务端 RPC endpoint %s（不经浏览器，不应登记）", serverOnly)
			}
		}
	}
	if meta.CSPSourcesOf == nil {
		t.Error("CSPSourcesOf 应声明（身份标子域按行派生）")
	}
	if _, ok := meta.CSPSources["frame-src"]; ok {
		t.Error("frame-src 不应声明（弹层为 DOM 渲染无固定 iframe 域）")
	}
}

// TestCSPSourcesOf 按行派生身份标子域：合法 prefix 派生 connect-src，
// 空 / 非法（防注入）返回 nil 不贡献源。
func TestCSPSourcesOf(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, want string
	}{
		{"合法", "abc123", "https://abc123.captcha-open.aliyuncs.com"},
		{"连字符下划线", "ab-c_1", "https://ab-c_1.captcha-open.aliyuncs.com"},
		{"空", "", ""},
		{"含点", "bad.example", ""},
		{"含路径", "bad/path", ""},
		{"含协议", "https://evil", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cspSourcesOf(&provider.Provider{Ext: &providerpb.Ext{Prefix: tc.prefix}})
			if tc.want == "" {
				if got != nil {
					t.Fatalf("cspSourcesOf = %v, want nil", got)
				}
				return
			}
			if len(got["connect-src"]) != 1 || got["connect-src"][0] != tc.want {
				t.Fatalf("cspSourcesOf = %v, want connect-src [%s]", got, tc.want)
			}
		})
	}
	if got := cspSourcesOf(nil); got != nil {
		t.Errorf("cspSourcesOf(nil) = %v, want nil", got)
	}
}

// TestVerifySuccessChain 真实 factory 分派（provider.NewVerifier）下的成功
// 链路：V2 形态 token 原样透传 → 假端点公共参数 / SceneId / 独立重算签名
// 全部通过 → Success + VerifyResult=true 返回 nil。
func TestVerifySuccessChain(t *testing.T) {
	f := newFake(t, "ak-secret-1", tokenV2, "scene-1")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: tokenV2}); err != nil {
		t.Fatalf("VerifyResult=true = %v, want nil", err)
	}
	if f.hits != 1 || f.mismatch {
		t.Fatalf("hits=%d mismatch=%v, want 1 次且验签通过", f.hits, f.mismatch)
	}
}

// TestV3TokenPassthrough V3 架构形态（紧凑字符串）同样原样透传——两种
// 形态都不解析不重组（接口文档 §2.5）。
func TestV3TokenPassthrough(t *testing.T) {
	const tokenV3 = "AAAAmQI0/v3_base64-like+string/with=="
	f := newFake(t, "ak-secret-1", tokenV3, "scene-1")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: tokenV3}); err != nil {
		t.Fatalf("V3 紧凑串透传 = %v, want nil", err)
	}
	if f.hits != 1 || f.mismatch {
		t.Fatalf("hits=%d mismatch=%v, want 1 次且验签通过", f.hits, f.mismatch)
	}
}

// TestEmptyTokenFailClosed 空 token 直接拒绝且零外呼（同各家 captcha 口径）。
func TestEmptyTokenFailClosed(t *testing.T) {
	f := newFake(t, "ak-secret-1", tokenV2, "scene-1")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	err = v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: ""})
	if !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("空 token = %v, want ErrInvalid", err)
	}
	if f.hits != 0 {
		t.Fatalf("空 token 不应外呼, hits = %d", f.hits)
	}
}

// TestJudgeFailPaths 厂商响应判定 fail-closed（卡契约：Code 非零 /
// Success=false / VerifyResult=false → 拒绝；HTTP 错 / JSON 损坏 → 基础设施
// 错误同样不放行——本实现无 fail-open 路径，厂商不可用边界的失败也在此
// 固化）。Code 空省略（部分成功响应形态）不得误拒。
func TestJudgeFailPaths(t *testing.T) {
	f := newFake(t, "ak-secret-1", tokenV2, "scene-1")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	cases := []struct {
		name string
		body string
	}{
		{"API 级失败 Code=Throttling", `{"Success":false,"Code":"Throttling","Message":"qps"}`},
		{"Success=false 无 Code", `{"Success":false,"Code":"","Message":"err"}`},
		{"限流容灾取值 VerifyResult=false", `{"Success":true,"Code":"Success","Result":{"VerifyResult":false,"VerifyCode":"T002"}}`},
		{"疑似攻击 VerifyResult=false", `{"Success":true,"Code":"Success","Result":{"VerifyResult":false,"VerifyCode":"F001"}}`},
		{"Code 非 Success 拒绝", `{"Success":true,"Code":"WeirdCode","Result":{"VerifyResult":true}}`},
	}
	for _, tc := range cases {
		f.body = tc.body
		err := v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: tokenV2})
		if !errors.Is(err, provider.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid（fail-closed）", tc.name, err)
		}
	}

	// Code 省略但 Success + VerifyResult=true：不得因 Code 空而误拒。
	f.body = `{"Success":true,"Result":{"VerifyResult":true}}`
	if err := v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: tokenV2}); err != nil {
		t.Errorf("Code 省略的成功响应 = %v, want nil", err)
	}

	// 基础设施错误：HTTP 非 200 / JSON 损坏 / 连接失败——不映射
	// captcha_invalid，但同样不放行（fail-closed 边界固化）。
	f.body = ""
	f.status = http.StatusInternalServerError
	err = v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: tokenV2})
	if err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Errorf("HTTP 500 = %v, want infra error（不放行、不映射 captcha_invalid）", err)
	}
	f.status = http.StatusOK
	f.body = "not-json"
	err = v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: tokenV2})
	if err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Errorf("响应坏 JSON = %v, want infra error", err)
	}
	f.body = ""
	f.server.Close() // 连接失败 = 厂商不可用，仍不放行
	err = v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: tokenV2})
	if err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Errorf("厂商不可用 = %v, want infra error（无 fail-open 路径）", err)
	}
}

// TestSignatureMismatchRejected 证伪闭环：假端点改持错误 secret 独立重算，
// 客户端签名与之不符时假端点按厂商语义回 SignatureDoesNotMatch、客户端判
// ErrInvalid——签名真的被服务端校验，伪造 RPC 请求过不去。
func TestSignatureMismatchRejected(t *testing.T) {
	f := newFake(t, "deliberately-wrong-secret", tokenV2, "scene-1")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: tokenV2}); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("签名与服务端重算不符 = %v, want ErrInvalid", err)
	}
	if f.hits != 1 || !f.mismatch {
		t.Fatalf("hits=%d mismatch=%v, want 1 次且确有签名不符", f.hits, f.mismatch)
	}
}

// TestNonceUnique 防重放随机数每次验证都不同（公共包 NewNonce 语义）。
func TestNonceUnique(t *testing.T) {
	f := newFake(t, "ak-secret-1", tokenV2, "scene-1")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := v.Verify(context.Background(), "aliyun_row", provider.Submission{Token: tokenV2}); err != nil {
			t.Fatalf("第 %d 次 Verify: %v", i+1, err)
		}
	}
	if len(f.nonces) != 3 {
		t.Errorf("3 次验证 SignatureNonce 去重后 = %d, want 3（防重放随机数须唯一）", len(f.nonces))
	}
}

// TestNewVerifierFailFast 构造期 fail-fast：nil provider / nil ext / 缺
// client_id(SceneId) / 缺 access_key_id / 缺 client_secret / 未知 region /
// endpoint 非法 URL 均构造失败；region 空回落 cn、sgp 映射新加坡地域、
// ga 映射全球加速 endpoint，endpoint 覆盖时跳过地域映射。
func TestNewVerifierFailFast(t *testing.T) {
	if _, err := provider.NewVerifier(nil); err == nil {
		t.Fatal("nil provider 应构造失败")
	}
	if _, err := provider.NewVerifier(&provider.Provider{Key: "r", Type: Type}); err == nil {
		t.Fatal("nil ext 应构造失败")
	}
	base := func(mut func(e *providerpb.Ext)) *provider.Provider {
		e := &providerpb.Ext{ClientId: "scene-1", ClientSecret: "k", AccessKeyId: "ak"}
		mut(e)
		return &provider.Provider{Key: "r", Type: Type, Ext: e}
	}
	cases := []struct {
		name string
		p    *provider.Provider
	}{
		{"缺 client_id", base(func(e *providerpb.Ext) { e.ClientId = "" })},
		{"缺 access_key_id", base(func(e *providerpb.Ext) { e.AccessKeyId = "" })},
		{"缺 client_secret", base(func(e *providerpb.Ext) { e.ClientSecret = "" })},
		{"未知 region", base(func(e *providerpb.Ext) { e.Region = "eu-central" })},
		{"endpoint 非法", base(func(e *providerpb.Ext) { e.Endpoint = "://bad" })},
	}
	for _, tc := range cases {
		if _, err := provider.NewVerifier(tc.p); err == nil {
			t.Errorf("%s: 应构造失败", tc.name)
		}
	}

	// region 空 = 默认 cn（§15.5 default cn）。
	v, err := newVerifier(&provider.Provider{Key: "r", Type: Type, Ext: &providerpb.Ext{
		ClientId: "s", ClientSecret: "k", AccessKeyId: "ak",
	}})
	if err != nil {
		t.Fatalf("region 空: %v", err)
	}
	impl, ok := v.(*Verifier)
	if !ok {
		t.Fatalf("newVerifier 产物 = %T, want *Verifier", v)
	}
	if impl.verifyURL != endpointCN {
		t.Errorf("region 空 endpoint = %q, want %q", impl.verifyURL, endpointCN)
	}

	// region=sgp 映射新加坡地域 endpoint。
	v, err = newVerifier(&provider.Provider{Key: "r", Type: Type, Ext: &providerpb.Ext{
		ClientId: "s", ClientSecret: "k", AccessKeyId: "ak", Region: "sgp",
	}})
	if err != nil {
		t.Fatalf("region=sgp: %v", err)
	}
	if impl = v.(*Verifier); impl.verifyURL != endpointSGP {
		t.Errorf("region=sgp endpoint = %q, want %q", impl.verifyURL, endpointSGP)
	}

	// region=ga 映射全球加速 endpoint（就近接入，流量最终路由新加坡）。
	if got, ok := regionEndpoint("ga"); !ok || got != endpointGA {
		t.Errorf("regionEndpoint(ga) = %q, %v, want %q, true", got, ok, endpointGA)
	}
	v, err = newVerifier(&provider.Provider{Key: "r", Type: Type, Ext: &providerpb.Ext{
		ClientId: "s", ClientSecret: "k", AccessKeyId: "ak", Region: "ga",
	}})
	if err != nil {
		t.Fatalf("region=ga: %v", err)
	}
	if impl = v.(*Verifier); impl.verifyURL != endpointGA {
		t.Errorf("region=ga endpoint = %q, want %q", impl.verifyURL, endpointGA)
	}

	// endpoint 覆盖优先于地域映射（自定义网关场景）。
	const custom = "https://captcha-gw.example.com/rpc"
	v, err = newVerifier(&provider.Provider{Key: "r", Type: Type, Ext: &providerpb.Ext{
		ClientId: "s", ClientSecret: "k", AccessKeyId: "ak", Region: "sgp", Endpoint: custom,
	}})
	if err != nil {
		t.Fatalf("endpoint 覆盖: %v", err)
	}
	if impl = v.(*Verifier); impl.verifyURL != custom {
		t.Errorf("endpoint 覆盖 = %q, want %q", impl.verifyURL, custom)
	}
}

// TestVerifyRequestContext 上下文取消即中止外呼（基础行为，防运行期悬挂）。
func TestVerifyRequestContext(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	t.Cleanup(func() { close(block); srv.Close() })
	v, err := provider.NewVerifier(newProvider(srv.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.Verify(ctx, "aliyun_row", provider.Submission{Token: tokenV2}); err == nil {
		t.Fatal("ctx 已取消 = nil, want 错误")
	}
}
