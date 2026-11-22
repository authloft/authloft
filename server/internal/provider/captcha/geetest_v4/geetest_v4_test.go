// geetest_v4_test.go 覆盖 geetest_v4 子包装配与校验全链路：注册表注册
// （meta / Schema 差异字段 / CSP 登记）、sign_token 签名（RFC 4231 已知
// 向量 + 假端点侧独立重算证伪）、token 四字段 JSON 解包 fail-closed、
// validate 判 result 的成功与全部拒绝路径。httptest 假端点，不打真实服务。
package geetest_v4

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
)

// TestSignTokenVector 已知向量证伪：RFC 4231 Test Case 2（key=Jefe）独立
// 外部算得（openssl dgst -sha256 -hmac），实现若改算法/编码/大小写必红；
// 另一测试向量锁 key=msg 组合，错 key 必不等。
func TestSignTokenVector(t *testing.T) {
	const rfc4231TC2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if got := signToken("Jefe", "what do ya want for nothing?"); got != rfc4231TC2 {
		t.Fatalf("signToken(Jefe) = %q, want RFC 4231 TC2 %q", got, rfc4231TC2)
	}
	const testVector = "ac17693007918d12841dced9dc61b4278b9d39e1f838b1cd00abb8a19c709b17"
	if got := signToken("captcha-key-1", "lot-123"); got != testVector {
		t.Fatalf("signToken(captcha-key-1, lot-123) = %q, want %q", got, testVector)
	}
	if got := signToken("captcha-key-1", "lot-123"); got != strings.ToLower(got) {
		t.Errorf("sign_token = %q, want hex 小写", got)
	}
	if signToken("captcha-key-1", "lot-123") == signToken("other-key", "lot-123") {
		t.Error("不同 captcha_key 签出同值，签名失效")
	}
}

// packToken 与前端 getValidate() 同构：四字段整体 JSON 序列化（§2.5）。
func packToken(lot, output, pass, gen string) string {
	b, _ := json.Marshal(map[string]string{
		"lot_number": lot, "captcha_output": output, "pass_token": pass, "gen_time": gen,
	})
	return string(b)
}

// fakeGeetest 假极验端点：断言请求形态（POST / form 编码 / query 带
// captcha_id / 五个 form 字段齐）并独立重算 sign_token 验签——签名不符时
// 以厂商语义回 status=error 并记 mismatch 标记（客户端签名错误可证伪）；
// result 按用例切换。
type fakeGeetest struct {
	server   *httptest.Server
	key      string
	result   string
	status   int
	body     string
	hits     int
	mismatch bool
}

func newFake(t *testing.T, key string) *fakeGeetest {
	t.Helper()
	f := &fakeGeetest{key: key, result: "success", status: http.StatusOK}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits++
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want form-urlencoded", ct)
		}
		if r.URL.Query().Get("captcha_id") == "" {
			t.Error("query 缺 captcha_id（厂商口径：captcha_id 放 URL query）")
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		lot := r.PostForm.Get("lot_number")
		for _, k := range []string{"captcha_output", "pass_token", "gen_time", "sign_token"} {
			if r.PostForm.Get(k) == "" {
				t.Errorf("form 缺 %s", k)
			}
		}
		mac := hmac.New(sha256.New, []byte(f.key))
		mac.Write([]byte(lot))
		if want := hex.EncodeToString(mac.Sum(nil)); r.PostForm.Get("sign_token") != want {
			f.mismatch = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"error","code":"-100","msg":"sign verification fail"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		body := f.body
		if body == "" {
			body = `{"status":"success","result":"` + f.result + `","reason":"","captcha_args":{}}`
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.server.Close)
	return f
}

func newProvider(endpoint string) *provider.Provider {
	return &provider.Provider{
		Key:  "gt_row",
		Type: Type,
		Ext:  &providerpb.Ext{ClientId: "cid-1", ClientSecret: "captcha-key-1", Endpoint: endpoint},
	}
}

// TestGeetestV4Registered 注册表断言（§15.3）：meta 缺位即 blank import 被
// 删；Schema 差异字段（widget_product 三选一 default bind、widget_options
// 可选 advanced）与 CSP 登记（frame-src / connect-src）随实现声明。
func TestGeetestV4Registered(t *testing.T) {
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
		"client_id", "client_secret", "endpoint", "widget_product", "widget_options",
		"icon_url", "sort_order", "remark", "proxy_provider_key",
	}
	if len(order) != len(wantOrder) {
		t.Fatalf("字段数 = %d (%v), want %d", len(order), order, len(wantOrder))
	}
	for i, w := range wantOrder {
		if order[i] != w {
			t.Fatalf("字段序 = %v, want %v（Ext 按 §15.5 geetest_v4 行序）", order, wantOrder)
		}
	}
	wp := got["widget_product"]
	if wp.Type != "select" || wp.Required || strings.Join(wp.Options, ",") != "bind,popup,float" || wp.Default != "bind" || wp.Storage != provider.StorageExt {
		t.Errorf("widget_product = %+v, want select bind/popup/float default bind 落 Ext", wp)
	}
	wo := got["widget_options"]
	if wo.Required || !wo.Advanced || wo.Storage != provider.StorageExt {
		t.Errorf("widget_options = %+v, want 可选 advanced 落 Ext", wo)
	}
	if got["endpoint"].Required || !got["endpoint"].Advanced {
		t.Errorf("endpoint = %+v, want 可选 advanced", got["endpoint"])
	}
	if _, ok := got["is_enabled"]; ok {
		t.Error("is_enabled 是 auth 专属开关，captcha 类别不得声明")
	}
	if src := meta.CSPSources["frame-src"]; len(src) != 1 || src[0] != "https://gcaptcha4.geetest.com" {
		t.Errorf("frame-src = %v, want [https://gcaptcha4.geetest.com]", src)
	}
	if src := meta.CSPSources["connect-src"]; len(src) != 1 || src[0] != "https://gcaptcha4.geetest.com" {
		t.Errorf("connect-src = %v, want [https://gcaptcha4.geetest.com]", src)
	}
}

// TestVerifySuccessChain 真实 factory 分派（provider.NewVerifier）下的成功
// 链路：合法四字段 token → 假端点验签通过（含 captcha_id query 断言）→
// result=success 返回 nil。
func TestVerifySuccessChain(t *testing.T) {
	f := newFake(t, "captcha-key-1")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := packToken("lot-123", "out-1", "pass-1", "1700000000")
	if err := v.Verify(context.Background(), "gt_row", provider.Submission{Token: tok}); err != nil {
		t.Fatalf("result=success = %v, want nil", err)
	}
	if f.hits != 1 || f.mismatch {
		t.Fatalf("hits=%d mismatch=%v, want 1 次且验签通过", f.hits, f.mismatch)
	}
}

// TestTokenUnpackFailClosed token 解包 fail-closed：空 token / 非法 JSON /
// 四字段缺任一 / 空串字段一律 ErrInvalid 且零请求（不发外呼）；多余字段
// 容忍（厂商 getValidate() 整体打包口径，不封死扩展）。
func TestTokenUnpackFailClosed(t *testing.T) {
	f := newFake(t, "captcha-key-1")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	cases := []struct {
		name  string
		token string
	}{
		{"空 token", ""},
		{"非法 JSON", "{not-json"},
		{"非 JSON 文本", "plain-token"},
		{"全空对象", "{}"},
		{"缺 lot_number", `{"captcha_output":"o","pass_token":"p","gen_time":"1"}`},
		{"缺 captcha_output", `{"lot_number":"l","pass_token":"p","gen_time":"1"}`},
		{"缺 pass_token", `{"lot_number":"l","captcha_output":"o","gen_time":"1"}`},
		{"缺 gen_time", `{"lot_number":"l","captcha_output":"o","pass_token":"p"}`},
		{"字段为空串", packToken("l", "o", "p", "")},
	}
	for _, tc := range cases {
		err := v.Verify(context.Background(), "gt_row", provider.Submission{Token: tc.token})
		if !errors.Is(err, provider.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", tc.name, err)
		}
	}
	if f.hits != 0 {
		t.Fatalf("解包失败不应外呼, hits = %d", f.hits)
	}
	tok := `{"lot_number":"l","captcha_output":"o","pass_token":"p","gen_time":"1","extra":"x"}`
	if err := v.Verify(context.Background(), "gt_row", provider.Submission{Token: tok}); err != nil {
		t.Errorf("带多余字段的 token = %v, want nil（容忍扩展）", err)
	}
}

// TestValidateResultFailPaths 厂商响应判定 fail-closed：result=fail /
// status=error（无 result）/ HTTP 500 / 响应 JSON 损坏各归其位——前两者
// ErrInvalid（校验不通过），后两者基础设施错误（不映射 captcha_invalid）。
func TestValidateResultFailPaths(t *testing.T) {
	f := newFake(t, "captcha-key-1")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := packToken("l", "o", "p", "1")

	f.result = "fail"
	if err := v.Verify(context.Background(), "gt_row", provider.Submission{Token: tok}); !errors.Is(err, provider.ErrInvalid) {
		t.Errorf("result=fail = %v, want ErrInvalid", err)
	}
	f.result = ""
	f.body = `{"status":"error","code":"-100","msg":"param error"}`
	if err := v.Verify(context.Background(), "gt_row", provider.Submission{Token: tok}); !errors.Is(err, provider.ErrInvalid) {
		t.Errorf("status=error = %v, want ErrInvalid", err)
	}
	f.status = http.StatusInternalServerError
	f.body = ""
	if err := v.Verify(context.Background(), "gt_row", provider.Submission{Token: tok}); err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Errorf("HTTP 500 = %v, want infra error", err)
	}
	f.status = http.StatusOK
	f.body = "not-json"
	if err := v.Verify(context.Background(), "gt_row", provider.Submission{Token: tok}); err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Errorf("响应坏 JSON = %v, want infra error", err)
	}
	if f.hits != 4 {
		t.Fatalf("hits = %d, want 4", f.hits)
	}
}

// TestSignTokenMismatchRejected 证伪闭环：假端点改持错误 key 独立重算，
// 客户端签名与之不符时假端点按厂商语义回 status=error、客户端判
// ErrInvalid——签名链路真被服务端校验，伪造 sign_token 过不去。
func TestSignTokenMismatchRejected(t *testing.T) {
	f := newFake(t, "deliberately-wrong-key")
	v, err := provider.NewVerifier(newProvider(f.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := packToken("l", "o", "p", "1")
	if err := v.Verify(context.Background(), "gt_row", provider.Submission{Token: tok}); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("sign_token 与服务端重算不符 = %v, want ErrInvalid", err)
	}
	if f.hits != 1 || !f.mismatch {
		t.Fatalf("hits=%d mismatch=%v, want 1 次且确有签名不符", f.hits, f.mismatch)
	}
}

// TestNewVerifierFailFast 构造期 fail-fast：nil provider / nil ext / 缺
// client_id / 缺 client_secret / endpoint 非法 URL 均构造失败；endpoint 为
// 空回落官方默认并自动并入 captcha_id query。
func TestNewVerifierFailFast(t *testing.T) {
	if _, err := provider.NewVerifier(nil); err == nil {
		t.Fatal("nil provider 应构造失败")
	}
	if _, err := provider.NewVerifier(&provider.Provider{Key: "gt_row", Type: Type}); err == nil {
		t.Fatal("nil ext 应构造失败")
	}
	noID := &provider.Provider{Key: "gt_row", Type: Type, Ext: &providerpb.Ext{ClientSecret: "k"}}
	if _, err := provider.NewVerifier(noID); err == nil {
		t.Fatal("缺 client_id 应构造失败")
	}
	noKey := &provider.Provider{Key: "gt_row", Type: Type, Ext: &providerpb.Ext{ClientId: "id"}}
	if _, err := provider.NewVerifier(noKey); err == nil {
		t.Fatal("缺 client_secret 应构造失败")
	}
	badURL := &provider.Provider{Key: "gt_row", Type: Type, Ext: &providerpb.Ext{ClientId: "id", ClientSecret: "k", Endpoint: "://bad"}}
	if _, err := provider.NewVerifier(badURL); err == nil {
		t.Fatal("endpoint 非法 URL 应构造失败")
	}

	v, err := newVerifier(newProvider(""))
	if err != nil {
		t.Fatalf("newVerifier: %v", err)
	}
	impl, ok := v.(*Verifier)
	if !ok {
		t.Fatalf("newVerifier 产物 = %T, want *Verifier", v)
	}
	const wantURL = defaultVerifyURL + "?captcha_id=cid-1"
	if impl.verifyURL != wantURL {
		t.Errorf("默认端点回落 = %q, want %q（captcha_id 并入 query）", impl.verifyURL, wantURL)
	}
}
