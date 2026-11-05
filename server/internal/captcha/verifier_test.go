// verifier_test.go 覆盖 ServiceVerifier 四类分派（§9.1 行 1085-1090、
// §9.2）：image 路径（builtin 不查表 / type=image 同路径 / GETDEL 一次性，
// 含 env-skip 真连 Redis 用例）与三家第三方 siteverify（httptest 假端点
// 断言请求形态与失败映射）。
package captcha

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/redis/go-redis/v9"

	"authloft/internal/cache"
)

// errStore 恒返回基础设施错误的图形码存储。
type errStore struct{}

func (errStore) Set(context.Context, string, string) error { return errors.New("redis down") }
func (errStore) Verify(context.Context, string, string) (bool, error) {
	return false, errors.New("redis down")
}

// genChallenge 用 fake 存储生成一个图形码并算出正确答案（复用 image_test
// 的 expectedAnswer）。
func genChallenge(t *testing.T, store *fakeCaptchaStore) (id, answer string) {
	t.Helper()
	ch, err := NewImageCaptcha(store).Generate(context.Background())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return ch.ID, strconv.Itoa(expectedAnswer(t, ch.Question))
}

// TestVerifierImageBuiltin 内置路径：builtin_image 不查表（source 为空也
// 可用），正确答案通过、错误 / 已消费 / 空 id → ErrInvalid（§2.5 行 515）。
func TestVerifierImageBuiltin(t *testing.T) {
	store := newFakeCaptchaStore()
	v := NewVerifier(mapSource{}, store, VerifierOptions{})
	ctx := context.Background()

	id, answer := genChallenge(t, store)
	if err := v.Verify(ctx, BuiltinProviderKey, Submission{ID: id, Answer: answer}); err != nil {
		t.Fatalf("正确答案 = %v, want nil", err)
	}
	if err := v.Verify(ctx, BuiltinProviderKey, Submission{ID: id, Answer: answer}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("已消费再校验 = %v, want ErrInvalid（一次性）", err)
	}

	id2, answer2 := genChallenge(t, store)
	if err := v.Verify(ctx, BuiltinProviderKey, Submission{ID: id2, Answer: "000000"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("错误答案 = %v, want ErrInvalid", err)
	}
	if err := v.Verify(ctx, BuiltinProviderKey, Submission{ID: id2, Answer: answer2}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("错误消费后正确答案 = %v, want ErrInvalid（错误也消费）", err)
	}
	if err := v.Verify(ctx, BuiltinProviderKey, Submission{ID: "", Answer: "1"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("空 id = %v, want ErrInvalid", err)
	}
}

// TestVerifierImageTypedProvider type=image 的表内 Provider 同走 image
// 路径（§9.2 行 1103，不另写第二条校验路径）。
func TestVerifierImageTypedProvider(t *testing.T) {
	store := newFakeCaptchaStore()
	v := NewVerifier(mapSource{rows: map[string]*ProviderRecord{
		"custom_img": {ProviderKey: "custom_img", Category: CategoryCaptcha, Type: TypeImage, Enabled: true},
	}}, store, VerifierOptions{})
	id, answer := genChallenge(t, store)
	if err := v.Verify(context.Background(), "custom_img", Submission{ID: id, Answer: answer}); err != nil {
		t.Fatalf("type=image 正确答案 = %v, want nil", err)
	}
	if err := v.Verify(context.Background(), "custom_img", Submission{ID: id, Answer: answer}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("type=image 二次校验 = %v, want ErrInvalid", err)
	}
}

// TestVerifierImageStoreError 存储故障为基础设施错误（→ engine 映射
// failed），不得映射 ErrInvalid。
func TestVerifierImageStoreError(t *testing.T) {
	v := NewVerifier(mapSource{}, errStore{}, VerifierOptions{})
	err := v.Verify(context.Background(), BuiltinProviderKey, Submission{ID: "id", Answer: "1"})
	if err == nil {
		t.Fatal("expected infra error")
	}
	if errors.Is(err, ErrInvalid) {
		t.Fatalf("存储故障被误映射为 ErrInvalid: %v", err)
	}
}

// TestVerifierProviderNotFound 行不存在（并发变更窗口）→ ErrInvalid；
// 空 token 不发请求直接 ErrInvalid；未知 type 为基础设施错误。
func TestVerifierNotFoundAndGuards(t *testing.T) {
	v := NewVerifier(mapSource{rows: map[string]*ProviderRecord{
		"bogus": {ProviderKey: "bogus", Category: CategoryCaptcha, Type: "bogus", Enabled: true},
		"cf":    {ProviderKey: "cf", Category: CategoryCaptcha, Type: TypeTurnstile, Enabled: true, Secret: "s"},
	}}, newFakeCaptchaStore(), VerifierOptions{VerifyURLs: map[string]string{TypeTurnstile: "http://127.0.0.1:1"}})
	ctx := context.Background()

	if err := v.Verify(ctx, "gone", Submission{Token: "t"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("provider 不存在 = %v, want ErrInvalid", err)
	}
	if err := v.Verify(ctx, "cf", Submission{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("空 token = %v, want ErrInvalid", err)
	}
	err := v.Verify(ctx, "bogus", Submission{Token: "t"})
	if err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("未知 type = %v, want infra error", err)
	}
}

// siteverifyRecorder 断言 siteverify 请求形态的假端点。
type siteverifyRecorder struct {
	server   *httptest.Server
	method   string
	ctype    string
	form     map[string]string
	status   int    // 响应状态码（默认 200）
	body     string // 响应体（默认 success JSON）
	hitCount int
}

func newSiteverifyServer(t *testing.T) *siteverifyRecorder {
	t.Helper()
	rec := &siteverifyRecorder{status: http.StatusOK}
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.hitCount++
		rec.method = r.Method
		rec.ctype = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		rec.form = map[string]string{}
		for k, vs := range r.PostForm {
			rec.form[k] = vs[0]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.status)
		body := rec.body
		if body == "" {
			body = `{"success":true}`
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(rec.server.Close)
	return rec
}

// TestVerifierRemoteFormAndSuccess 三家第三方逐 type 断言请求形态
//（POST + application/x-www-form-urlencoded + 恰好 secret/response 两字段）
// 与 success 判定（§9.1 行 1088-1090；httptest 假端点，不打真实厂商）。
func TestVerifierRemoteFormAndSuccess(t *testing.T) {
	for _, typ := range []string{TypeTurnstile, TypeRecaptcha, TypeHcaptcha} {
		t.Run(typ, func(t *testing.T) {
			rec := newSiteverifyServer(t)
			v := NewVerifier(mapSource{rows: map[string]*ProviderRecord{
				"pk": {ProviderKey: "pk", Category: CategoryCaptcha, Type: typ, Enabled: true, Secret: "sec-1"},
			}}, newFakeCaptchaStore(), VerifierOptions{VerifyURLs: map[string]string{typ: rec.server.URL}})

			if err := v.Verify(context.Background(), "pk", Submission{Token: "tok-1"}); err != nil {
				t.Fatalf("success=true = %v, want nil", err)
			}
			if rec.hitCount != 1 {
				t.Fatalf("siteverify 请求数 = %d, want 1", rec.hitCount)
			}
			if rec.method != http.MethodPost {
				t.Errorf("method = %q, want POST", rec.method)
			}
			if rec.ctype != "application/x-www-form-urlencoded" {
				t.Errorf("Content-Type = %q, want form-urlencoded", rec.ctype)
			}
			if len(rec.form) != 2 || rec.form["secret"] != "sec-1" || rec.form["response"] != "tok-1" {
				t.Errorf("form = %v, want exactly {secret:sec-1, response:tok-1}", rec.form)
			}
		})
	}
}

// TestVerifierRemoteFailures 失败映射：success=false → ErrInvalid；
// HTTP 500 / 坏 JSON → 基础设施错误（非 ErrInvalid）。
func TestVerifierRemoteFailures(t *testing.T) {
	base := func() (ProviderSource, *siteverifyRecorder) {
		rec := newSiteverifyServer(t)
		return mapSource{rows: map[string]*ProviderRecord{
			"pk": {ProviderKey: "pk", Category: CategoryCaptcha, Type: TypeTurnstile, Enabled: true, Secret: "s"},
		}}, rec
	}

	src, rec := base()
	rec.body = `{"success":false,"error-codes":["invalid-input-response"]}`
	v := NewVerifier(src, newFakeCaptchaStore(), VerifierOptions{VerifyURLs: map[string]string{TypeTurnstile: rec.server.URL}})
	if err := v.Verify(context.Background(), "pk", Submission{Token: "t"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("success=false = %v, want ErrInvalid", err)
	}

	src, rec = base()
	rec.status = http.StatusInternalServerError
	v = NewVerifier(src, newFakeCaptchaStore(), VerifierOptions{VerifyURLs: map[string]string{TypeTurnstile: rec.server.URL}})
	err := v.Verify(context.Background(), "pk", Submission{Token: "t"})
	if err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("HTTP 500 = %v, want infra error", err)
	}

	src, rec = base()
	rec.body = "not-json"
	v = NewVerifier(src, newFakeCaptchaStore(), VerifierOptions{VerifyURLs: map[string]string{TypeTurnstile: rec.server.URL}})
	err = v.Verify(context.Background(), "pk", Submission{Token: "t"})
	if err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("坏 JSON = %v, want infra error", err)
	}
}

// TestVerifierEndpointPrecedence 地址优先级：注入覆盖 > Ext.endpoint
//（§9.1 行 1083 自定义校验地址）> 厂商默认。
func TestVerifierEndpointPrecedence(t *testing.T) {
	ext := newSiteverifyServer(t)
	injected := newSiteverifyServer(t)

	// 不注入 VerifyURLs：Ext.endpoint 生效。
	v := NewVerifier(mapSource{rows: map[string]*ProviderRecord{
		"pk": {ProviderKey: "pk", Category: CategoryCaptcha, Type: TypeHcaptcha, Enabled: true, Secret: "s", VerifyURL: ext.server.URL},
	}}, newFakeCaptchaStore(), VerifierOptions{})
	if err := v.Verify(context.Background(), "pk", Submission{Token: "t"}); err != nil {
		t.Fatalf("ext.endpoint 校验 = %v, want nil", err)
	}
	if ext.hitCount != 1 {
		t.Fatalf("ext.endpoint 请求数 = %d, want 1", ext.hitCount)
	}

	// 注入 VerifyURLs：优先于 Ext.endpoint。
	v = NewVerifier(mapSource{rows: map[string]*ProviderRecord{
		"pk": {ProviderKey: "pk", Category: CategoryCaptcha, Type: TypeHcaptcha, Enabled: true, Secret: "s", VerifyURL: ext.server.URL},
	}}, newFakeCaptchaStore(), VerifierOptions{VerifyURLs: map[string]string{TypeHcaptcha: injected.server.URL}})
	if err := v.Verify(context.Background(), "pk", Submission{Token: "t"}); err != nil {
		t.Fatalf("注入覆盖校验 = %v, want nil", err)
	}
	if injected.hitCount != 1 {
		t.Fatalf("注入端点请求数 = %d, want 1", injected.hitCount)
	}
	if ext.hitCount != 1 {
		t.Fatalf("注入后 ext.endpoint 仍被请求（%d 次），want 1（不再请求）", ext.hitCount)
	}
}

// TestVerifierImageOnceSemanticsRealRedis（env-skip）：真连 Redis +
// cache.CaptchaStore，实证 image 路径经真实 Lua GETDEL 的一次性语义
//（首次正确通过 → 键已删 → 再校验 ErrInvalid，§9.2 行 1101）。清理口径
// 同 cache/captcha_test.go：测后删除用例键自证零残留。
func TestVerifierImageOnceSemanticsRealRedis(t *testing.T) {
	addr := os.Getenv("UC_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("环境变量 UC_TEST_REDIS_ADDR 未设置，跳过 Redis 连接用例")
	}
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("连接 Redis 测试实例失败: %v", err)
	}
	store := cache.NewCaptchaStore(rdb)
	v := NewVerifier(mapSource{}, store, VerifierOptions{})

	ch, err := NewImageCaptcha(store).Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	id := ch.ID
	answer := strconv.Itoa(expectedAnswer(t, ch.Question))
	t.Cleanup(func() { _ = rdb.Del(ctx, cache.CaptchaKey(id)).Err() })

	if err := v.Verify(ctx, BuiltinProviderKey, Submission{ID: id, Answer: answer}); err != nil {
		t.Fatalf("首次正确校验 = %v, want nil", err)
	}
	if err := v.Verify(ctx, BuiltinProviderKey, Submission{ID: id, Answer: answer}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("GETDEL 后再校验 = %v, want ErrInvalid（真实一次性语义）", err)
	}
}
