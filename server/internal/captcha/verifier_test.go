// verifier_test.go 覆盖两件事（docs/后端架构.md §15.3 接口归属、§9.1 阶段三）：
// ① 类型别名调用面零改动——Verifier / Submission / ErrInvalid 与 provider 包
// 上移定义同恒，既有引用方（dto / handler / service）import 路径与签名不变；
// ② 图形码内置路径不变——builtin_image 与 type=image 表内行经 Gate 内置路径
// 核 al:cap:{id}（fake 存储与 env-skip 真 Redis GETDEL 两档，§9.2 一次性语义）。
// 第三方 siteverify 行为随工厂化迁 provider/captcha/captcha-core 与各 type
// 子包单测。
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/redis/go-redis/v9"

	"authloft/internal/cache"
	"authloft/internal/provider"
)

// TestAliasSurfaceUnchanged 别名调用面零改动（§15.3）：captcha 包导出的
// Verifier / Submission / ErrInvalid 与 provider 上移定义同恒；type 常量与
// provider 字面量单一来源相等，运行时注册 type 与本包判零漂移（ Servicetype
// 同源判据在本包一侧的对应断言）。
func TestAliasSurfaceUnchanged(t *testing.T) {
	// Submission 别名：字段字面量与跨包赋值两向成立。
	sub := Submission{ProviderKey: "cf", Token: "tok", ID: "id", Answer: "42"}
	var psub provider.Submission = sub
	if psub != (provider.Submission{ProviderKey: "cf", Token: "tok", ID: "id", Answer: "42"}) {
		t.Fatalf("Submission 别名值不等: %+v", psub)
	}
	// Verifier 别名：同一实现可双向赋值（接口恒等）。
	var v Verifier = &fakeVerifier{}
	var pv provider.Verifier = v
	_ = pv
	// 哨兵同值：errors.Is 判别面跨包不变。
	if ErrInvalid != provider.ErrInvalid {
		t.Fatalf("ErrInvalid 应为 provider.ErrInvalid 同值, got %v", ErrInvalid)
	}
	if !errors.Is(provider.ErrInvalid, ErrInvalid) {
		t.Fatal("errors.Is(provider.ErrInvalid, ErrInvalid) 应成立")
	}
	// type 常量单一来源。
	if TypeTurnstile != provider.CaptchaTypeTurnstile ||
		TypeRecaptcha != provider.CaptchaTypeRecaptcha ||
		TypeHcaptcha != provider.CaptchaTypeHcaptcha {
		t.Fatalf("type 常量与 provider 漂移: (%q,%q,%q)", TypeTurnstile, TypeRecaptcha, TypeHcaptcha)
	}
	// Config 下发 JSON 字段名不变（§1.3 providerKey/type/siteKey）。
	raw, err := json.Marshal(Config{ProviderKey: "cf", Type: TypeTurnstile, SiteKey: "0xSITE"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["providerKey"] != "cf" || out["type"] != TypeTurnstile || out["siteKey"] != "0xSITE" {
		t.Fatalf("Config JSON 字段漂移: %s", raw)
	}
	// ProviderCatalog 新口径：完整 provider 实例（fakeCatalog 可赋值编译）；
	// factory 形态与注册表取件签名一致。
	var _ ProviderCatalog = &fakeCatalog{}
	var _ provider.VerifierFactory = func(*provider.Provider) (provider.Verifier, error) { return nil, nil }
}

// TestGateImageBuiltinWithRealChallenge 图形码内置路径端到端（fake 存储）：
// 生成真题面 → 正确答案通过、已消费 / 错误答案 ErrInvalid、错误也消费、
// 空 id → invalid（§2.5 内置项不是 Provider 表记录）。
func TestGateImageBuiltinWithRealChallenge(t *testing.T) {
	ctx := context.Background()
	store := newFakeCaptchaStore()
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		store, func(*provider.Provider) (provider.Verifier, error) { return nil, nil })

	ch, err := NewImageCaptcha(store).Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	answer := strconv.Itoa(expectedAnswer(t, ch.Question))
	sub := &Submission{ProviderKey: BuiltinProviderKey, ID: ch.ID, Answer: answer}

	if out, err := g.Evaluate(ctx, Request{Scene: SceneOtpDispatch, Submission: sub}); err != nil || out.Status != "" {
		t.Fatalf("正确答案 = (out=%+v, err=%v), want 放行", out, err)
	}
	if out, err := g.Evaluate(ctx, Request{Scene: SceneOtpDispatch, Submission: sub}); err != nil || out.Status != StatusInvalid {
		t.Fatalf("已消费再校验 = (out=%+v, err=%v), want invalid（一次性）", out, err)
	}

	ch2, err := NewImageCaptcha(store).Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	wrong := &Submission{ProviderKey: BuiltinProviderKey, ID: ch2.ID, Answer: "000000"}
	if out, _ := g.Evaluate(ctx, Request{Scene: SceneOtpDispatch, Submission: wrong}); out.Status != StatusInvalid {
		t.Fatalf("错误答案 out=%+v, want invalid", out)
	}
	right2 := &Submission{ProviderKey: BuiltinProviderKey, ID: ch2.ID, Answer: strconv.Itoa(expectedAnswer(t, ch2.Question))}
	if out, _ := g.Evaluate(ctx, Request{Scene: SceneOtpDispatch, Submission: right2}); out.Status != StatusInvalid {
		t.Fatalf("错误消费后正确答案 out=%+v, want invalid（错误也消费）", out)
	}
	empty := &Submission{ProviderKey: BuiltinProviderKey, ID: "", Answer: "1"}
	if out, _ := g.Evaluate(ctx, Request{Scene: SceneOtpDispatch, Submission: empty}); out.Status != StatusInvalid {
		t.Fatalf("空 id out=%+v, want invalid", out)
	}
}

// TestGateImageStoreInfraError 存储故障为基础设施错误（→ engine 映射
// failed），不得映射 invalid。
func TestGateImageStoreInfraError(t *testing.T) {
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		errStore{}, func(*provider.Provider) (provider.Verifier, error) { return nil, nil })
	_, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: BuiltinProviderKey, ID: "id", Answer: "1"},
	})
	if err == nil {
		t.Fatal("expected infra error")
	}
	if errors.Is(err, ErrInvalid) {
		t.Fatalf("存储故障被误映射为 ErrInvalid: %v", err)
	}
}

// errStore 恒返回基础设施错误的图形码存储。
type errStore struct{}

func (errStore) Set(context.Context, string, string) error { return errors.New("redis down") }
func (errStore) Verify(context.Context, string, string) (bool, error) {
	return false, errors.New("redis down")
}

// TestGateImageOnceSemanticsRealRedis（env-skip）：真连 Redis +
// cache.CaptchaStore，实证内置路径经真实 Lua GETDEL 的一次性语义
// （首次正确通过 → 键已删 → 再校验 invalid，§9.2）。清理口径同
// cache/captcha_test.go：测后删除用例键自证零残留。
func TestGateImageOnceSemanticsRealRedis(t *testing.T) {
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
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		store, func(*provider.Provider) (provider.Verifier, error) { return nil, nil })

	ch, err := NewImageCaptcha(store).Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	answer := strconv.Itoa(expectedAnswer(t, ch.Question))
	t.Cleanup(func() { _ = rdb.Del(ctx, cache.CaptchaKey(ch.ID)).Err() })

	sub := &Submission{ProviderKey: BuiltinProviderKey, ID: ch.ID, Answer: answer}
	if out, err := g.Evaluate(ctx, Request{Scene: SceneOtpDispatch, Submission: sub}); err != nil || out.Status != "" {
		t.Fatalf("首次正确校验 = (out=%+v, err=%v), want 放行", out, err)
	}
	if out, err := g.Evaluate(ctx, Request{Scene: SceneOtpDispatch, Submission: sub}); err != nil || out.Status != StatusInvalid {
		t.Fatalf("GETDEL 后再校验 = (out=%+v, err=%v), want invalid（真实一次性语义）", out, err)
	}
}
