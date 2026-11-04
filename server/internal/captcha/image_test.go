package captcha

import (
	"bytes"
	"context"
	"encoding/base64"
	"image/png"
	"strconv"
	"strings"
	"testing"
)

// fakeCaptchaStore 模拟 cache.CaptchaStore：Set 记录答案，Verify 做的是一次性
// 消费（正确 / 错误都删键，对应 cache 层 Lua GETDEL）。
type fakeCaptchaStore struct {
	setCalls    int
	setIDs      []string
	verifyCalls int
	answers     map[string]string
}

func newFakeCaptchaStore() *fakeCaptchaStore {
	return &fakeCaptchaStore{answers: map[string]string{}}
}

func (f *fakeCaptchaStore) Set(_ context.Context, id, answer string) error {
	f.setCalls++
	f.setIDs = append(f.setIDs, id)
	f.answers[id] = answer
	return nil
}

func (f *fakeCaptchaStore) Verify(_ context.Context, id, answer string) (bool, error) {
	f.verifyCalls++
	stored, ok := f.answers[id]
	delete(f.answers, id)
	return ok && stored == answer, nil
}

// expectedAnswer 从题面算出期望答案，并断言结果非负。
func expectedAnswer(t *testing.T, question string) int {
	t.Helper()
	i := strings.IndexAny(question, "+-")
	if i <= 0 || i == len(question)-1 {
		t.Fatalf("题面格式非法: %q", question)
	}
	left, err := strconv.Atoi(question[:i])
	if err != nil {
		t.Fatalf("题面左操作数非法: %q", question)
	}
	right, err := strconv.Atoi(question[i+1:])
	if err != nil {
		t.Fatalf("题面右操作数非法: %q", question)
	}
	var got int
	if question[i] == '+' {
		got = left + right
	} else {
		got = left - right
	}
	if got < 0 {
		t.Fatalf("答案不应为负: %q = %d", question, got)
	}
	return got
}

func TestImageGenerate(t *testing.T) {
	store := newFakeCaptchaStore()
	c := NewImageCaptcha(store)

	got, err := c.Generate(context.Background())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if got.ID == "" {
		t.Fatal("id 不应为空")
	}
	if got.ExpiresIn != 300 {
		t.Fatalf("expiresIn = %d, want 300", got.ExpiresIn)
	}

	want := strconv.Itoa(expectedAnswer(t, got.Question))
	if store.setCalls != 1 {
		t.Fatalf("Set 调用次数 = %d, want 1", store.setCalls)
	}
	if store.answers[got.ID] != want {
		t.Fatalf("写入答案 = %q, want %q (题面 %q)", store.answers[got.ID], want, got.Question)
	}

	if len(got.PNG) == 0 {
		t.Fatal("PNG 字节不应为空")
	}
	if base64.StdEncoding.EncodeToString(got.PNG) == "" {
		t.Fatal("imageBase64 不应为空")
	}
	img, err := png.Decode(bytes.NewReader(got.PNG))
	if err != nil {
		t.Fatalf("PNG 解码失败: %v", err)
	}
	if img.Bounds().Dx() <= 0 || img.Bounds().Dy() <= 0 {
		t.Fatalf("图片尺寸非法: %v", img.Bounds())
	}
}

func TestImageGenerateUniqueIDs(t *testing.T) {
	store := newFakeCaptchaStore()
	c := NewImageCaptcha(store)

	first, err := c.Generate(context.Background())
	if err != nil {
		t.Fatalf("第一次 Generate error: %v", err)
	}
	second, err := c.Generate(context.Background())
	if err != nil {
		t.Fatalf("第二次 Generate error: %v", err)
	}
	if first.ID == second.ID {
		t.Fatalf("两次生成的 id 重复: %q", first.ID)
	}
	if store.setCalls != 2 {
		t.Fatalf("Set 调用次数 = %d, want 2", store.setCalls)
	}
}

func TestImageVerifyStates(t *testing.T) {
	store := newFakeCaptchaStore()
	c := NewImageCaptcha(store)
	ctx := context.Background()

	challenge, err := c.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	answer := strconv.Itoa(expectedAnswer(t, challenge.Question))

	if ok, err := c.Verify(ctx, challenge.ID, answer); err != nil || !ok {
		t.Fatalf("正确答案校验 = (%v, %v), want (true, nil)", ok, err)
	}
	// 一次性的：正确校验后再次校验必须失败。
	if ok, err := c.Verify(ctx, challenge.ID, answer); err != nil || ok {
		t.Fatalf("已消费的 id 再次校验 = (%v, %v), want (false, nil)", ok, err)
	}

	second, err := c.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	secondAnswer := strconv.Itoa(expectedAnswer(t, second.Question))
	if ok, err := c.Verify(ctx, second.ID, "999999"); err != nil || ok {
		t.Fatalf("错误答案校验 = (%v, %v), want (false, nil)", ok, err)
	}
	// 错误答案同样消费：之后即使答对也必须失败。
	if ok, err := c.Verify(ctx, second.ID, secondAnswer); err != nil || ok {
		t.Fatalf("错误答案消费后校验 = (%v, %v), want (false, nil)", ok, err)
	}

	if ok, err := c.Verify(ctx, "missing-id", answer); err != nil || ok {
		t.Fatalf("缺失 id 校验 = (%v, %v), want (false, nil)", ok, err)
	}
	if store.verifyCalls != 5 {
		t.Fatalf("Verify 调用次数 = %d, want 5", store.verifyCalls)
	}
}
