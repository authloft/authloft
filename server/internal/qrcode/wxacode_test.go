// wxacode_test.go 覆盖 CompressJPEG（PNG→JPEG 转码、质量 75、非图片
// 原样返回）与 DeleteExecutor（解析→删除、解析失败告警不 panic、无关
// 任务忽略）。全部 fake，不连 DB / Redis / 微信。
package qrcode

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	"authloft/internal/asyncqueue"
	"authloft/internal/storage"
)

// testPNG 生成 32×32 纯色 PNG（模拟微信下发的码图）。
func testPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for x := 0; x < 32; x++ {
		for y := 0; y < 32; y++ {
			img.Set(x, y, color.RGBA{R: 200, G: 30, B: 30, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}
	return buf.Bytes()
}

// TestCompressJPEGPNGToJPEG PNG 入 → JPEG q75 出。
func TestCompressJPEGPNGToJPEG(t *testing.T) {
	out, err := CompressJPEG(testPNG(t))
	if err != nil {
		t.Fatalf("CompressJPEG: %v", err)
	}
	if _, format, err := image.Decode(bytes.NewReader(out)); err != nil || format != "jpeg" {
		t.Fatalf("出参应为可解码 JPEG (format=%q, err=%v)", format, err)
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("jpeg.DecodeConfig: %v", err)
	}
	if cfg.Width != 32 || cfg.Height != 32 {
		t.Fatalf("尺寸变化 = %dx%d, want 32x32", cfg.Width, cfg.Height)
	}
}

// TestCompressJPEGJPEGReencode JPEG 入同样重编码为 q75（格式归一）。
func TestCompressJPEGJPEGReencode(t *testing.T) {
	var src bytes.Buffer
	img := image.NewGray(image.Rect(0, 0, 16, 16))
	if err := jpeg.Encode(&src, img, &jpeg.Options{Quality: 100}); err != nil {
		t.Fatalf("jpeg encode: %v", err)
	}
	out, err := CompressJPEG(src.Bytes())
	if err != nil {
		t.Fatalf("CompressJPEG: %v", err)
	}
	if _, format, err := image.Decode(bytes.NewReader(out)); err != nil || format != "jpeg" {
		t.Fatalf("出参应为 JPEG (format=%q, err=%v)", format, err)
	}
}

// TestCompressJPEGNonImagePassthrough 非图片字节原样返回、不报错。
func TestCompressJPEGNonImagePassthrough(t *testing.T) {
	in := []byte("not-an-image-at-all")
	out, err := CompressJPEG(in)
	if err != nil {
		t.Fatalf("CompressJPEG: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Fatalf("非图片应原样返回, got %q", out)
	}
}

// fakeStorage 记录 Delete 调用的 fake Storage。
type fakeStorage struct {
	deleted []string
	err     error
}

func (f *fakeStorage) Put(ctx context.Context, key string, body []byte, ct string) (string, error) {
	return "", nil
}
func (f *fakeStorage) Get(ctx context.Context, key string) ([]byte, error) {
	return nil, nil
}
func (f *fakeStorage) Delete(ctx context.Context, key string) error {
	if f.err != nil {
		return f.err
	}
	f.deleted = append(f.deleted, key)
	return nil
}
func (f *fakeStorage) URL(key string) string { return "" }
func (f *fakeStorage) PresignPut(ctx context.Context, key, ct string, size int64) (string, map[string]string, error) {
	return "", nil, nil
}

// fakeResolver 按 StorageKey 返回 fakeStorage / 错误。
type fakeResolver struct {
	byKey map[string]*fakeStorage
	fail  map[string]error
}

func (r fakeResolver) Resolve(_ context.Context, key string) (storage.Storage, error) {
	if err, ok := r.fail[key]; ok {
		return nil, err
	}
	if st, ok := r.byKey[key]; ok {
		return st, nil
	}
	return nil, storage.ErrNotConfigured
}

// TestDeleteExecutorConsumesAndSkips DeleteTask 被解析并删除；无关任务
// 类型原样忽略；解析失败不阻断同批其余任务。
func TestDeleteExecutorConsumesAndSkips(t *testing.T) {
	st := &fakeStorage{}
	res := fakeResolver{byKey: map[string]*fakeStorage{"files": st}, fail: map[string]error{"broken": storage.ErrNotConfigured}}
	ex := NewDeleteExecutor(res)

	ex.Execute(context.Background(), []asyncqueue.Task{
		{Key: "a", Value: DeleteTask{StorageKey: "files", ObjectKey: "q1.jpg"}},
		{Key: "b", Value: "not-a-delete-task"},                                  // 无关任务忽略
		{Key: "c", Value: DeleteTask{StorageKey: "broken", ObjectKey: "x.jpg"}}, // 解析失败告警不 panic
		{Key: "d", Value: DeleteTask{StorageKey: "files", ObjectKey: "q2.jpg"}},
	})

	if len(st.deleted) != 2 || st.deleted[0] != "q1.jpg" || st.deleted[1] != "q2.jpg" {
		t.Fatalf("deleted = %v, want [q1.jpg q2.jpg]", st.deleted)
	}
}
