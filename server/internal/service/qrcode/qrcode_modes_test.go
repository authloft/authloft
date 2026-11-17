// qrcode_modes_test.go 拉码产出三模式分派用例（§2.8 / §13.2）：ticket 模式
// 不调微信拉码、不写 Storage、仅模板替换；base64 模式拉码压缩后 base64 直发、
// 不写 Storage；url（显式 / 缺省）保持 Storage 中转；未知模式收敛渠道不可用；
// renderTicketContent 纯函数与 tip_html 透传；码图自动删除仅 url 模式投递
// （§13.3）。复用 qrcode_test.go 的全 fake 环境（qrEnv / addScanProvider /
// validCaptcha）。
package qrcode

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/jpeg"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/gen/go/token"
	"authloft/internal/storage"
)

// testJPEG 构造真实可解码的 JPEG 字节（CompressJPEG 解码失败会原样透传，
// base64 模式的产物断言须有真图）。
func testJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 75}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return buf.Bytes()
}

// TestCreateQrcodeTicketMode ticket 模式（§2.8）：不调微信拉码、不写 Storage
// （存储解析器注入故障仍成功——存储依赖整段不在路径上），产物为 qrcode_format
// 模板将 {{TICKET}}（可多次出现）替换为完整加密 ticket 的内容；tip_html 直填
// Ext qrcode_tip 原文。
func TestCreateQrcodeTicketMode(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", nil)
	p := e.loader.byKey["scan"]
	p.Ext = &providerpb.Ext{
		QrcodeMode:   "ticket",
		QrcodeFormat: "https://example.com/scan?t={{TICKET}}&r={{TICKET}}",
		QrcodeTip:    "<p>请使用微信扫一扫</p>",
	}
	// 存储侧注入故障：ticket 模式若触达存储依赖即失败，反之成功即证门控。
	e.resolver.err = storage.ErrNotConfigured
	out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
	if err != nil {
		t.Fatalf("CreateQrcode: %v", err)
	}
	if out.QrcodeMode != "ticket" {
		t.Fatalf("qrcodeMode = %q, want ticket", out.QrcodeMode)
	}
	want := "https://example.com/scan?t=" + out.Ticket + "&r=" + out.Ticket
	if out.QrcodeContent != want {
		t.Fatalf("qrcodeContent = %q, want 模板两处 {{TICKET}} 均替换为加密 ticket", out.QrcodeContent)
	}
	if out.QrcodeURL != "" || out.QrcodeBase64 != "" {
		t.Fatalf("产出字段应按模式只填其一: %+v", out)
	}
	if out.TipHTML != "<p>请使用微信扫一扫</p>" {
		t.Fatalf("tipHtml = %q, want Ext 原文直填", out.TipHTML)
	}
	if len(e.adapter.fetchCalls) != 0 {
		t.Fatalf("ticket 模式不应调微信拉码, fetchCalls = %v", e.adapter.fetchCalls)
	}
	if e.store.putCalls != 0 {
		t.Fatalf("ticket 模式不应写 Storage, putCalls = %d", e.store.putCalls)
	}
}

// TestCreateQrcodeTicketModeTemplateMissing ticket 模板缺占位符（含空模板）：
// 运行期兜底收敛渠道不可用（保存期已拒绝的配置从旁路进来也不静默）。
func TestCreateQrcodeTicketModeTemplateMissing(t *testing.T) {
	ctx := context.Background()
	for name, tpl := range map[string]string{"空模板": "", "无占位符": "https://example.com/scan"} {
		t.Run(name, func(t *testing.T) {
			e := newQrEnv(t)
			e.addScanProvider("scan", nil)
			e.loader.byKey["scan"].Ext = &providerpb.Ext{QrcodeMode: "ticket", QrcodeFormat: tpl}
			_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
			if !errors.Is(err, ErrQrcodeProviderDisabled) {
				t.Fatalf("err = %v, want ErrQrcodeProviderDisabled", err)
			}
			if len(e.adapter.fetchCalls) != 0 || e.store.putCalls != 0 {
				t.Fatalf("失败前不应拉码 / 写存储: fetch=%v put=%d", e.adapter.fetchCalls, e.store.putCalls)
			}
		})
	}
}

// TestCreateQrcodeBase64Mode base64 模式（§2.8）：拉微信码 + 压缩后 JPEG 纯
// base64 直发（可解码、SOI 头），不写 Storage（不要求存储配置）；产出字段按
// 模式只填其一。
func TestCreateQrcodeBase64Mode(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", nil)
	p := e.loader.byKey["scan"]
	p.Ext = &providerpb.Ext{QrcodeMode: "base64", QrcodeTip: "<p>tip</p>"}
	e.adapter.fetchBody = testJPEG(t)
	// 存储侧注入故障：base64 模式若触达存储依赖即失败。
	e.resolver.err = storage.ErrNotConfigured
	out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
	if err != nil {
		t.Fatalf("CreateQrcode: %v", err)
	}
	if out.QrcodeMode != "base64" {
		t.Fatalf("qrcodeMode = %q, want base64", out.QrcodeMode)
	}
	raw, derr := base64.StdEncoding.DecodeString(out.QrcodeBase64)
	if derr != nil {
		t.Fatalf("qrcodeBase64 非合法 base64: %v", derr)
	}
	if len(raw) < 3 || raw[0] != 0xFF || raw[1] != 0xD8 || raw[2] != 0xFF {
		t.Fatalf("qrcodeBase64 解码后非 JPEG（SOI 头缺失）: % x", raw[:3])
	}
	if out.QrcodeURL != "" || out.QrcodeContent != "" {
		t.Fatalf("产出字段应按模式只填其一: %+v", out)
	}
	if out.TipHTML != "<p>tip</p>" {
		t.Fatalf("tipHtml = %q, want Ext 原文直填", out.TipHTML)
	}
	if len(e.adapter.fetchCalls) != 1 || e.adapter.fetchCalls[0] != out.TicketID {
		t.Fatalf("FetchQrcode 入参 = %v, want [ticket_id]", e.adapter.fetchCalls)
	}
	if e.store.putCalls != 0 {
		t.Fatalf("base64 模式不应写 Storage, putCalls = %d", e.store.putCalls)
	}
}

// TestCreateQrcodeURLModeExplicit 显式 url 与缺省（空）行为一致：拉码 +
// Storage 中转，产出字段按模式只填其一（空值归一由既有用例覆盖）。
func TestCreateQrcodeURLModeExplicit(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", nil)
	e.loader.byKey["scan"].Ext.QrcodeMode = "url"
	out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
	if err != nil {
		t.Fatalf("CreateQrcode: %v", err)
	}
	if out.QrcodeMode != "url" || out.QrcodeURL == "" {
		t.Fatalf("out = %+v, want mode=url + Storage URL", out)
	}
	if out.QrcodeContent != "" || out.QrcodeBase64 != "" {
		t.Fatalf("产出字段应按模式只填其一: %+v", out)
	}
	if len(e.adapter.fetchCalls) != 1 || e.store.putCalls != 1 {
		t.Fatalf("url 模式应拉码并写存储: fetch=%v put=%d", e.adapter.fetchCalls, e.store.putCalls)
	}
}

// TestCreateQrcodeUnknownMode 未知模式（§2.8 / §13.2）：收敛渠道不可用，
// 不静默回落 url；失败前不拉码、不写存储。
func TestCreateQrcodeUnknownMode(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", nil)
	e.loader.byKey["scan"].Ext.QrcodeMode = "pigeon_post"
	_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
	if !errors.Is(err, ErrQrcodeProviderDisabled) {
		t.Fatalf("err = %v, want ErrQrcodeProviderDisabled", err)
	}
	if len(e.adapter.fetchCalls) != 0 || e.store.putCalls != 0 {
		t.Fatalf("未知模式不应拉码 / 写存储: fetch=%v put=%d", e.adapter.fetchCalls, e.store.putCalls)
	}
}

// TestRenderTicketContent 模板替换纯函数：可多次出现、区分大小写、特殊字符
// 原样保留；缺占位符（含空模板）报错。
func TestRenderTicketContent(t *testing.T) {
	t.Run("多次替换", func(t *testing.T) {
		got, err := renderTicketContent("a{{TICKET}}b{{TICKET}}c", "T1")
		if err != nil || got != "aT1bT1c" {
			t.Fatalf("got = (%q, %v), want (aT1bT1c, nil)", got, err)
		}
	})
	t.Run("区分大小写", func(t *testing.T) {
		if _, err := renderTicketContent("a{{ticket}}b", "T1"); err == nil {
			t.Fatal("小写占位符不算命中，应报配置错误")
		}
	})
	t.Run("特殊字符原样保留", func(t *testing.T) {
		got, err := renderTicketContent("{{TICKET}}&x=<y>%z", "T&T")
		if err != nil || got != "T&T&x=<y>%z" {
			t.Fatalf("got = (%q, %v)", got, err)
		}
	})
	t.Run("缺占位符报错", func(t *testing.T) {
		for _, tpl := range []string{"", "https://example.com/scan"} {
			if _, err := renderTicketContent(tpl, "T1"); err == nil {
				t.Fatalf("模板 %q 缺占位符应报错", tpl)
			}
		}
	})
}

// TestAutoDeleteModeGated 码图自动删除仅 url 模式投递（§13.3）：ticket /
// base64 模式即便 qrcode_auto_delete 开启也不产码图、不投任务。
func TestAutoDeleteModeGated(t *testing.T) {
	for name, mode := range map[string]string{"ticket": "ticket", "base64": "base64"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			e := newQrEnv(t)
			p := e.addScanProvider("scan", nil)
			p.Ext.QrcodeAutoDelete = true
			p.Ext.QrcodeMode = mode
			e.tickets.res["tid123"] = &token.TicketResult{
				V: 1, Status: "success", Scene: "login", ProviderKey: "scan",
				LoginResult: &token.LoginResult{Uid: 9},
			}
			out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
			if out.Envelope.GetStatus() != "success" {
				t.Fatalf("status = %q, want success", out.Envelope.GetStatus())
			}
			if len(e.queue.tasks) != 0 {
				t.Fatalf("%s 模式不应投删除任务, tasks = %v", mode, e.queue.tasks)
			}
		})
	}
	t.Run("url 模式照常投递", func(t *testing.T) {
		ctx := context.Background()
		e := newQrEnv(t)
		p := e.addScanProvider("scan", nil)
		p.Ext.QrcodeAutoDelete = true
		e.tickets.res["tid123"] = &token.TicketResult{
			V: 1, Status: "success", Scene: "login", ProviderKey: "scan",
			LoginResult: &token.LoginResult{Uid: 9},
		}
		out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
		if out.Envelope.GetStatus() != "success" {
			t.Fatalf("status = %q, want success", out.Envelope.GetStatus())
		}
		if len(e.queue.tasks) != 1 {
			t.Fatalf("url 模式应投 1 个删除任务, tasks = %v", e.queue.tasks)
		}
	})
}
