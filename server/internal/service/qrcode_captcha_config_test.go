// qrcode_captcha_config_test.go 覆盖 CreateQrcode 的 captcha 失败错误载荷：
// Gate.Evaluate 返回的当前生效配置必须随哨兵错误透出（§9.1 同源），且
// errors.Is 仍可判别原哨兵。把断言取反（Config 不等于 gate 输出 / 错误
// 不携带配置 / 三字段为空）即可失败。
package service

import (
	"context"
	"errors"
	"testing"

	"authloft/internal/captcha"
)

func TestCreateQrcodeCaptchaFailureCarriesGateConfig(t *testing.T) {
	catalog := &qrCatalog{p: &captcha.Provider{ProviderKey: "cf_turnstile", Type: "turnstile", SiteKey: "0xSITE"}}
	gate := captcha.NewGate(&tpSettings{}, catalog, &qrVerifier{})
	want := gate.Config(context.Background()) // gate 单一出口当前生效配置
	svc := NewQRCode(QRCodeDeps{Gate: gate})

	cases := []struct {
		name         string
		in           CreateQrcodeInput
		wantSentinel error
	}{
		{"captcha_required", CreateQrcodeInput{ProviderKey: "wechat_mp_scan"}, ErrQrcodeCaptchaRequired},
		{"captcha_invalid", CreateQrcodeInput{ProviderKey: "wechat_mp_scan", Captcha: &captcha.Submission{ProviderKey: "builtin_image"}}, ErrQrcodeCaptchaInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateQrcode(context.Background(), tc.in)
			if !errors.Is(err, tc.wantSentinel) {
				t.Fatalf("err = %v, want %v", err, tc.wantSentinel)
			}
			var f *QrcodeCaptchaFailure
			if !errors.As(err, &f) {
				t.Fatalf("err = %T, want *QrcodeCaptchaFailure（配置未透出）", err)
			}
			// 可证伪：配置须逐字段等于该次 gate 判定的当前生效项；
			// 取反（缺失 / 不等 / 空值）即失败。
			if f.Config != want {
				t.Fatalf("carried Config = %+v, want gate 输出 %+v", f.Config, want)
			}
			if f.Config.ProviderKey == "" || f.Config.Type == "" || f.Config.SiteKey == "" {
				t.Fatalf("carried Config 三字段须非空: %+v", f.Config)
			}
		})
	}
}
