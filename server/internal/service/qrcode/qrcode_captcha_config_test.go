// qrcode_captcha_config_test.go 覆盖 CreateQrcode 的 captcha 失败错误载荷：
// Gate.Evaluate 返回的当前生效配置必须随哨兵错误透出（§9.1 同源），且
// errors.Is 仍可判别原哨兵。把断言取反（Config 不等于 gate 输出 / 错误
// 不携带配置 / 三字段为空）即可失败。
// 链路含 provider 前置校验（need_captcha=true 才进入 captcha 判定），
// 复用 qrcode_test 的全 fake env 播种扫码 provider。
package qrcode

import (
	"context"
	"errors"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/captcha"
	"authloft/internal/provider"
)

func TestCreateQrcodeCaptchaFailureCarriesGateConfig(t *testing.T) {
	env := newQrEnv(t)
	p := env.addScanProvider("wechat_mp_scan", nil)
	p.Ext.NeedCaptcha = true // 触发表第 7 行：该 provider 拉码需人机校验
	// 当前生效 captcha provider 用 turnstile（site_key 取 Ext.client_id，
	// §9.1），校验函数不得被触达（失败发生在凭据比对之前）。
	catalog := &qrCatalog{p: &provider.Provider{
		Key: "cf_turnstile", Type: "turnstile", Ext: &providerpb.Ext{ClientId: "0xSITE"},
	}}
	gate := captcha.NewGate(&tpSettings{}, catalog, env.verifier,
		func(*provider.Provider) (captcha.Verifier, error) { return nil, errors.New("not reached") })
	want := gate.Config(context.Background()) // gate 单一出口当前生效配置
	env.svc.deps.Gate = gate

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
			_, err := env.svc.CreateQrcode(context.Background(), tc.in)
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
