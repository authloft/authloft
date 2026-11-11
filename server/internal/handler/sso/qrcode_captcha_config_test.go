// qrcode_captcha_config_test.go 覆盖扫码域 captcha 失败的错误体：CreateQrcode
// 经真 Gate.Evaluate → 真 service.QRCode → 真 mapQrcodeError 的端到端链路，
// 断言 captcha_required / captcha_invalid 两码的 details 并列当前生效且与
// gate 判定同源的 CaptchaConfig（§2.5 行 631 / §9.1 行 1128 / §13.2 行
// 1679）。把断言（detail 存在 / 三字段逐项等于 gate 输出）取反即可失败。
package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "authloft/gen/go/api/common/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/captcha"
	"authloft/internal/service"
)

// newQrcodeCaptchaChainHandler 组装真 Gate + 真 QRCode + 真 handler：captcha
// 失败路径在 Gate.Evaluate 后立即返回，不触达 Loader / Storage / TicketCodec
// 等其余依赖，故 QRCodeDeps 只需 Gate 一项。chainCatalog 回显带 siteKey 的
// turnstile 当前生效项，使 CaptchaConfig 三字段均非空，便于逐项可证伪断言。
func newQrcodeCaptchaChainHandler(t *testing.T) http.Handler {
	t.Helper()
	gate := captcha.NewGate(chainSettings{}, chainCatalog{}, chainVerifier{})
	svc := service.NewQRCode(service.QRCodeDeps{Gate: gate})
	_, handler := ssov1connect.NewSsoServiceHandler(New(nil, nil, nil, nil, svc))
	return handler
}

func TestCreateQrcodeCaptchaFailureCarriesConfig(t *testing.T) {
	// want 即 gate 单一出口当前生效配置（chainCatalog 固定回显）。
	want := captcha.NewGate(chainSettings{}, chainCatalog{}, chainVerifier{}).Config(context.Background())

	cases := []struct {
		name     string
		body     string
		wantCode string
	}{
		{"captcha_required", `{"providerKey":"wechat_mp_scan"}`, captcha.StatusRequired},
		{"captcha_invalid", `{"providerKey":"wechat_mp_scan","captcha":{"providerKey":"other_provider"}}`, captcha.StatusInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(newQrcodeCaptchaChainHandler(t))
			defer srv.Close()
			resp, err := http.Post(srv.URL+ssov1connect.SsoServiceCreateQrcodeProcedure,
				"application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("POST CreateQrcode: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}

			var envelope struct {
				Code    string `json:"code"`
				Details []struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"details"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if envelope.Code != "invalid_argument" {
				t.Fatalf("error.code = %q, want invalid_argument", envelope.Code)
			}

			var info *commonv1.ErrorInfo
			var cfg *commonv1.CaptchaConfig
			for _, d := range envelope.Details {
				raw := decodeDetailValue(t, d.Value)
				switch d.Type {
				case "api.common.v1.ErrorInfo":
					m := &commonv1.ErrorInfo{}
					if err := proto.Unmarshal(raw, m); err != nil {
						t.Fatalf("unmarshal ErrorInfo: %v", err)
					}
					info = m
				case "api.common.v1.CaptchaConfig":
					m := &commonv1.CaptchaConfig{}
					if err := proto.Unmarshal(raw, m); err != nil {
						t.Fatalf("unmarshal CaptchaConfig: %v", err)
					}
					cfg = m
				}
			}
			if info == nil || info.GetDomain() != "sso" || info.GetCode() != tc.wantCode {
				t.Fatalf("ErrorInfo = %+v, want sso/%s", info, tc.wantCode)
			}
			// 可证伪：配置 detail 必须存在且三字段逐项等于 gate 输出；
			// 取反（缺失 / 任一字段为空或不等）即失败。
			if cfg == nil {
				t.Fatal("details 缺少 api.common.v1.CaptchaConfig（captcha 配置未并列下发）")
			}
			if cfg.GetProviderKey() == "" || cfg.GetType() == "" || cfg.GetSiteKey() == "" {
				t.Fatalf("CaptchaConfig 三字段须非空: %+v", cfg)
			}
			if cfg.GetProviderKey() != want.ProviderKey || cfg.GetType() != want.Type || cfg.GetSiteKey() != want.SiteKey {
				t.Fatalf("CaptchaConfig = %+v, want 与 gate 输出一致 %+v", cfg, want)
			}
		})
	}
}
