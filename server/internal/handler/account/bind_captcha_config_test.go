// bind_captcha_config_test.go 覆盖账号域绑定族 captcha 失败的错误体与请求
// 顶层读取：真 Gate.Evaluate → 真 BindContactService → 真 handler → 生成的
// Connect handler + httptest。断言 captcha 失败响应 details 并列与 gate 判定
// 同源的 CaptchaConfig；只把凭据留在旧 payload 位置的请求按缺 captcha 处理，
// 顶层 captcha 正常放行。把断言（detail 存在 / 三字段等于 gate 输出 / 顶层
// 放行 / 旧位置被忽略）取反即可失败。
package account

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"database/sql"
	"google.golang.org/protobuf/proto"

	accountv1connect "authloft/gen/go/api/account/v1/accountv1connect"
	commonv1 "authloft/gen/go/api/common/v1"
	providerpb "authloft/gen/go/provider"
	"authloft/internal/cache"
	"authloft/internal/captcha"
	internalconnect "authloft/internal/connect"
	core "authloft/internal/otp"
	"authloft/internal/provider"
	"authloft/internal/repo/model"
	accountsvc "authloft/internal/service/account"
)

// —— 真链路所需进程内 fake（不读 DB / Redis）——

type bindChainSettings struct{}

func (bindChainSettings) GetInt64(string) (int64, bool) { return 0, false }

// bindChainCatalog 回显带 siteKey 的第三方当前生效项（完整 provider 实例），
// 使 CaptchaConfig 三字段均非空，便于逐项可证伪断言。
type bindChainCatalog struct{}

func (bindChainCatalog) Current(context.Context) (*provider.Provider, error) {
	return &provider.Provider{
		Key: "cf_turnstile", Type: "turnstile", Ext: &providerpb.Ext{ClientId: "0xSITE"},
	}, nil
}

// bindChainImageStore 图形码存储桩（gate 内置路径 Store 槽，本链路恒走
// 第三方 factory，不触达）。
type bindChainImageStore struct{}

func (bindChainImageStore) Set(context.Context, string, string) error { return nil }

func (bindChainImageStore) Verify(context.Context, string, string) (bool, error) {
	return true, nil
}

// bindChainVerifier 第三方校验桩：恒放行（经 factory 运行期构造注入）。
type bindChainVerifier struct{}

func (bindChainVerifier) Verify(context.Context, string, captcha.Submission) error { return nil }

// bindChainUsers 用户行存在、目标未被占用、列更新成功，供 challenge 放行
// 路径使用（captcha 失败在 Gate.Evaluate 后立即返回，不触达这些依赖）。
type bindChainUsers struct{}

func (bindChainUsers) FindByID(context.Context, int64) (*model.User, error) {
	return &model.User{ID: 10086}, nil
}

func (bindChainUsers) FindByPhone(context.Context, string) (*model.User, error) {
	return nil, fmt.Errorf("user repo: find by phone: %w", sql.ErrNoRows)
}

func (bindChainUsers) FindByEmail(context.Context, string) (*model.User, error) {
	return nil, fmt.Errorf("user repo: find by email: %w", sql.ErrNoRows)
}

func (bindChainUsers) UpdateContactColumns(context.Context, int64, *string, *string, *int8, *int8) error {
	return nil
}

// bindChainStore 真 *otp.Service 的存储底座：发码恒成功（SendOK）。
type bindChainStore struct{}

func (bindChainStore) Send(context.Context, string, string, string, string, string) (cache.SendResult, error) {
	return cache.SendOK, nil
}

func (bindChainStore) Verify(context.Context, string, string, string, string) (cache.CodeVerifyResult, error) {
	return cache.CodeVerifyResult{Result: cache.VerifyMissing}, nil
}

type bindChainSender struct{}

func (bindChainSender) SendCode(context.Context, string, string) error { return nil }

func newBindChainGate() *captcha.Gate {
	return captcha.NewGate(bindChainSettings{}, bindChainCatalog{}, bindChainImageStore{},
		func(*provider.Provider) (captcha.Verifier, error) { return bindChainVerifier{}, nil })
}

func newBindChainService() *accountsvc.BindContactService {
	return accountsvc.NewBindContactService(accountsvc.BindContactDeps{
		Users:  bindChainUsers{},
		OTP:    core.NewService(bindChainStore{}, core.DefaultConfig()),
		Sender: bindChainSender{},
		Gate:   newBindChainGate(),
		Config: core.DefaultConfig(),
	})
}

// decodeBindDetailValue 解 Connect 错误体 details[].value（base64 编码的
// 消息字节）；按标准 / 无填充 / URL variant 依次尝试。
func decodeBindDetailValue(t *testing.T, value string) []byte {
	t.Helper()
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(value); err == nil {
			return b
		}
	}
	t.Fatalf("detail value 无法 base64 解码: %q", value)
	return nil
}

// decodeBindErrorDetails 解析 Connect 错误体，取出 ErrorInfo 与并列的
// CaptchaConfig 两枚 detail。
func decodeBindErrorDetails(t *testing.T, raw string) (*commonv1.ErrorInfo, *commonv1.CaptchaConfig) {
	t.Helper()
	var envelope struct {
		Code    string `json:"code"`
		Details []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	if envelope.Code != "invalid_argument" {
		t.Fatalf("error.code = %q, want invalid_argument", envelope.Code)
	}
	var info *commonv1.ErrorInfo
	var cfg *commonv1.CaptchaConfig
	for _, d := range envelope.Details {
		b := decodeBindDetailValue(t, d.Value)
		switch d.Type {
		case "api.common.v1.ErrorInfo":
			m := &commonv1.ErrorInfo{}
			if err := proto.Unmarshal(b, m); err != nil {
				t.Fatalf("unmarshal ErrorInfo: %v", err)
			}
			info = m
		case "api.common.v1.CaptchaConfig":
			m := &commonv1.CaptchaConfig{}
			if err := proto.Unmarshal(b, m); err != nil {
				t.Fatalf("unmarshal CaptchaConfig: %v", err)
			}
			cfg = m
		}
	}
	return info, cfg
}

var bindCaptchaEndpoints = []struct {
	name      string
	procedure string
	target    string
	value     string
}{
	{"BindPhone", accountv1connect.AccountServiceBindPhoneProcedure, "phone", "+8613900008000"},
	{"BindEmail", accountv1connect.AccountServiceBindEmailProcedure, "email", "new@example.com"},
}

// TestBindCaptchaFailureNilCause 可证伪：cause 缺失（零值 / nil 接收者）时
// Error() 返回可读文案而非 panic——错误体编码会调用 Error()，nil cause 若
// 直接解引用会在响应阶段崩掉整个请求。
func TestBindCaptchaFailureNilCause(t *testing.T) {
	f := &accountsvc.BindCaptchaFailure{}
	if got := f.Error(); got == "" {
		t.Fatal("nil cause 的 Error() 应返回可读文案")
	}
	var nilF *accountsvc.BindCaptchaFailure
	if got := nilF.Error(); got == "" {
		t.Fatal("nil 接收者的 Error() 应返回可读文案")
	}
	if nilF.Unwrap() != nil {
		t.Fatal("nil 接收者的 Unwrap() 应为 nil")
	}
}

// TestMapBindCaptchaErrorAlignedWithSso 可证伪：绑定族 captcha 失败的
// Connect 形态与 sso 域同口径——invalid_argument + ErrorInfo.domain=account
// + 固定 message，不把 service 内部文案漏进错误体。message / domain / code
// 任一不符即失败。
func TestMapBindCaptchaErrorAlignedWithSso(t *testing.T) {
	cases := []struct {
		err     error
		code    string
		message string
	}{
		{accountsvc.ErrBindCaptchaRequired, captcha.StatusRequired, "captcha required"},
		{accountsvc.ErrBindCaptchaInvalid, captcha.StatusInvalid, "captcha invalid or used"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			out := mapBindError("bind phone", fmt.Errorf("wrap: %w", tc.err))
			var coded *connect.Error
			if !errors.As(out, &coded) {
				t.Fatalf("err = %v, want *connect.Error", out)
			}
			if coded.Code() != connect.CodeInvalidArgument || coded.Message() != tc.message {
				t.Fatalf("connect 形态 = %s/%q, want invalid_argument/%q", coded.Code(), coded.Message(), tc.message)
			}
			info, ok := internalconnect.ErrorInfoOf(out)
			if !ok || info.GetDomain() != "account" || info.GetCode() != tc.code {
				t.Fatalf("ErrorInfo = %+v (ok=%v), want account/%s", info, ok, tc.code)
			}
		})
	}
}

// TestBindCaptchaFailureCarriesConfig 可证伪：两个绑定端点的 captcha 失败
// 响应 details 并列 ErrorInfo 与 CaptchaConfig，错误码取 gate 常量、配置三
// 字段逐项等于 gate 单一出口的当前生效项。detail 缺失 / 字段不符即失败。
func TestBindCaptchaFailureCarriesConfig(t *testing.T) {
	want := newBindChainGate().Config(context.Background())
	if want.ProviderKey == "" || want.Type == "" || want.SiteKey == "" {
		t.Fatalf("gate 配置三字段须非空: %+v", want)
	}
	cases := []struct {
		name     string
		wantCode string
		withTop  bool
	}{
		{"required", captcha.StatusRequired, false},
		{"invalid", captcha.StatusInvalid, true},
	}
	for _, ep := range bindCaptchaEndpoints {
		for _, tc := range cases {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				body := fmt.Sprintf(`{"step":"challenge","payload":{"%s":"%s"}`, ep.target, ep.value)
				if tc.withTop {
					// providerKey 与当前生效项不符 → gate 判 captcha_invalid。
					body += `,"captcha":{"providerKey":"other","token":"tok-x"}`
				}
				body += "}"
				code, raw, _ := postService(t, ep.procedure, body,
					&getConfigDeps{bindcontactIn: newBindChainService()})
				if code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (body %s)", code, raw)
				}
				info, cfg := decodeBindErrorDetails(t, raw)
				if info == nil || info.GetDomain() != "account" || info.GetCode() != tc.wantCode {
					t.Fatalf("ErrorInfo = %+v, want account/%s", info, tc.wantCode)
				}
				if cfg == nil {
					t.Fatal("details 缺少 api.common.v1.CaptchaConfig（captcha 配置未并列下发）")
				}
				if cfg.GetProviderKey() != want.ProviderKey || cfg.GetType() != want.Type || cfg.GetSiteKey() != want.SiteKey {
					t.Fatalf("CaptchaConfig = %+v, want 与 gate 输出一致 %+v", cfg, want)
				}
			})
		}
	}
}

// TestBindCaptchaTopLevelOnly 可证伪：只把凭据留在旧 payload 位置的请求
// （未知字段按 connect-go 内建 DiscardUnknown 静默忽略）按缺 captcha 处理；
// 顶层 captcha 正常通过（HTTP 200）。顶层若未读取、旧位置若仍被读取，
// 用例立即失败。
func TestBindCaptchaTopLevelOnly(t *testing.T) {
	for _, ep := range bindCaptchaEndpoints {
		t.Run(ep.name, func(t *testing.T) {
			legacy := fmt.Sprintf(`{"step":"challenge","payload":{"%s":"%s","captcha":{"providerKey":"cf_turnstile","token":"tok-old"}}}`, ep.target, ep.value)
			code, raw, _ := postService(t, ep.procedure, legacy,
				&getConfigDeps{bindcontactIn: newBindChainService()})
			if code != http.StatusBadRequest {
				t.Fatalf("仅旧位置的 captcha 应按缺 captcha 处理, status = %d (body %s)", code, raw)
			}
			info, cfg := decodeBindErrorDetails(t, raw)
			if info == nil || info.GetCode() != captcha.StatusRequired {
				t.Fatalf("ErrorInfo = %+v, want code=%s", info, captcha.StatusRequired)
			}
			if cfg == nil {
				t.Fatal("details 缺少 CaptchaConfig（captcha 配置未并列下发）")
			}

			top := fmt.Sprintf(`{"step":"challenge","payload":{"%s":"%s"},"captcha":{"providerKey":"cf_turnstile","token":"tok-new"}}`, ep.target, ep.value)
			code, raw, _ = postService(t, ep.procedure, top,
				&getConfigDeps{bindcontactIn: newBindChainService()})
			if code != http.StatusOK {
				t.Fatalf("顶层 captcha 应放行（HTTP 200）, status = %d (body %s)", code, raw)
			}
			if raw != "{}" {
				t.Fatalf("成功响应 = %q, want {}", raw)
			}
		})
	}
}
