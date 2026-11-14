package connect

import (
	"errors"

	"connectrpc.com/connect"

	commonv1 "authloft/gen/go/api/common/v1"
)

// NewErrorInfo 构造 ErrorInfo（docs/接口文档.md §1.5 行 213-221：domain /
// code / message；retry_after / attempts_left 按需由调用方直接设置——如
// too_many_requests / invalid_code 等场景）。code 只允许接口文档 §1.6
// 词汇表与域内定义值（§3.14 errors.go 行约束）。
func NewErrorInfo(domain, code, message string) *commonv1.ErrorInfo {
	return &commonv1.ErrorInfo{
		Domain:  domain,
		Code:    code,
		Message: message,
	}
}

// WithErrorInfo 把 info 作为 detail 挂到 err（§1.5 行 203-210）并返回 err
// 本身（便于内联构造）。err 必须是 *connect.Error（包内口径：先 NewError
// 再 WithErrorInfo）；序列化失败（ErrorInfo 为简单消息，实际不可达）时跳过挂载。
func WithErrorInfo(err *connect.Error, info *commonv1.ErrorInfo) *connect.Error {
	if detail, derr := connect.NewErrorDetail(info); derr == nil {
		err.AddDetail(detail)
	}
	return err
}

// ErrorInfoOf 从 err 中读出第一枚 ErrorInfo detail（测试与排障用）；
// err 非 connect.Error 或无该类 detail 时返回 false。
func ErrorInfoOf(err error) (*commonv1.ErrorInfo, bool) {
	var coded *connect.Error
	if !errors.As(err, &coded) {
		return nil, false
	}
	for _, detail := range coded.Details() {
		msg, verr := detail.Value()
		if verr != nil {
			continue
		}
		if info, ok := msg.(*commonv1.ErrorInfo); ok {
			return info, true
		}
	}
	return nil, false
}

// WithCaptchaConfig 把当前生效的 captcha 配置作为 detail 与 ErrorInfo 并列挂到
// 错误体（§1.5 行 228：captcha 失败时 details 允许并列一个 CaptchaConfig 元素）。
func WithCaptchaConfig(err *connect.Error, cfg *commonv1.CaptchaConfig) *connect.Error {
	if cfg != nil {
		if detail, derr := connect.NewErrorDetail(cfg); derr == nil {
			err.AddDetail(detail)
		}
	}
	return err
}

// InternalError 把服务端原始错误包装成线上固定文案 "internal error"：
// 客户端只见通用文案（§1.5 消毒口径），根因经 Unwrap 保留，供
// NewErrorLogInterceptor 记录完整链文本、供服务端 errors.Is / As 回溯。
//
// 各 handler 的「未知异常 / 基础设施故障」分支应统一用本函数，而不是各造
// 一个 errXxxInternal = errors.New("internal error") 把原始 err 丢掉——后者
// 会让统一错误日志只剩 "internal error"。与
// interceptors.go 的 sanitizedError 同源，不新增第二套机制。
//
// err == nil 时回落固定文案本身（无根因可保留）。
func InternalError(err error) error {
	if err == nil {
		return errInternal
	}
	return sanitizedError{err: err}
}

// CaptchaConfigOf 从 err 中读出第一枚 CaptchaConfig detail（测试与排障用）；
// err 非 connect.Error 或无该类 detail 时返回 false。
func CaptchaConfigOf(err error) (*commonv1.CaptchaConfig, bool) {
	var coded *connect.Error
	if !errors.As(err, &coded) {
		return nil, false
	}
	for _, detail := range coded.Details() {
		msg, verr := detail.Value()
		if verr != nil {
			continue
		}
		if cfg, ok := msg.(*commonv1.CaptchaConfig); ok {
			return cfg, true
		}
	}
	return nil, false
}
