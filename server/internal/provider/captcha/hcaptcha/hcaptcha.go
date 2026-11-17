// Package hcaptcha hCaptcha 人机校验实现（docs/后端架构.md §9.1 阶段三
// 工厂化）：init() 经 RegisterVerifier 自注册进统一注册表（meta 与 factory
// 同处注册），bootstrap 以 blank import 触发（CODE_GUIDE §3.3）；siteverify
// 共用逻辑沉 captchacore，本包只声明 type 常量与厂商默认端点（方案 §4.1）。
package hcaptcha

import (
	"authloft/internal/provider"
	captchacore "authloft/internal/provider/captcha/captcha-core"
)

// Type 注册类型（字面量单一来源在 provider 包 servicetype.go）。
const Type = provider.CaptchaTypeHcaptcha

// defaultVerifyURL 厂商 siteverify 端点（ext.endpoint 空串时回落，§9.1）。
const defaultVerifyURL = "https://api.hcaptcha.com/siteverify"

// init 注册进统一注册表（§15.3）：Schema 是 /schema 的唯一数据源（表列 +
// Ext + 引用键，接口文档 §5.3），三家共用同一声明（captchacore.Schema）。
func init() {
	provider.RegisterVerifier(Type, provider.Meta{
		DisplayName: "hCaptcha",
		Category:    provider.CategoryCaptcha,
		Schema:      captchacore.Schema,
	}, newVerifier)
}

// newVerifier 注册表工厂：从 Provider 实例取 Ext / Outbound 构造（§9.1
// 配置口径 + §15.4 代理装配期固化）。
func newVerifier(p *provider.Provider) (provider.Verifier, error) {
	return captchacore.New(p, defaultVerifyURL)
}
