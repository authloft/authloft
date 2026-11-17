// verifier.go 类型别名层（docs/后端架构.md §15.3 接口归属）：Verifier 接口
// 与随行数据类（Submission）、可判别哨兵（ErrInvalid）已上移 provider 包
// 定义——factory 签名 `func(p *Provider) (Verifier, error)` 的产物类型必须
// 让 provider 可见，而本包已 import provider，反向 import 会成环，故接口
// 先上移；本包以类型别名 / 同值变量保持调用方（dto / handler / service 各
// 域）import 路径与签名零改动。
//
// 工厂化（§9.1 阶段三）后第三方校验实现位于 provider/captcha/<type>/ 子包
// （init 自注册，bootstrap blank import 触发），gate 运行期经注册表
// provider.NewVerifier 构造，本包不再持有按 type 分派的大对象；image /
// builtin_image 不入 factory——校验依赖图形码 Store（Redis GETDEL，§9.2）
// 这一运行时依赖，保留为 gate 内置路径。
package captcha

import (
	"authloft/internal/provider"
)

// 第三方渠道 type 常量（§9.1 封闭集合与 gate.go normalize 一致；字面量
// 单一来源在 provider 包 servicetype.go，实现子包经同源常量注册）。
const (
	TypeTurnstile = provider.CaptchaTypeTurnstile
	TypeRecaptcha = provider.CaptchaTypeRecaptcha
	TypeHcaptcha  = provider.CaptchaTypeHcaptcha
)

// Verifier 按 providerKey 分派到对应渠道的校验实现（定义在 provider 包，
// §15.3 上移）。校验不通过 / 已使用必须返回 ErrInvalid（可包裹）；其它
// 错误视为基础设施错误。
type Verifier = provider.Verifier

// Submission 是前端回传的人机校验凭据（§2.5）。
type Submission = provider.Submission

// ErrInvalid 由 Verifier 返回，表示校验不通过或凭据已使用（→ StatusInvalid）。
// 其它错误一律视为基础设施错误，由调用方映射为 failed。
var ErrInvalid = provider.ErrInvalid
