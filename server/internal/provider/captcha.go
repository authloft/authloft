// captcha Verifier 基建（docs/后端架构.md §9.1 阶段三、§15.3 接口归属）：
// Verifier 接口与随行数据类（Submission）及可判别哨兵从 internal/captcha
// 上移定义——factory 签名 `func(p *Provider) (Verifier, error)` 定义在本包，
// 产物类型必须让本包可见，而 captcha 已 import provider，反向 import 会成环
// （§15.3），故接口先上移；原包以类型别名保持调用方 import 路径与签名零改动。
//
// 实现位于 provider/captcha/<type>/ 子包，init() 经 RegisterVerifier 自注册，
// bootstrap 以 blank import 触发（CODE_GUIDE §3.3）；image / builtin_image
// 不入 factory——校验依赖图形码 Store（Redis GETDEL，§9.2）这一运行时依赖，
// *Provider 承载不了，保留为 gate 内置路径（§9.1）。
package provider

import (
	"context"
	"errors"
	"fmt"
)

// ErrInvalid 由 Verifier 返回，表示校验不通过或凭据已使用（映射
// captcha_invalid）；其它错误一律视为基础设施错误（映射 failed）。
// 文案自 internal/captcha 平移不变，errors.Is 判别面不变。
var ErrInvalid = errors.New("captcha: invalid or used")

// Submission 是前端回传的人机校验凭据（接口文档 §2.5 统一提交格式）。
type Submission struct {
	ProviderKey string
	Token       string
	ID          string
	Answer      string
}

// Verifier 按 providerKey 校验人机凭据。校验不通过 / 已使用必须返回
// ErrInvalid（可包裹）；其它错误视为基础设施错误。
type Verifier interface {
	Verify(ctx context.Context, providerKey string, sub Submission) error
}

// VerifierFactory captcha 槽 factory：由 Provider 实例构造对应 type 的校验
// 实现（运行期按当前生效 provider 经 NewVerifier 构造，§9.1：配置取自 Ext
// —— site_key=client_id、secret=client_secret、endpoint=自定义校验地址；
// 代理经 Outbound，装配期固化）。gate 改持 factory，Verify 内不再按 type
// 分派——分派权交给注册表。
type VerifierFactory func(p *Provider) (Verifier, error)

// WithVerifier 挂 verifier 槽（captcha type 工厂）。
func WithVerifier(f VerifierFactory) Option {
	return func(e *entry) error {
		if f == nil {
			return fmt.Errorf("%w: verifier slot", ErrNilFactory)
		}
		if e.verifier != nil {
			return fmt.Errorf("%w: verifier slot", ErrSlotConflict)
		}
		e.verifier = f
		return nil
	}
}

// RegisterVerifier 注册 captcha 校验实现（§15.3 薄封装：转调唯一入口
// register + WithVerifier，type 子包 init() 调用）。重复注册 / 空 type /
// 空 factory / category 非 captcha 属程序错误，直接 panic（init 无法返回
// 错误）。
func RegisterVerifier(captchaType string, meta Meta, factory VerifierFactory) {
	if captchaType == "" {
		panic(fmt.Errorf("%w: empty captcha type", ErrUnknownType))
	}
	if factory == nil {
		panic(fmt.Errorf("%w: captcha %q", ErrNilFactory, captchaType))
	}
	if meta.Category != CategoryCaptcha {
		panic(fmt.Errorf("provider: register captcha %q: category %q must be %q",
			captchaType, meta.Category, CategoryCaptcha))
	}
	if err := register(captchaType, meta, WithVerifier(factory)); err != nil {
		panic(err)
	}
}

// NewVerifier verifier 槽取件（§9.1）：按 Provider 实例的 type 经注册表
// 运行期构造校验实现。type 未注册或未挂 verifier 槽 → ErrUnknownType
// （gate 侧属基础设施错误收敛，不会构造出假校验器）；factory 自身错误
// 原样上抛。
func NewVerifier(p *Provider) (Verifier, error) {
	if p == nil {
		return nil, ErrNilProvider
	}
	registry.mu.RLock()
	e, ok := registry.entries[p.Type]
	registry.mu.RUnlock()
	if !ok || e.verifier == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, p.Type)
	}
	v, err := e.verifier(p)
	if err != nil {
		return nil, fmt.Errorf("provider: new verifier %q: %w", p.Type, err)
	}
	if v == nil {
		return nil, fmt.Errorf("%w: %q", ErrNilAdapter, p.Type)
	}
	return v, nil
}
