package factor

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// 注册表可判别错误。
var (
	ErrUnknownKind           = errors.New("factor: unknown factor kind")
	ErrKindNotRegistered     = errors.New("factor: factor kind not registered")
	ErrKindAlreadyRegistered = errors.New("factor: factor kind already registered")
	ErrKindMismatch          = errors.New("factor: factor kind mismatch")
	ErrRegistryIncomplete    = errors.New("factor: registry incomplete")
)

// pendingKinds 尚无可用装配依赖、暂不参与启动期完整性断言的 kind 显式清单
// （后端架构 §3.8 行 390 口径）：依赖落地即从此处移除，清空后恢复
// 全量断言。allKinds 本身保持不变。otp_sms / otp_email 已随 §15.2
// 消息 Sender 基建装配，从清单移除；剩 thirdparty / device 两条。
var pendingKinds = []FactorKind{
	FactorThirdParty, // TODO(§3.8): provider 适配器未落地
	FactorDevice,     // TODO(§3.8): 登录设备内部因子未落地
}

// isPending 判定 kind 是否属于 pendingKinds。
func isPending(kind FactorKind) bool {
	for _, p := range pendingKinds {
		if p == kind {
			return true
		}
	}
	return false
}

// Registry 因子注册表（后端架构 §3.8 行 387）：Register / Get，
// AssertComplete 仅在启动期调用，断言 allKinds − pendingKinds 都有实现。
type Registry struct {
	mu      sync.RWMutex
	factors map[FactorKind]Factor
}

// NewRegistry 构造空注册表。
func NewRegistry() *Registry {
	return &Registry{factors: make(map[FactorKind]Factor)}
}

// Register 注册一个因子：kind 必须是已知 FactorKind，且必须与 f.Kind()
// 一致；重复注册返回错误。
func (r *Registry) Register(kind FactorKind, f Factor) error {
	if !validKind(kind) {
		return fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
	if f == nil {
		return fmt.Errorf("factor: register %q: nil factor", kind)
	}
	if f.Kind() != kind {
		return fmt.Errorf("%w: registered as %q, factor reports %q", ErrKindMismatch, kind, f.Kind())
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.factors[kind]; ok {
		return fmt.Errorf("%w: %q", ErrKindAlreadyRegistered, kind)
	}
	r.factors[kind] = f
	return nil
}

// Get 按 kind 取因子。未知 kind 与已注册但未实现的 kind 返回不同错误，
// 便于编排层区分请求非法与启动装配缺失。
func (r *Registry) Get(kind FactorKind) (Factor, error) {
	if !validKind(kind) {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.factors[kind]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrKindNotRegistered, kind)
	}
	return f, nil
}

// AssertComplete 启动期断言注册完整性：除 pendingKinds 与显式排除清单
// （degraded：启动期初始化失败被降级禁用的因子，§8.3 行 1069 webauthn
// 先例——不注册即不参与断言）外，每个合法 kind 都必须有实现（§3.8 行 390）。
func (r *Registry) AssertComplete(degraded ...FactorKind) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var missing []string
	for _, kind := range allKinds {
		if isPending(kind) || containsKind(degraded, kind) {
			continue
		}
		if _, ok := r.factors[kind]; !ok {
			missing = append(missing, string(kind))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("%w: missing %s", ErrRegistryIncomplete, strings.Join(missing, ", "))
}

// containsKind 线性包含判定（清单长度为个位数，不值得建 map）。
func containsKind(list []FactorKind, kind FactorKind) bool {
	for _, k := range list {
		if k == kind {
			return true
		}
	}
	return false
}
