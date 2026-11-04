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

// Registry 因子注册表（后端架构 §3.8 行 387）：Register / Get，
// AssertComplete 仅在启动期调用，断言每个 kind 都有实现。
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

// AssertComplete 启动期断言注册完整性：每个合法 kind 都必须有实现。
func (r *Registry) AssertComplete() error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var missing []string
	for _, kind := range allKinds {
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
