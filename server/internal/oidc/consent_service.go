// consent_service.go 授权同意判定与授权记录写回（后端架构 §4.5 读写口径、
// §14.2 步骤 3 三态判定内核、接口文档 §4.2 形态判定 / §3.10 步骤 4）：
// Decide 供 authorize 有会话分支做免同意 / 需同意判定，Grant 供 Terminal
// 登录即同意与同意 RPC 落授权记录。依赖只注入 repo 窄接口，不连 DB；
// 「从未同意 = 空集」的空集判定在本层做（§4.5：repo 未命中返回包装的
// sql.ErrNoRows）；scope 解析 / 比对复用本包 consent.go 纯工具。
package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"authloft/internal/repo"

	"database/sql"
)

// ConsentRepo 授权记录读写窄接口（后端架构 §4.5）；*repo.OidcConsentRepo
// 天然满足，测试用 fake。GetConsentScopes 未命中返回包装的
// sql.ErrNoRows，本层按「从未同意 = 空集」口径消费；MergeConsent
// 为行锁合并原语（单事务 FOR UPDATE 读现值 → 回调算新值 → 写回，首插撞
// uk 重试），并集口径由本层回调注入。scopes 原文入库出库（空格分隔口径），
// 解析归本层。
type ConsentRepo interface {
	GetConsentScopes(ctx context.Context, userID int64, clientID string) (string, error)
	MergeConsent(ctx context.Context, userID int64, clientID string, merge func(current string) (string, error)) error
}

// errConsentNotConfigured 依赖未注入（装配错误）。
var errConsentNotConfigured = errors.New("oidc: consent service not configured (repo nil)")

// ConsentService 同意判定与授权记录写回。
type ConsentService struct {
	Consents ConsentRepo
}

// Decision 免同意 / 需同意判定结果（接口文档 §4.2 三态）：
//   - NeedsConsent=false：请求 scope ⊆ 已授权且 prompt≠consent → 形态 C
//     免同意直签（调用方直接签码）；
//   - NeedsConsent=true：需同意展示（形态 B）；prompt=none 时调用方映射
//     302 consent_required 零交互（§4.2 prompt 分支）。
//
// GrantedScopes 为已授权并集（规范化空格口径，无记录 = ""），供形态 B
// 渲染已授权锁定项（已授权项不可取消，§4.2）；PendingScopes = 有效请求
// scope ∖ 已授权，供本次新请求项默认勾选。
type Decision struct {
	GrantedScopes string
	PendingScopes string
	NeedsConsent  bool
}

// promptConsent 强制同意展示的 prompt 取值（§4.2：有会话强制形态 B、
// 跳过免同意判定）。
const promptConsent = "consent"

// Decide 免同意 / 需同意判定（§14.2 步骤 3 内核）：读授权记录与有效请求
// scope 做子集比对——无记录按空集（全需同意）；子集 → 免同意，非子集 →
// 需同意（Pending 为需同意集合）。请求 scope 以缺省补值后的有效口径判定
// （EffectiveScope，§4.2 空 scope 按缺省补值判定）。prompt=consent 强制
// 需同意；其余取值（none / login / 空）不影响子集判定——prompt=none 的
// consent_required 302 等分支映射归调用方（§4.2 prompt 全分支）。
func (s *ConsentService) Decide(ctx context.Context, userID int64, clientID, reqScope, prompt string) (Decision, error) {
	record, err := s.grantedScopes(ctx, userID, clientID)
	if err != nil {
		return Decision{}, fmt.Errorf("oidc: consent decide: %w", err)
	}
	effective := ParseScopes(EffectiveScope(reqScope))
	granted := ParseScopes(record)
	pending := scopeDifference(effective, granted)
	return Decision{
		GrantedScopes: strings.Join(granted, " "),
		PendingScopes: strings.Join(pending, " "),
		NeedsConsent:  len(pending) > 0 || prompt == promptConsent,
	}, nil
}

// Grant 写授权记录（接口文档 §3.10 步骤 4、后端架构 §14.2 步骤 5）：经
// repo 行锁合并原语落库——单事务 FOR UPDATE 读现值（首插撞 uk 整事务回滚
// 重试），并集计算留在本层回调：旧已授权 ∪ 本次写入集（§4.5 只扩不缩）。
// 本次写入集为空按缺省补值口径取 DefaultScope（§4.2）。调用方须先经
// authz_validate 完成 scope 校验（必含 openid、⊆ 注册 scopes），本方法
// 不重复校验。失败路径原样上抛，由调用方按整体失败档位处理（§14.2 步骤 5：
// 写记录失败即整体登录失败，不签码）。
func (s *ConsentService) Grant(ctx context.Context, userID int64, clientID, scopes string) error {
	if s == nil || s.Consents == nil {
		return errConsentNotConfigured
	}
	add := EffectiveScope(scopes)
	if err := s.Consents.MergeConsent(ctx, userID, clientID, func(current string) (string, error) {
		return ScopeUnion(current, add), nil
	}); err != nil {
		return fmt.Errorf("oidc: consent grant: %w", err)
	}
	return nil
}

// grantedScopes 读已授权并集：无记录（包装的 sql.ErrNoRows）按
// 「从未同意 = 空集」口径返回空串（§4.5）；其余错误原样上抛由调用方包装。
func (s *ConsentService) grantedScopes(ctx context.Context, userID int64, clientID string) (string, error) {
	if s == nil || s.Consents == nil {
		return "", errConsentNotConfigured
	}
	record, err := s.Consents.GetConsentScopes(ctx, userID, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return record, nil
}

// scopeDifference 返回 a 中不在 b 的取值，保持 a 的出现顺序（需同意集合
// = 有效请求 scope ∖ 已授权）。
func scopeDifference(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

// 编译期断言：生产 repo 满足窄接口（签名漂移在编译期暴露）。
var _ ConsentRepo = (*repo.OidcConsentRepo)(nil)
