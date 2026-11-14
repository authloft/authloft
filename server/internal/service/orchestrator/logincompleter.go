// logincompleter.go step-up 成功结论接回登录终点（docs/后端架构.md §3.6
// logincompleter 规划项、§3.8.1）：实现 verification.LoginCompleter /
// LoginTokenReader 的登录过程态适配器，复用同一个 Terminal 建会话。
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"authloft/gen/go/token"
	"authloft/internal/service/verification"
)

// LoginTokenReader 把登录过程态编解码器适配为 step-up 主体推导出口
// （§3.8.1：uid != 0 且 passed 非空，防止绕过主因子）。
type LoginTokenReader struct {
	state *State
}

func (r LoginTokenReader) Read(_ context.Context, tok string) (int64, bool, error) {
	p, err := r.state.Parse(tok)
	if err != nil {
		return 0, false, err
	}
	return p.GetUid(), len(p.GetPassed()) > 0, nil
}

// LoginCompleter 把 step-up 的成功结论接回既有登录终点（§7.3 步骤 7）：
// 复用同一个 Terminal 建会话、投递登录日志、拼多域名同步链
// 与 OIDC 跳转；登录链路另附 loginToken 时恢复其 oidc / tid / passed，
// uid 仍以挑战令牌主体为准（§3.8.5）。会话令牌经调用方注入的写点下发
// （与 LoginDefault 同一 Set-Cookie 出口）。
type LoginCompleter struct {
	terminal *Terminal
	state    *State
}

func (c LoginCompleter) Complete(ctx context.Context, subject verification.Subject, loginToken, method string) (verification.LoginSession, error) {
	if c.terminal == nil {
		return verification.LoginSession{}, fmt.Errorf("login completer: terminal not configured")
	}
	uid, err := strconv.ParseInt(subject.ID, 10, 64)
	if err != nil || uid <= 0 {
		return verification.LoginSession{}, fmt.Errorf("%w: subject uid %q", verification.ErrLoginContext, subject.ID)
	}

	// 默认最小载荷（纯直登场景）；携带 loginToken 时以解析结果整体覆盖，
	// 恢复 Oidc / Tid / Passed，仅以挑战令牌主体覆盖 Uid。
	p := &token.LoginTokenPayload{Tid: subject.ID}
	if loginToken != "" {
		if c.state == nil {
			return verification.LoginSession{}, fmt.Errorf("%w: login state not configured", verification.ErrLoginContext)
		}
		parsed, err := c.state.Parse(loginToken)
		if err != nil {
			// 保留底层令牌错误的 errors.Is 链：按过期 / 篡改分别包装成
			// 服务层可判别的主体凭证哨兵（§3.8.5 的 token_expired /
			// token_invalid），ErrLoginContext 一并保留供未知失败收敛。
			switch {
			case errors.Is(err, ErrTokenExpired):
				return verification.LoginSession{}, fmt.Errorf("%w: %w: %w", verification.ErrLoginContext, verification.ErrLoginTokenExpired, err)
			case errors.Is(err, ErrTokenInvalid):
				return verification.LoginSession{}, fmt.Errorf("%w: %w: %w", verification.ErrLoginContext, verification.ErrLoginTokenInvalid, err)
			default:
				return verification.LoginSession{}, fmt.Errorf("%w: %w", verification.ErrLoginContext, err)
			}
		}
		if parsed.GetUid() != uid {
			return verification.LoginSession{}, fmt.Errorf("%w: uid %d != challenge subject %d", verification.ErrLoginContext, parsed.GetUid(), uid)
		}
		p = parsed
	}
	p.Uid = uid
	// 会话 amr 取原 passed / amr 与本次二次因子的并集，不覆盖成单一因子。
	p.Amr = mergeAMR(p.GetAmr(), p.GetPassed(), method)

	success, err := c.terminal.Complete(ctx, p)
	if err != nil {
		return verification.LoginSession{}, err
	}
	if sink, ok := SessionTokenSinkFromContext(ctx); ok {
		sink(success.SessionToken)
	}
	return verification.LoginSession{
		RedirectTo:    success.RedirectTo,
		SyncCookieURL: success.SyncCookieURL,
	}, nil
}

// mergeAMR 按首次出现顺序合并认证方法，去掉空值与重复项。
func mergeAMR(amr, passed []string, method string) []string {
	out := make([]string, 0, len(amr)+len(passed)+1)
	seen := map[string]bool{}
	add := func(m string) {
		if m == "" || seen[m] {
			return
		}
		seen[m] = true
		out = append(out, m)
	}
	for _, m := range amr {
		add(m)
	}
	for _, m := range passed {
		add(m)
	}
	add(method)
	return out
}

// NewLoginCompleter 注入登录终点与登录过程态（装配层构造）。
func NewLoginCompleter(terminal *Terminal, state *State) *LoginCompleter {
	return &LoginCompleter{terminal: terminal, state: state}
}

// NewLoginTokenReader 注入登录过程态（装配层构造）。
func NewLoginTokenReader(state *State) *LoginTokenReader {
	return &LoginTokenReader{state: state}
}
