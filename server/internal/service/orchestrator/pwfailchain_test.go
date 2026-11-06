// pwfailchain_test.go 真实链路测试：密码失败计数「因子写键 = 引擎
// 读键」。绝不按引擎口径直接种计数键制造通过（哨兵链漏检同款教训）——计数只能经真实 password.Factor.Verify 的失败路径
// 写入（Capture），引擎经注入的 UserRefResolver 读取（Count），任一侧键
// 口径漂移即断言失败。
package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/internal/factor"
	factorpassword "authloft/internal/factor/password"
	"authloft/internal/repo/model"
)

// pwChainUsers password.Users 子集 Fake：ByUsername 命中给定用户，其余
// 一律 NotFound（引擎与因子共用同一实例——装配方同样保证两侧同源）。
type pwChainUsers struct {
	user *model.User
}

func (u pwChainUsers) FindByUsername(context.Context, string) (*model.User, error) {
	if u.user != nil {
		return u.user, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (u pwChainUsers) FindByPhone(context.Context, string) (*model.User, error) {
	return nil, gorm.ErrRecordNotFound
}

func (u pwChainUsers) FindByEmail(context.Context, string) (*model.User, error) {
	return nil, gorm.ErrRecordNotFound
}

// pwChainIP 固定来源 IP 的 password.IPResolver Fake。
type pwChainIP struct{ ip string }

func (p pwChainIP) ClientIP(context.Context) string { return p.ip }

// memPwFails 进程内失败计数存储：同一实例注入因子（写 Capture）与引擎
// （读 Count），并记录两侧实际使用的键——键不一致即链路断裂。
type memPwFails struct {
	counts map[string]int64

	captured []string
	read     []string
}

func newMemPwFails() *memPwFails { return &memPwFails{counts: map[string]int64{}} }

func (m *memPwFails) Capture(_ context.Context, userRef string) (int64, error) {
	m.captured = append(m.captured, userRef)
	m.counts[userRef]++
	return m.counts[userRef], nil
}

func (m *memPwFails) Count(_ context.Context, userRef string) (int64, error) {
	m.read = append(m.read, userRef)
	return m.counts[userRef], nil
}

func (m *memPwFails) IsBanned(context.Context, string) (bool, error) { return false, nil }
func (m *memPwFails) Ban(context.Context, string) (bool, error)      { return true, nil }
func (m *memPwFails) BanRemaining(context.Context, string) (time.Duration, error) {
	return 0, nil
}

// expectedUnknownUserRef 独立于实现拼装期望键（ip|sha256 小写 hex），把
// §8.1 行 1027 的格式钉死：实现若改格式，测试必须同步改这里。
func expectedUnknownUserRef(identifier, ip string) string {
	sum := sha256.Sum256([]byte(identifier))
	return ip + "|" + hex.EncodeToString(sum[:])
}

// TestEnginePasswordCaptchaKeyMatchesFactorWrite 真实链路（核心）：
// 真实 password.Factor 失败写计数 ×3 → 第 4 次提交引擎读同一键计数 ≥3 →
// captcha_required。两个变体分别覆盖「用户存在 → {userID}」与「用户不存在
// → {ip}|{sha256(identifier)}」两种 user_ref 推导，并断言引擎读取键与因子
// 写入键逐字一致。
func TestEnginePasswordCaptchaKeyMatchesFactorWrite(t *testing.T) {
	cases := []struct {
		name       string
		identifier string
		users      pwChainUsers
		wantRef    string
	}{
		{
			name:       "unknown user uses ip|sha256 ref",
			identifier: "nosuch_zzz",
			users:      pwChainUsers{},
			wantRef:    expectedUnknownUserRef("nosuch_zzz", "10.0.0.1"),
		},
		{
			name:       "existing user uses userID ref",
			identifier: "alice",
			users:      pwChainUsers{user: &model.User{ID: 42, Username: "alice", UserStatus: 1}},
			wantRef:    "42",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := time.Unix(1_700_000_000, 0)
			deps := newTestDeps(t, at)
			fails := newMemPwFails()

			// 引擎侧：读计数走注入的共用解析器（与因子同一 Users / IP 实例）。
			deps.failures = fails
			deps.userRef = factorpassword.UserRefResolver{Users: tc.users, IP: pwChainIP{ip: "10.0.0.1"}}
			// 因子侧：真实 password.Factor，失败经 Capture 真实写入。
			// Credentials 空 → 凭证 NotFound → onFailure（两种变体同路径）。
			pw := factorpassword.New(tc.users, fails, nil, pwChainIP{ip: "10.0.0.1"}, factorpassword.DefaultOptions())
			deps.registry.factors[factor.FactorPassword] = pw
			e := deps.engine(testState(t, at))

			submit := func() string {
				resp := e.Submit(context.Background(), "login", Request{
					Method: "password", Step: "verify",
					Payload: &factor.Payload{Username: tc.identifier, Password: "wrong-password"},
				})
				return resp.Status
			}

			// 3 次错误密码：每次读取计数 0/1/2（未达阈值 3）放行 → 因子
			// 真实失败写入 1/2/3。凭据不存在 → invalid_credentials。
			for i := 1; i <= 3; i++ {
				if got := submit(); got != "invalid_credentials" {
					t.Fatalf("attempt %d status = %q, want invalid_credentials", i, got)
				}
			}
			// 第 4 次：引擎读到同一键计数 3 → captcha_required（因子执行前拦截）。
			if got := submit(); got != "captcha_required" {
				t.Fatalf("attempt 4 status = %q, want captcha_required", got)
			}

			// 键口径断言：因子写入键与引擎读取键全部等于期望 user_ref。
			if len(fails.captured) != 3 {
				t.Fatalf("captured keys = %v, want 3 captures", fails.captured)
			}
			for i, ref := range fails.captured {
				if ref != tc.wantRef {
					t.Fatalf("capture %d ref = %q, want %q", i+1, ref, tc.wantRef)
				}
			}
			if len(fails.read) == 0 {
				t.Fatal("engine never read the failure count")
			}
			for i, ref := range fails.read {
				if ref != tc.wantRef {
					t.Fatalf("read %d ref = %q, want %q (factor write key)", i+1, ref, tc.wantRef)
				}
			}
		})
	}
}

// TestEnginePasswordCaptchaNilResolverSkipsCount nil 安全：未注入解析器时
// 跳过计数读取（不触发渐进式保护），密码登录本身不受影响。
func TestEnginePasswordCaptchaNilResolverSkipsCount(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	fails := newMemPwFails()
	deps.failures = fails
	deps.userRef = nil
	pw := factorpassword.New(pwChainUsers{}, fails, nil, pwChainIP{ip: "10.0.0.1"}, factorpassword.DefaultOptions())
	deps.registry.factors[factor.FactorPassword] = pw
	e := deps.engine(testState(t, at))

	req := Request{Method: "password", Step: "verify",
		Payload: &factor.Payload{Username: "nosuch_zzz", Password: "wrong"}}
	for i := 1; i <= 4; i++ {
		resp := e.Submit(context.Background(), "login", req)
		if resp.Status != "invalid_credentials" {
			t.Fatalf("attempt %d status = %q, want invalid_credentials (nil resolver must skip count)", i, resp.Status)
		}
	}
	if len(fails.read) != 0 {
		t.Fatalf("nil resolver must not read count, read = %v", fails.read)
	}
	if len(fails.captured) != 4 {
		t.Fatalf("captured = %v, want 4 (factor writes still happen)", fails.captured)
	}
}

// TestEngineUserRefResolverErrorPropagates 解析器仓储错误上抛 → failed
//（与因子 Verify 的 lookup 错误口径一致，不吞错制造假放行）。
func TestEngineUserRefResolverErrorPropagates(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.failures = newMemPwFails()
	deps.userRef = stubUserRef{err: errors.New("db down")}
	deps.registry.factors[factor.FactorPassword] = passwordFactor(7)
	e := deps.engine(testState(t, at))

	resp := e.Submit(context.Background(), "login", Request{
		Method: "password", Step: "verify",
		Payload: &factor.Payload{Username: "alice", Password: "p"},
	})
	if resp.Status != StatusFailed {
		t.Fatalf("status = %q, want failed on resolver error", resp.Status)
	}
}
