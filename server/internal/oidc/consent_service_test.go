// consent_service.go 测试：Decide 三态判定内核（子集 / 非子集 / 无记录 /
// prompt 语义 / 有效 scope 口径）与 Grant 行锁合并写回（回调收现值 / 并发
// 不丢侧 / 首插撞 uk 重试）、失败路径、空集口径。
package oidc

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"database/sql"
)

// fakeConsentRepo ConsentRepo fake：records 以 uid → clientID → scopes 原文
// 承载；MergeConsent 按行锁原语契约仿真——读现值 → 回调算新值 → 写回，
// 回调现值序列记入 callbackCurrents。conflictOnce 模拟首插撞 uk_user_client：
// 无记录时首次事务内冲突，注入对手方已提交行（winner）后整事务回滚重试
// （真实现为回滚重读），验证回调以新现值重算不丢侧。getErr / mergeErr
// 模拟读 / 合并原语故障。
type fakeConsentRepo struct {
	records          map[int64]map[string]string
	getErr           error
	mergeErr         error
	conflictOnce     bool
	winner           string
	callbackCurrents []string
}

func (f *fakeConsentRepo) lookup(userID int64, clientID string) string {
	if row, ok := f.records[userID]; ok {
		return row[clientID] // 无该 client 键时零值即空串（从未同意 = 空集）
	}
	return ""
}

func (f *fakeConsentRepo) store(userID int64, clientID, scopes string) {
	if f.records == nil {
		f.records = map[int64]map[string]string{}
	}
	if f.records[userID] == nil {
		f.records[userID] = map[string]string{}
	}
	f.records[userID][clientID] = scopes
}

func (f *fakeConsentRepo) GetConsentScopes(_ context.Context, userID int64, clientID string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	if _, ok := f.records[userID]; !ok {
		return "", fmt.Errorf("fake repo: %w", sql.ErrNoRows)
	}
	scopes := f.records[userID][clientID]
	if _, ok := f.records[userID][clientID]; !ok {
		return "", fmt.Errorf("fake repo: %w", sql.ErrNoRows)
	}
	return scopes, nil
}

func (f *fakeConsentRepo) MergeConsent(_ context.Context, userID int64, clientID string, merge func(current string) (string, error)) error {
	if f.mergeErr != nil {
		return f.mergeErr
	}
	for attempt := 0; ; attempt++ {
		current := f.lookup(userID, clientID)
		f.callbackCurrents = append(f.callbackCurrents, current)
		next, err := merge(current)
		if err != nil {
			return err
		}
		if f.conflictOnce && attempt == 0 && current == "" {
			f.conflictOnce = false
			f.store(userID, clientID, f.winner)
			continue
		}
		f.store(userID, clientID, next)
		return nil
	}
}

func TestConsentDecide(t *testing.T) {
	ctx := context.Background()
	newRepo := func(records map[int64]map[string]string) *fakeConsentRepo {
		return &fakeConsentRepo{records: records}
	}

	t.Run("无记录全需同意（从未同意 = 空集）", func(t *testing.T) {
		s := &ConsentService{Consents: newRepo(nil)}
		d, err := s.Decide(ctx, 1, "app", "openid profile", "")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !d.NeedsConsent || d.GrantedScopes != "" {
			t.Errorf("Decision = %+v, want 需同意且 Granted 为空", d)
		}
		if d.PendingScopes != "openid profile" {
			t.Errorf("PendingScopes = %q, want 全量请求 scope", d.PendingScopes)
		}
	})
	t.Run("子集免同意", func(t *testing.T) {
		s := &ConsentService{Consents: newRepo(map[int64]map[string]string{
			1: {"app": "openid profile email"},
		})}
		d, err := s.Decide(ctx, 1, "app", "openid profile", "")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if d.NeedsConsent {
			t.Errorf("Decision = %+v, want 免同意", d)
		}
		if d.GrantedScopes != "openid profile email" || d.PendingScopes != "" {
			t.Errorf("Decision = %+v", d)
		}
	})
	t.Run("非子集需同意且 Pending 为差集", func(t *testing.T) {
		s := &ConsentService{Consents: newRepo(map[int64]map[string]string{
			1: {"app": "openid profile"},
		})}
		d, err := s.Decide(ctx, 1, "app", "openid profile email", "")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !d.NeedsConsent {
			t.Errorf("Decision = %+v, want 需同意", d)
		}
		if d.PendingScopes != "email" {
			t.Errorf("PendingScopes = %q, want email", d.PendingScopes)
		}
	})
	t.Run("prompt=consent 强制需同意（子集也展示）", func(t *testing.T) {
		s := &ConsentService{Consents: newRepo(map[int64]map[string]string{
			1: {"app": "openid profile"},
		})}
		d, err := s.Decide(ctx, 1, "app", "openid profile", promptConsent)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !d.NeedsConsent {
			t.Errorf("Decision = %+v, want 强制需同意", d)
		}
		if d.PendingScopes != "" || d.GrantedScopes != "openid profile" {
			t.Errorf("Decision = %+v", d)
		}
	})
	t.Run("prompt=none 不改变子集判定", func(t *testing.T) {
		s := &ConsentService{Consents: newRepo(map[int64]map[string]string{
			1: {"app": "openid profile"},
		})}
		subset, err := s.Decide(ctx, 1, "app", "openid", "none")
		if err != nil || subset.NeedsConsent {
			t.Errorf("subset Decision = %+v, err = %v, want 免同意", subset, err)
		}
		grown, err := s.Decide(ctx, 1, "app", "openid profile email", "none")
		if err != nil || !grown.NeedsConsent {
			t.Errorf("grown Decision = %+v, err = %v, want 需同意（调用方映射 consent_required）", grown, err)
		}
	})
	t.Run("空请求 scope 按缺省补值判定", func(t *testing.T) {
		s := &ConsentService{Consents: newRepo(map[int64]map[string]string{
			1: {"app": "openid"},
		})}
		d, err := s.Decide(ctx, 1, "app", "", "")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !d.NeedsConsent || d.PendingScopes != "profile email" {
			t.Errorf("Decision = %+v, want 按缺省 %q 判定差集 profile email", d, DefaultScope)
		}
	})
	t.Run("记录解析容错（空 token / 逗号残留）", func(t *testing.T) {
		s := &ConsentService{Consents: newRepo(map[int64]map[string]string{
			1: {"app": ",openid profile"},
		})}
		d, err := s.Decide(ctx, 1, "app", "openid", "")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if d.NeedsConsent || d.GrantedScopes != "openid profile" {
			t.Errorf("Decision = %+v, want 免同意且 Granted=openid profile", d)
		}
	})
	t.Run("读故障上抛", func(t *testing.T) {
		boom := errors.New("db down")
		s := &ConsentService{Consents: &fakeConsentRepo{getErr: boom}}
		if _, err := s.Decide(ctx, 1, "app", "openid", ""); !errors.Is(err, boom) {
			t.Errorf("err = %v, want 包装上抛", err)
		}
	})
	t.Run("依赖未注入", func(t *testing.T) {
		s := &ConsentService{}
		if _, err := s.Decide(ctx, 1, "app", "openid", ""); !errors.Is(err, errConsentNotConfigured) {
			t.Errorf("err = %v, want errConsentNotConfigured", err)
		}
	})
}

func TestConsentGrant(t *testing.T) {
	ctx := context.Background()

	t.Run("首次授权整行并集，回调收空集现值", func(t *testing.T) {
		f := &fakeConsentRepo{records: nil}
		s := &ConsentService{Consents: f}
		if err := s.Grant(ctx, 7, "app", "openid profile"); err != nil {
			t.Fatalf("err = %v", err)
		}
		if got := f.lookup(7, "app"); got != "openid profile" {
			t.Errorf("scopes = %q, want openid profile", got)
		}
		if len(f.callbackCurrents) != 1 || f.callbackCurrents[0] != "" {
			t.Errorf("回调现值序列 = %q, want [空串]", f.callbackCurrents)
		}
	})
	t.Run("追加并集只扩不缩，回调收已存现值", func(t *testing.T) {
		f := &fakeConsentRepo{records: map[int64]map[string]string{
			7: {"app": "openid profile"},
		}}
		s := &ConsentService{Consents: f}
		if err := s.Grant(ctx, 7, "app", "email openid"); err != nil {
			t.Fatalf("err = %v", err)
		}
		if got := f.lookup(7, "app"); got != "openid profile email" {
			t.Errorf("scopes = %q, want openid profile email", got)
		}
		if len(f.callbackCurrents) != 1 || f.callbackCurrents[0] != "openid profile" {
			t.Errorf("回调现值序列 = %q, want [openid profile]", f.callbackCurrents)
		}
	})
	t.Run("并发授权行锁串行化后两侧不丢", func(t *testing.T) {
		// 行锁将同键并发授权串行化：后到事务必读到先到事务的提交结果
		// （原语契约），两次授权的并集两侧均保留。
		f := &fakeConsentRepo{records: map[int64]map[string]string{
			7: {"app": "openid profile"},
		}}
		s := &ConsentService{Consents: f}
		if err := s.Grant(ctx, 7, "app", "email"); err != nil {
			t.Fatalf("grant A: %v", err)
		}
		if err := s.Grant(ctx, 7, "app", "phone"); err != nil {
			t.Fatalf("grant B: %v", err)
		}
		if got := f.lookup(7, "app"); got != "openid profile email phone" {
			t.Errorf("scopes = %q, want openid profile email phone", got)
		}
	})
	t.Run("首插撞 uk 重试后重算不丢侧", func(t *testing.T) {
		// 无记录首插撞 uk_user_client：整事务回滚重试，对手方已提交行
		// 成为重试现值——回调以新现值重算，对手方与本次写入侧均保留。
		f := &fakeConsentRepo{conflictOnce: true, winner: "openid"}
		s := &ConsentService{Consents: f}
		if err := s.Grant(ctx, 7, "app", "openid email"); err != nil {
			t.Fatalf("err = %v", err)
		}
		if got := f.lookup(7, "app"); got != "openid email" {
			t.Errorf("scopes = %q, want openid email（两侧均保留）", got)
		}
		if len(f.callbackCurrents) != 2 || f.callbackCurrents[0] != "" || f.callbackCurrents[1] != "openid" {
			t.Errorf("回调现值序列 = %q, want [空串, openid]", f.callbackCurrents)
		}
	})
	t.Run("空写入集按缺省补值口径", func(t *testing.T) {
		f := &fakeConsentRepo{records: nil}
		s := &ConsentService{Consents: f}
		if err := s.Grant(ctx, 7, "app", ""); err != nil {
			t.Fatalf("err = %v", err)
		}
		if got := f.lookup(7, "app"); got != DefaultScope {
			t.Errorf("scopes = %q, want %q", got, DefaultScope)
		}
	})
	t.Run("原语失败原样上抛（整体失败档位由调用方处理）", func(t *testing.T) {
		boom := errors.New("merge down")
		f := &fakeConsentRepo{records: nil, mergeErr: boom}
		s := &ConsentService{Consents: f}
		if err := s.Grant(ctx, 7, "app", "openid"); !errors.Is(err, boom) {
			t.Errorf("err = %v, want 包装上抛", err)
		}
		if len(f.callbackCurrents) != 0 {
			t.Errorf("原语失败不应执行回调, currents = %q", f.callbackCurrents)
		}
	})
	t.Run("依赖未注入", func(t *testing.T) {
		s := &ConsentService{}
		if err := s.Grant(ctx, 7, "app", "openid"); !errors.Is(err, errConsentNotConfigured) {
			t.Errorf("err = %v, want errConsentNotConfigured", err)
		}
	})
}
