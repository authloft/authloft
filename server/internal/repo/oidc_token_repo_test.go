// oidc_refresh_token 表 repo 层测试：真实 MariaDB 测试实例经
// UC_TEST_MYSQL_DSN env 注入，无 env 时全部用例 skip。表结构由 migrate.Up
// 建（§3.16 DDL 唯一来源）；用例开始 drop 全表、结束 drop 全表 +
// assertNoTables 自证零残留（同既有 repo 测试口径）。跨二进制互斥由
// settings_repo_test.go 的 TestMain（GET_LOCK uc_test_db_slot）保证；共享
// 辅助 dropAllTables / assertNoTables /
// dbTestConfig 在彼处与 db_test.go，本文件不自带 TestMain。连接串只经
// 环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/internal/migrate"
	"authloft/internal/repo/model"
)

// oidcTokenTestSetup 清库 + 建表 + 注册测后零残留清理，返回就绪的
// OidcTokenRepo。
func oidcTokenTestSetup(t *testing.T) *OidcTokenRepo {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 oidc token repo 集成用例")
	}
	ctx := context.Background()
	raw, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := raw.Ping(); err != nil {
		t.Fatalf("连接 MariaDB 测试实例失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := dropAllTables(raw); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	if err := migrate.Up(ctx, dsn); err != nil {
		t.Fatalf("migrate up 失败: %v", err)
	}
	t.Cleanup(func() {
		if err := dropAllTables(raw); err != nil {
			t.Errorf("测后清空测试库失败: %v", err)
		}
		if err := assertNoTables(raw); err != nil {
			t.Errorf("零残留自证失败: %v", err)
		}
	})
	db, err := Open(dbTestConfig(dsn, 10, 5, time.Minute))
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return NewOidcTokenRepo(db)
}

// oidcTestHash 构造 64 字符 token_hash（CHAR(64) 列宽），不同 seed 字符
// 保证唯一。
func oidcTestHash(seed byte) string {
	return strings.Repeat(string(seed), 64)
}

// oidcTestToken 构造一行刷新令牌（expiresAt 由调用方决定）。
func oidcTestToken(hash byte, clientID string, userID int64, sessionID, scopes string, expiresAt time.Time) *model.OidcRefreshToken {
	return &model.OidcRefreshToken{
		TokenHash: oidcTestHash(hash),
		ClientID:  clientID,
		UserID:    userID,
		SessionID: sessionID,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
	}
}

// TestOidcTokenRepoCreateAndFind（env-skip）：Create 回填 id / created_at
// → 按 token_hash 命中且字段一致 → 未命中 ErrRecordNotFound → uk_token_hash
// 冲突判错且不入库。
func TestOidcTokenRepoCreateAndFind(t *testing.T) {
	rp := oidcTokenTestSetup(t)
	ctx := context.Background()

	expiresAt := time.Now().Truncate(time.Second).Add(24 * time.Hour)
	tok := oidcTestToken('a', "oidc_app", 1001, "sess_1", "openid,profile", expiresAt)
	if err := rp.Create(ctx, tok); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	if tok.ID == 0 {
		t.Fatal("Create 后 ID 应非零（自增回填）")
	}
	if tok.CreatedAt.IsZero() {
		t.Error("Create 应自动填充 created_at")
	}
	if tok.RevokedAt != nil {
		t.Errorf("新建行 revoked_at 应为 NULL, got %v", tok.RevokedAt)
	}

	got, err := rp.FindByTokenHash(ctx, oidcTestHash('a'))
	if err != nil {
		t.Fatalf("FindByTokenHash 失败: %v", err)
	}
	if got.ID != tok.ID || got.TokenHash != oidcTestHash('a') ||
		got.ClientID != "oidc_app" || got.UserID != 1001 ||
		got.SessionID != "sess_1" || got.Scopes != "openid,profile" {
		t.Errorf("FindByTokenHash 字段不一致: %+v", got)
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Errorf("expires_at = %v, want %v", got.ExpiresAt, expiresAt)
	}
	if got.RevokedAt != nil {
		t.Errorf("未吊销行的 revoked_at 应为 NULL, got %v", got.RevokedAt)
	}

	// 未命中。
	if _, err := rp.FindByTokenHash(ctx, oidcTestHash('z')); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("未命中应 ErrRecordNotFound, got %v", err)
	}

	// uk_token_hash 冲突：同 token_hash 再建 → 报错、不入库。
	if err := rp.Create(ctx, oidcTestToken('a', "oidc_other", 1002, "", "", expiresAt)); err == nil {
		t.Error("同 token_hash 冲突应报错, got nil")
	}
	if rows, err := rp.ListByClientAndUser(ctx, "oidc_app", 1001); err != nil || len(rows) != 1 {
		t.Errorf("冲突不应入库: rows=%d err=%v; want 1/nil", len(rows), err)
	}
}

// TestOidcTokenRepoRevoke（env-skip）：按 token_hash 原子吊销（首次 true、
// 重复 / 未知 false）→ 按 user_id / session_id 批量吊销只命中未吊销行 →
// 按 client+user 列表隔离与 id DESC 稳定顺序。
func TestOidcTokenRepoRevoke(t *testing.T) {
	rp := oidcTokenTestSetup(t)
	ctx := context.Background()
	revokedAt := time.Now().Truncate(time.Second)
	future := revokedAt.Add(24 * time.Hour)

	// 同一 client 下：u1/s1 两枚、u1/s2 一枚、u2/s1 一枚。
	seeds := []struct {
		hash  byte
		user  int64
		sesID string
	}{
		{'a', 2001, "sess_1"},
		{'b', 2001, "sess_1"},
		{'c', 2001, "sess_2"},
		{'d', 2002, "sess_1"},
	}
	for _, s := range seeds {
		if err := rp.Create(ctx, oidcTestToken(s.hash, "oidc_app", s.user, s.sesID, "openid", future)); err != nil {
			t.Fatalf("Create token %c 失败: %v", s.hash, err)
		}
	}

	// 单令牌原子吊销：首次 true；重复 / 未知 false、不报错。
	ok, err := rp.RevokeByTokenHash(ctx, oidcTestHash('a'), revokedAt)
	if err != nil || !ok {
		t.Fatalf("首次吊销应 true, got %v, %v", ok, err)
	}
	got, err := rp.FindByTokenHash(ctx, oidcTestHash('a'))
	if err != nil {
		t.Fatalf("吊销后 Find 失败: %v", err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
		t.Errorf("revoked_at = %v, want %v", got.RevokedAt, revokedAt)
	}
	if ok, err := rp.RevokeByTokenHash(ctx, oidcTestHash('a'), revokedAt.Add(time.Minute)); err != nil || ok {
		t.Errorf("重复吊销应 false, nil; got %v, %v", ok, err)
	}
	if got, err := rp.FindByTokenHash(ctx, oidcTestHash('a')); err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
		t.Errorf("重复吊销不应覆盖首次 revoked_at: %+v, err %v", got, err)
	}
	if ok, err := rp.RevokeByTokenHash(ctx, oidcTestHash('z'), revokedAt); err != nil || ok {
		t.Errorf("未知令牌吊销应 false, nil; got %v, %v", ok, err)
	}

	// 按 user_id 批量吊销：u1 剩 b / c 两枚未吊销；a 已吊销不重复计数。
	n, err := rp.RevokeByUserID(ctx, 2001, revokedAt)
	if err != nil || n != 2 {
		t.Fatalf("RevokeByUserID = %d, err %v; want 2, nil", n, err)
	}
	for _, seed := range []byte{'b', 'c'} {
		row, err := rp.FindByTokenHash(ctx, oidcTestHash(seed))
		if err != nil || row.RevokedAt == nil || !row.RevokedAt.Equal(revokedAt) {
			t.Errorf("user 批量吊销后 token %c = %+v, err %v", seed, row, err)
		}
	}
	if row, err := rp.FindByTokenHash(ctx, oidcTestHash('d')); err != nil || row.RevokedAt != nil {
		t.Errorf("其他用户令牌不应被吊销: %+v, err %v", row, err)
	}
	if n, err := rp.RevokeByUserID(ctx, 2001, revokedAt); err != nil || n != 0 {
		t.Errorf("重复批量吊销应 0, nil; got %d, %v", n, err)
	}

	// 按 session_id 批量吊销：s1 中 a / b 已吊销，只剩 d 未吊销。
	if n, err := rp.RevokeBySessionID(ctx, "sess_1", revokedAt); err != nil || n != 1 {
		t.Errorf("RevokeBySessionID = %d, err %v; want 1, nil", n, err)
	}
	if n, err := rp.RevokeBySessionID(ctx, "sess_1", revokedAt); err != nil || n != 0 {
		t.Errorf("重复按会话吊销应 0, nil; got %d, %v", n, err)
	}

	// 按 client+user 列表：含已吊销行，id DESC（c / b / a）。
	rows, err := rp.ListByClientAndUser(ctx, "oidc_app", 2001)
	if err != nil {
		t.Fatalf("ListByClientAndUser 失败: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("u1 列表 = %d 行, want 3", len(rows))
	}
	for i, want := range []byte{'c', 'b', 'a'} {
		if rows[i].TokenHash != oidcTestHash(want) {
			t.Errorf("列表顺序[%d] = %q, want %q（id DESC）", i, rows[i].TokenHash, oidcTestHash(want))
		}
	}
	// 用户隔离 / 客户端隔离。
	if rows, err := rp.ListByClientAndUser(ctx, "oidc_app", 2002); err != nil || len(rows) != 1 || rows[0].TokenHash != oidcTestHash('d') {
		t.Errorf("u2 列表 = %+v, err %v; want 仅 d", rows, err)
	}
	if rows, err := rp.ListByClientAndUser(ctx, "oidc_other", 2001); err != nil || len(rows) != 0 {
		t.Errorf("其他 client 列表应为空: %+v, err %v", rows, err)
	}
}

// TestOidcTokenRepoDeleteExpired（env-skip）：删除 now 时点已过期行、保留
// 未过期行并返回删除行数；重复清理幂等。
func TestOidcTokenRepoDeleteExpired(t *testing.T) {
	rp := oidcTokenTestSetup(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	expiredA := now.Add(-time.Hour)
	expiredB := now.Add(-time.Minute)
	live := now.Add(24 * time.Hour)
	for _, s := range []struct {
		hash byte
		user int64
		exp  time.Time
	}{
		{'a', 3001, expiredA},
		{'b', 3002, expiredB},
		{'c', 3001, live},
	} {
		if err := rp.Create(ctx, oidcTestToken(s.hash, "oidc_app", s.user, "sess_1", "openid", s.exp)); err != nil {
			t.Fatalf("Create token %c 失败: %v", s.hash, err)
		}
	}

	n, err := rp.DeleteExpired(ctx, now)
	if err != nil || n != 2 {
		t.Fatalf("DeleteExpired = %d, err %v; want 2, nil", n, err)
	}
	if rows, err := rp.ListByClientAndUser(ctx, "oidc_app", 3001); err != nil || len(rows) != 1 || rows[0].TokenHash != oidcTestHash('c') {
		t.Errorf("清理后应只剩未过期行 c: %+v, err %v", rows, err)
	}
	if rows, err := rp.ListByClientAndUser(ctx, "oidc_app", 3002); err != nil || len(rows) != 0 {
		t.Errorf("已过期行应全部删除: %+v, err %v", rows, err)
	}
	if n, err := rp.DeleteExpired(ctx, now); err != nil || n != 0 {
		t.Errorf("重复清理应 0, nil; got %d, %v", n, err)
	}
}
