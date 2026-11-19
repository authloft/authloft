// oidc_consent 表 repo 层测试：真实测试实例经 UC_TEST_DB_DRIVER +
// UC_TEST_DB_DSN env 注入（兼容读 UC_TEST_MYSQL_DSN），无 env 时全部用例
// skip。表结构由迁移建（§3.16 DDL 唯一来源）；用例开始清空全表、结束
// 清空并自证零残留（同既有 repo 测试口径）。方言与清理 / 互斥细节见
// testsupport_test.go，本文件不自带 TestMain。连接串只经环境变量注入，
// 代码不含主机 / 凭证信息。
package repo

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"authloft/internal/repo/model"
)

// oidcConsentTestSetup 准备方言就绪的空库 + bun 连接（清空 → 建表 → 测后
// 零残留清理，口径见 testsupport_test.go），返回就绪的 OidcConsentRepo。
func oidcConsentTestSetup(t *testing.T) *OidcConsentRepo {
	t.Helper()
	return NewOidcConsentRepo(repoTestDB(t))
}

// TestOidcConsentGetMissing（env-skip）：空表取已授权并集 → 未命中返回包装
// 的 sql.ErrNoRows（从未同意属正常稳态，空集口径归上层 §4.5）。
func TestOidcConsentGetMissing(t *testing.T) {
	rp := oidcConsentTestSetup(t)
	ctx := context.Background()

	got, err := rp.GetConsentScopes(ctx, 1001, "oidc_app")
	if got != "" {
		t.Errorf("未命中应返回空串, got %q", got)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("未命中应 ErrRecordNotFound, got %v", err)
	}
}

// TestOidcConsentMerge（env-skip）：MergeConsent 行锁合并原语——首次写入
// 整行插入（created_at / updated_at 由 repo 写入路径补齐，回调现值为空集）→ 同键
// 再写走 uk_user_client 冲突更新，回调现值为已存值、scopes 刷新且
// created_at 保持首次授权时刻 → 不同键互不串行。回调返回值即写回值
// （并集计算归上层 §4.5，本文件以固定值回调模拟）。
func TestOidcConsentMerge(t *testing.T) {
	rp := oidcConsentTestSetup(t)
	ctx := context.Background()

	// 首次授权：整行插入，回调收到空集现值（从未同意）。
	var currents []string
	merge := func(scopes string) func(string) (string, error) {
		return func(current string) (string, error) {
			currents = append(currents, current)
			return scopes, nil
		}
	}
	if err := rp.MergeConsent(ctx, 2001, "oidc_app", merge("openid profile")); err != nil {
		t.Fatalf("首次 MergeConsent 失败: %v", err)
	}
	if len(currents) != 1 || currents[0] != "" {
		t.Errorf("首插回调现值 = %q, want [空串]", currents)
	}
	got, err := rp.GetConsentScopes(ctx, 2001, "oidc_app")
	if err != nil {
		t.Fatalf("GetConsentScopes 失败: %v", err)
	}
	if got != "openid profile" {
		t.Errorf("scopes = %q, want %q", got, "openid profile")
	}

	var row model.OidcConsent
	if err := dbTakeConsent(ctx, rp, 2001, "oidc_app", &row); err != nil {
		t.Fatalf("读回授权行失败: %v", err)
	}
	if row.CreatedAt.IsZero() || row.UpdatedAt.IsZero() {
		t.Error("插入应自动回填 created_at / updated_at")
	}
	firstCreatedAt := row.CreatedAt

	// 同键扩集再写：冲突更新 scopes，回调现值为已存值，created_at 保持
	// 首次授权时刻。
	if err := rp.MergeConsent(ctx, 2001, "oidc_app", merge("openid profile email offline_access")); err != nil {
		t.Fatalf("扩集 MergeConsent 失败: %v", err)
	}
	if len(currents) != 2 || currents[1] != "openid profile" {
		t.Errorf("扩集回调现值 = %q, want 第二次收到已存值", currents)
	}
	got, err = rp.GetConsentScopes(ctx, 2001, "oidc_app")
	if err != nil {
		t.Fatalf("扩集后 GetConsentScopes 失败: %v", err)
	}
	if got != "openid profile email offline_access" {
		t.Errorf("扩集后 scopes = %q, want %q", got, "openid profile email offline_access")
	}
	if err := dbTakeConsent(ctx, rp, 2001, "oidc_app", &row); err != nil {
		t.Fatalf("扩集后读回授权行失败: %v", err)
	}
	if !row.CreatedAt.Equal(firstCreatedAt) {
		t.Errorf("冲突更新不应覆盖 created_at: got %v, want %v", row.CreatedAt, firstCreatedAt)
	}

	// 其他用户 / 其他客户端互不串行。
	if err := rp.MergeConsent(ctx, 2001, "oidc_other", merge("openid")); err != nil {
		t.Fatalf("MergeConsent（其他客户端）失败: %v", err)
	}
	if err := rp.MergeConsent(ctx, 2002, "oidc_app", merge("openid profile")); err != nil {
		t.Fatalf("MergeConsent（其他用户）失败: %v", err)
	}
	if got, err := rp.GetConsentScopes(ctx, 2001, "oidc_other"); err != nil || got != "openid" {
		t.Errorf("client 隔离: got %q, err %v; want openid/nil", got, err)
	}
	if got, err := rp.GetConsentScopes(ctx, 2002, "oidc_app"); err != nil || got != "openid profile" {
		t.Errorf("user 隔离: got %q, err %v; want openid profile/nil", got, err)
	}
	if got, err := rp.GetConsentScopes(ctx, 2001, "oidc_app"); err != nil || got != "openid profile email offline_access" {
		t.Errorf("原行未被串写: got %q, err %v", got, err)
	}

	// 同键同值重写：冲突更新幂等，不报错。
	if err := rp.MergeConsent(ctx, 2001, "oidc_app", merge("openid profile email offline_access")); err != nil {
		t.Errorf("同值重写应幂等成功, got %v", err)
	}
}

// dbTakeConsent 按唯一键直读授权行（测试断言列值用）。
func dbTakeConsent(ctx context.Context, rp *OidcConsentRepo, userID int64, clientID string, row *model.OidcConsent) error {
	return rp.db.NewSelect().Model(row).
		Where("user_id = ? AND client_id = ?", userID, clientID).
		Limit(1).
		Scan(ctx)
}
