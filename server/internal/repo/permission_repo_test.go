// 真库用例经 UC_TEST_MYSQL_DSN 注入、无 env 时 skip。共享测试库靠命名锁
// 串行并自证零残留，避免兄弟二进制互相踩表；辅助见 settings_repo_test.go。
// 连接串经 env 注入，代码不含主机或凭证。
package repo

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"authloft/internal/migrate"
	"authloft/internal/repo/model"
)

// TestPermissionRepoHasPermission（env-skip）：真库验证两类判定与错误上抛。
func TestPermissionRepoHasPermission(t *testing.T) {
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 permission repo 集成用例")
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
	rp := NewPermissionRepo(db)

	// 空表不得误判为持有权限。
	if ok, err := rp.HasPermission(ctx, 1, "superadmin"); err != nil || ok {
		t.Fatalf("空表 HasPermission = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := rp.HasAnyPermission(ctx, 1); err != nil || ok {
		t.Fatalf("空表 HasAnyPermission = (%v, %v), want (false, nil)", ok, err)
	}

	// 仅安装账号持有权限点。
	if err := db.WithContext(ctx).Create(&model.UserPermission{UserID: 1, Point: "superadmin"}).Error; err != nil {
		t.Fatalf("插入权限行失败: %v", err)
	}

	if ok, err := rp.HasPermission(ctx, 1, "superadmin"); err != nil || !ok {
		t.Errorf("HasPermission(1, superadmin) = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := rp.HasPermission(ctx, 1, "other"); err != nil || ok {
		t.Errorf("HasPermission(1, other) = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := rp.HasPermission(ctx, 2, "superadmin"); err != nil || ok {
		t.Errorf("HasPermission(2, superadmin) = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := rp.HasAnyPermission(ctx, 1); err != nil || !ok {
		t.Errorf("HasAnyPermission(1) = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := rp.HasAnyPermission(ctx, 2); err != nil || ok {
		t.Errorf("HasAnyPermission(2) = (%v, %v), want (false, nil)", ok, err)
	}
}
