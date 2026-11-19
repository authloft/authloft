// 真库用例经 UC_TEST_DB_DRIVER + UC_TEST_DB_DSN 注入（兼容读
// UC_TEST_MYSQL_DSN）、无 env 时 skip。共享测试库靠命名锁串行并自证零
// 残留，避免兄弟二进制互相踩表；方言与清理 / 互斥细节见 testsupport_test.go。
// 连接串经 env 注入，代码不含主机或凭证。
package repo

import (
	"context"
	"testing"

	"authloft/internal/repo/model"
)

// TestPermissionRepoHasPermission（env-skip）：真库验证两类判定与错误上抛。
func TestPermissionRepoHasPermission(t *testing.T) {
	ctx := context.Background()
	db := repoTestDB(t)
	rp := NewPermissionRepo(db)

	// 空表不得误判为持有权限。
	if ok, err := rp.HasPermission(ctx, 1, "superadmin"); err != nil || ok {
		t.Fatalf("空表 HasPermission = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := rp.HasAnyPermission(ctx, 1); err != nil || ok {
		t.Fatalf("空表 HasAnyPermission = (%v, %v), want (false, nil)", ok, err)
	}

	// 仅安装账号持有权限点。
	if _, err := db.NewInsert().Model(&model.UserPermission{UserID: 1, Point: "superadmin"}).Exec(ctx); err != nil {
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

	// ListPermissions 返回该 uid 的全部权限点，ListAdminUIDs 返回去重的持有者集合。
	if points, err := rp.ListPermissions(ctx, 1); err != nil || len(points) != 1 || points[0] != "superadmin" {
		t.Errorf("ListPermissions(1) = (%v, %v), want ([superadmin], nil)", points, err)
	}
	if points, err := rp.ListPermissions(ctx, 2); err != nil || len(points) != 0 {
		t.Errorf("ListPermissions(2) = (%v, %v), want (empty, nil)", points, err)
	}
	if uids, err := rp.ListAdminUIDs(ctx); err != nil || len(uids) != 1 || uids[0] != 1 {
		t.Errorf("ListAdminUIDs = (%v, %v), want ([1], nil)", uids, err)
	}

	// 同一 uid 多个权限点、多个 uid 持有权限：列表全量、uid 集合去重。
	if _, err := db.NewInsert().Model(&model.UserPermission{UserID: 1, Point: "other"}).Exec(ctx); err != nil {
		t.Fatalf("插入第二权限点失败: %v", err)
	}
	if _, err := db.NewInsert().Model(&model.UserPermission{UserID: 2, Point: "superadmin"}).Exec(ctx); err != nil {
		t.Fatalf("插入第二持有者失败: %v", err)
	}
	if points, err := rp.ListPermissions(ctx, 1); err != nil || len(points) != 2 {
		t.Errorf("ListPermissions(1) 多点 = (%v, %v), want len 2", points, err)
	}
	if uids, err := rp.ListAdminUIDs(ctx); err != nil || len(uids) != 2 {
		t.Errorf("ListAdminUIDs 多持有者 = (%v, %v), want len 2（DISTINCT）", uids, err)
	}
}
