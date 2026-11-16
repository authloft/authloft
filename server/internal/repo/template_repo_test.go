// template 表 repo 层测试：真实 MariaDB 测试实例经 UC_TEST_MYSQL_DSN
// env 注入，无 env 时 skip。表结构由 migrate.Up 建（DDL 唯一来源）；用例
// 开始 drop 全表、结束 drop 全表 + assertNoTables 自证零残留（同既有 repo
// 测试口径）；跨二进制互斥由 settings_repo_test.go 的 TestMain 保证。
package repo

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/internal/migrate"
	"authloft/internal/repo/model"
)

// templateTestSetup 清库 + 建表 + 注册测后零残留清理，返回就绪的
// TemplateRepo。
func templateTestSetup(t *testing.T) *TemplateRepo {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 template repo 集成用例")
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
	return NewTemplateRepo(db)
}

// TestTemplateRepoCRUD 覆盖 Create / FindByKey / List / Update / Delete
// 与未命中语义；Update 允许改 key；重复 key 命中 ErrTemplateDuplicate。
func TestTemplateRepoCRUD(t *testing.T) {
	r := templateTestSetup(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	if _, err := r.FindByKey(ctx, "missing"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("FindByKey(missing) err = %v, want ErrRecordNotFound", err)
	}

	row := &model.Template{
		TemplateKey: "login_custom",
		Name:        "自定义登录",
		Content:     "<html>one</html>",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := r.Create(ctx, row); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if row.ID == 0 {
		t.Error("Create 未回填主键")
	}

	got, err := r.FindByKey(ctx, "login_custom")
	if err != nil {
		t.Fatalf("FindByKey: %v", err)
	}
	if got.Content != row.Content || got.Name != row.Name {
		t.Errorf("FindByKey 与入参不一致: %+v", got)
	}

	dup := &model.Template{
		TemplateKey: "login_custom",
		Content:     "dup",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := r.Create(ctx, dup); !errors.Is(err, ErrTemplateDuplicate) {
		t.Errorf("Create 重复 key err = %v, want ErrTemplateDuplicate", err)
	}

	rows, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("List 行数 = %d, want 1", len(rows))
	}

	got.TemplateKey = "login_renamed"
	got.Content = "<html>two</html>"
	if err := r.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := r.FindByKey(ctx, "login_renamed"); err != nil {
		t.Errorf("Update 后新 key 查不到: %v", err)
	}

	if err := r.Delete(ctx, got.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.FindByKey(ctx, "login_renamed"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Delete 后仍能查到: %v", err)
	}
	if err := r.Delete(ctx, got.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Delete 不存在行 err = %v, want ErrRecordNotFound", err)
	}
}
