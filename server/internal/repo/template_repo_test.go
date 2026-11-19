// template 表 repo 层测试：真实测试实例经 UC_TEST_DB_DRIVER +
// UC_TEST_DB_DSN env 注入（兼容读 UC_TEST_MYSQL_DSN），无 env 时 skip。
// 表结构由迁移建（DDL 唯一来源）；用例开始清空全表、结束清空并自证
// 零残留（同既有 repo 测试口径）；方言与清理 / 互斥细节见
// testsupport_test.go。
package repo

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"authloft/internal/repo/model"
)

// templateTestSetup 准备方言就绪的空库 + bun 连接（清空 → 建表 → 测后
// 零残留清理，口径见 testsupport_test.go），返回就绪的 TemplateRepo。
func templateTestSetup(t *testing.T) *TemplateRepo {
	t.Helper()
	return NewTemplateRepo(repoTestDB(t))
}

// TestTemplateRepoCRUD 覆盖 Create / FindByKey / List / Update / Delete
// 与未命中语义；Update 允许改 key；重复 key 命中 ErrTemplateDuplicate。
func TestTemplateRepoCRUD(t *testing.T) {
	r := templateTestSetup(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	if _, err := r.FindByKey(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
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
	if _, err := r.FindByKey(ctx, "login_renamed"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Delete 后仍能查到: %v", err)
	}
	if err := r.Delete(ctx, got.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Delete 不存在行 err = %v, want ErrRecordNotFound", err)
	}
}
