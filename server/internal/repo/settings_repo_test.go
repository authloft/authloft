// settings 表 repo 层测试：真实测试实例经 UC_TEST_DB_DRIVER +
// UC_TEST_DB_DSN env 注入（兼容读 UC_TEST_MYSQL_DSN），无 env 时 skip。
// 表结构由迁移建（§3.16 DDL 唯一来源）；用例开始清空全表、结束清空并
// 自证零残留（清理口径与既有 DB 测试一致）；方言与清理 / 互斥细节见
// testsupport_test.go。连接串只经环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"context"
	"testing"
	"time"

	"authloft/internal/repo/model"
)

// TestSettingsRepoRoundTrip（env-skip）：LoadAll 空表 → UpsertAll 插入 →
// UpsertAll 更新（v / updated_by 变更，未涉及行不动）→ InsertIgnoreAll
// 不覆写已有行、只补缺失行；空集短路。
func TestSettingsRepoRoundTrip(t *testing.T) {
	ctx := context.Background()
	rp := NewSettingsRepo(repoTestDB(t))

	// 空表 LoadAll：空集、无错误。
	rows, err := rp.LoadAll(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("空表 LoadAll = %d 行, err %v；want 0, nil", len(rows), err)
	}

	// UpsertAll 插入两行（v 为 §4.7 JSON 编码口径）。
	now := time.Now()
	if err := rp.UpsertAll(ctx, []model.Setting{
		{K: "pwd_min_length", V: "8", UpdatedAt: now, UpdatedBy: 0},
		{K: "cookie_name", V: `"al_session"`, UpdatedAt: now, UpdatedBy: 0},
	}); err != nil {
		t.Fatalf("UpsertAll 插入失败: %v", err)
	}
	rows, err = rp.LoadAll(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("插入后 LoadAll = %d 行, err %v；want 2", len(rows), err)
	}
	byKey := map[string]model.Setting{}
	for _, r := range rows {
		byKey[r.K] = r
	}
	if r := byKey["pwd_min_length"]; r.V != "8" || r.UpdatedBy != 0 {
		t.Errorf("pwd_min_length 行 = %+v", r)
	}
	if r := byKey["cookie_name"]; r.V != `"al_session"` {
		t.Errorf("cookie_name 行 v = %q", r.V)
	}

	// UpsertAll 更新：v 与 updated_by 变更，未涉及行不动。
	later := now.Add(time.Hour)
	if err := rp.UpsertAll(ctx, []model.Setting{
		{K: "pwd_min_length", V: "10", UpdatedAt: later, UpdatedBy: 42},
	}); err != nil {
		t.Fatalf("UpsertAll 更新失败: %v", err)
	}
	rows, err = rp.LoadAll(ctx)
	if err != nil {
		t.Fatalf("更新后 LoadAll: %v", err)
	}
	byKey = map[string]model.Setting{}
	for _, r := range rows {
		byKey[r.K] = r
	}
	if r := byKey["pwd_min_length"]; r.V != "10" || r.UpdatedBy != 42 {
		t.Errorf("更新后 pwd_min_length = %+v；want v=10 by=42", r)
	}
	if r := byKey["cookie_name"]; r.V != `"al_session"` || r.UpdatedBy != 0 {
		t.Errorf("未涉及行不应变动: %+v", r)
	}

	// InsertIgnoreAll：已有行不覆写（保持 v=10），缺失行补入。
	if err := rp.InsertIgnoreAll(ctx, []model.Setting{
		{K: "pwd_min_length", V: "8", UpdatedAt: later.Add(time.Hour), UpdatedBy: 0},
		{K: "otp_ttl", V: "300", UpdatedAt: later.Add(time.Hour), UpdatedBy: 0},
	}); err != nil {
		t.Fatalf("InsertIgnoreAll 失败: %v", err)
	}
	rows, err = rp.LoadAll(ctx)
	if err != nil || len(rows) != 3 {
		t.Fatalf("InsertIgnore 后 LoadAll = %d 行, err %v；want 3", len(rows), err)
	}
	byKey = map[string]model.Setting{}
	for _, r := range rows {
		byKey[r.K] = r
	}
	if r := byKey["pwd_min_length"]; r.V != "10" || r.UpdatedBy != 42 {
		t.Errorf("InsertIgnore 不得覆写已有行: %+v", r)
	}
	if r := byKey["otp_ttl"]; r.V != "300" {
		t.Errorf("缺失行应补入 otp_ttl=300: %+v", r)
	}

	// 空集短路：无错误、无副作用。
	if err := rp.UpsertAll(ctx, nil); err != nil {
		t.Errorf("UpsertAll 空集应 nil: %v", err)
	}
	if err := rp.InsertIgnoreAll(ctx, nil); err != nil {
		t.Errorf("InsertIgnoreAll 空集应 nil: %v", err)
	}
}
