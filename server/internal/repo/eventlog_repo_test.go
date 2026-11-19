// event_log 表 repo 层测试：真实测试实例经 UC_TEST_DB_DRIVER +
// UC_TEST_DB_DSN env 注入（兼容读 UC_TEST_MYSQL_DSN），无 env 时全部用例
// skip。表结构由迁移建（§3.16 DDL 唯一来源）；用例开始清空全表、结束
// 清空并自证零残留（同既有 repo 测试口径）。方言与清理 / 互斥细节见
// testsupport_test.go，本文件不自带 TestMain。连接串只经环境变量注入，
// 代码不含主机 / 凭证信息。
package repo

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/config"
	"authloft/internal/repo/model"
)

// eventLogTestSetup 准备方言就绪的空库 + bun 连接（清空 → 建表 → 测后
// 零残留清理，口径见 testsupport_test.go），返回就绪的 EventLogRepo 与
// bun 连接（后者供用例回读断言）。
func eventLogTestSetup(t *testing.T) (*EventLogRepo, *bun.DB) {
	t.Helper()
	db := repoTestDB(t)
	return NewEventLogRepo(db), db
}

// TestEventLogRepoBatchInsert（env-skip）：批量写入后字段原样回读；
// 零值 default 列取 DDL 默认；detail nil → NULL、非 nil（含空字节）→ 原样
// 落库；created_at 显式值保留、零值由 repo 填当前时刻。
func TestEventLogRepoBatchInsert(t *testing.T) {
	rp, db := eventLogTestSetup(t)
	ctx := context.Background()

	fixed := time.Now().Truncate(time.Second).Add(-time.Hour)
	detail := []byte{0x00, 0x01, 0x7f, 0xff}
	before := time.Now()
	rows := []model.EventLog{
		{
			Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42,
			ClientID: "oidc_app", AMR: "pwd,otp", IP: "10.0.0.1", UA: "ua/1.0",
			Detail: detail, CreatedAt: fixed,
		},
		// 全零：actor_id/user_id 取 DEFAULT 0，字符串列取 DEFAULT ''，
		// detail nil，created_at 零值交给 repo 填。
		{Event: "provider_update", ActorType: "system", Target: "qq"},
		// 空但非 nil 的 detail 应按原样字节落成零长 BLOB，而非 NULL。
		{Event: "change_password", ActorType: "admin", ActorID: 1, UserID: 7, Detail: []byte{}},
	}
	if err := rp.BatchInsert(ctx, rows); err != nil {
		t.Fatalf("BatchInsert 失败: %v", err)
	}
	// 复合主键 (id, created_at) 下调用方切片的 id 仍应逐行回填（PG 走
	// RETURNING、MySQL 走首 id 递推，机制见 backfillEventLogIDs）。
	for i := range rows {
		if rows[i].ID == 0 {
			t.Errorf("rows[%d].ID 应回填", i)
		}
	}

	var got []model.EventLog
	if err := db.NewSelect().Model(&got).OrderExpr("id ASC").Scan(ctx); err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("回读 = %d 行, want 3", len(got))
	}
	// 回读 id 应与回填值一致：DB 实发 id = 内存回填 id（非凑巧撞数）。
	for i := range got {
		if got[i].ID != rows[i].ID {
			t.Errorf("回读 id 与回填不一致: [%d] got=%d rows=%d", i, got[i].ID, rows[i].ID)
		}
	}

	// 行 0：全字段原样、detail 二进制保留、created_at 显式值保留。
	r0 := got[0]
	if r0.ID == 0 {
		t.Error("自增 id 应回填")
	}
	if r0.Event != "login_success" || r0.ActorType != "user" || r0.ActorID != 42 ||
		r0.UserID != 42 || r0.ClientID != "oidc_app" || r0.AMR != "pwd,otp" ||
		r0.IP != "10.0.0.1" || r0.UA != "ua/1.0" || r0.Target != "" {
		t.Errorf("行 0 字段不一致: %+v", r0)
	}
	if !bytes.Equal(r0.Detail, detail) {
		t.Errorf("行 0 detail = %v, want %v", r0.Detail, detail)
	}
	if !r0.CreatedAt.Equal(fixed) {
		t.Errorf("行 0 created_at = %v, want %v", r0.CreatedAt, fixed)
	}

	// 行 1：默认值列、nil detail、created_at 由 repo 填充。
	r1 := got[1]
	if r1.ActorID != 0 || r1.UserID != 0 || r1.ClientID != "" ||
		r1.AMR != "" || r1.IP != "" || r1.UA != "" {
		t.Errorf("行 1 默认值列不正确: %+v", r1)
	}
	if r1.Target != "qq" {
		t.Errorf("行 1 target = %q, want \"qq\"", r1.Target)
	}
	if r1.Detail != nil {
		t.Errorf("行 1 detail 应为 NULL, got %v", r1.Detail)
	}
	if r1.CreatedAt.IsZero() {
		t.Error("行 1 created_at 零值应由 repo 填充")
	}
	if d := r1.CreatedAt.Sub(before); d < -time.Second || d > 2*time.Second {
		t.Errorf("行 1 created_at = %v 偏离写入时刻 %v", r1.CreatedAt, before)
	}

	// 行 2：空非 nil detail 落成零长 BLOB，created_at 同样被填充。
	r2 := got[2]
	if len(r2.Detail) != 0 {
		t.Errorf("行 2 detail 长度 = %d, want 0", len(r2.Detail))
	}
	if r2.CreatedAt.IsZero() {
		t.Error("行 2 created_at 零值应由 repo 填充")
	}

	// detail NULL 语义按 SQL 直查确认：仅行 1 为 NULL。
	var nullCount, emptyCount int64
	if err := db.NewRaw("SELECT COUNT(*) FROM event_log WHERE detail IS NULL").
		Scan(ctx, &nullCount); err != nil {
		t.Fatalf("查 detail NULL 计数失败: %v", err)
	}
	if nullCount != 1 {
		t.Errorf("detail IS NULL = %d 行, want 1", nullCount)
	}
	if err := db.NewRaw("SELECT COUNT(*) FROM event_log WHERE detail IS NOT NULL AND OCTET_LENGTH(detail) = 0").
		Scan(ctx, &emptyCount); err != nil {
		t.Fatalf("查 detail 空 BLOB 计数失败: %v", err)
	}
	if emptyCount != 1 {
		t.Errorf("detail 零长 BLOB = %d 行, want 1", emptyCount)
	}
}

// TestEventLogRepoBatchInsertChunks（env-skip）：超过批上限的行数按
// EventLogBatchSize 分批插入且全部落库、id 自增连续；跨批回填（每批按首
// id 递推 / RETURNING）后各行 id 均非零且与回读一致；所有零值 created_at
// 均被填充。
func TestEventLogRepoBatchInsertChunks(t *testing.T) {
	rp, db := eventLogTestSetup(t)
	ctx := context.Background()

	if EventLogBatchSize != 200 {
		t.Errorf("EventLogBatchSize = %d, want 200（§5.2 攒批口径）", EventLogBatchSize)
	}
	n := EventLogBatchSize + 5
	rows := make([]model.EventLog, n)
	for i := range rows {
		rows[i] = model.EventLog{Event: "login_success", ActorType: "user", UserID: int64(i + 1)}
	}
	if err := rp.BatchInsert(ctx, rows); err != nil {
		t.Fatalf("BatchInsert %d 行失败: %v", n, err)
	}
	for i := range rows {
		if rows[i].ID == 0 {
			t.Fatalf("rows[%d].ID 应回填", i)
		}
	}

	count, err := db.NewSelect().Model((*model.EventLog)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("计数失败: %v", err)
	}
	if count != int64(n) {
		t.Fatalf("落库 = %d 行, want %d", count, n)
	}

	var got []model.EventLog
	if err := db.NewSelect().Model(&got).OrderExpr("id ASC").Scan(ctx); err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if len(got) != n {
		t.Fatalf("回读 = %d 行, want %d", len(got), n)
	}
	for i := range got {
		if got[i].ID != rows[i].ID {
			t.Fatalf("回读 id 与回填不一致: [%d] got=%d rows=%d", i, got[i].ID, rows[i].ID)
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID <= got[i-1].ID {
			t.Fatalf("id 应随插入顺序递增: [%d]=%d [%d]=%d", i-1, got[i-1].ID, i, got[i].ID)
		}
	}
	for i, r := range got {
		if r.CreatedAt.IsZero() {
			t.Fatalf("第 %d 行 created_at 应被填充", i)
		}
		if r.UserID != int64(i+1) {
			t.Fatalf("第 %d 行 user_id = %d, want %d", i, r.UserID, i+1)
		}
	}
}

// TestEventLogRepoBatchInsertEmpty（env-skip）：nil / 空切片 no-op，不写
// 任何行、不报错。
func TestEventLogRepoBatchInsertEmpty(t *testing.T) {
	rp, db := eventLogTestSetup(t)
	ctx := context.Background()

	if err := rp.BatchInsert(ctx, nil); err != nil {
		t.Errorf("BatchInsert(nil) 应 nil, got %v", err)
	}
	if err := rp.BatchInsert(ctx, []model.EventLog{}); err != nil {
		t.Errorf("BatchInsert(空切片) 应 nil, got %v", err)
	}
	count, err := db.NewSelect().Model((*model.EventLog)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("计数失败: %v", err)
	}
	if count != 0 {
		t.Errorf("空批量应不写行, got %d 行", count)
	}
}

// TestEventLogRepoListByUser（env-skip）：user 维度 + event 过滤分页
// （GetUserEvents「该用户登录记录」的数据源）——只出目标用户的行、event
// 非空时再过滤、id DESC 全序稳定、分页归一（page 1 起、pageSize 默认 20 /
// clamp 100）、total 为过滤后总数。
func TestEventLogRepoListByUser(t *testing.T) {
	rp, _ := eventLogTestSetup(t)
	ctx := context.Background()

	// 用户 42：3 条 login_success + 1 条 change_password（乱序插入，id 递增）；
	// 用户 43：2 条 login_success（不串页）。
	rows := []model.EventLog{
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, IP: "1.1.1.1"},
		{Event: "change_password", ActorType: "user", ActorID: 42, UserID: 42},
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, IP: "2.2.2.2"},
		{Event: "login_success", ActorType: "user", ActorID: 43, UserID: 43},
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, IP: "3.3.3.3"},
		{Event: "login_success", ActorType: "user", ActorID: 43, UserID: 43},
	}
	if err := rp.BatchInsert(ctx, rows); err != nil {
		t.Fatalf("BatchInsert 失败: %v", err)
	}

	// event=login_success + user=42：3 行，id DESC。
	got, total, err := rp.ListByUser(ctx, EventLogListQuery{UserID: 42, Event: "login_success"})
	if err != nil || total != 3 || len(got) != 3 {
		t.Fatalf("login_success@42 = (%d 行, total=%d, %v), want 3/3", len(got), total, err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID >= got[i-1].ID || got[i].UserID != 42 || got[i].Event != "login_success" {
			t.Fatalf("顺序 / 过滤泄漏: %+v", got)
		}
	}

	// event 过滤关闭（空）：42 的全部 4 行。
	if _, total, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 42}); err != nil || total != 4 {
		t.Fatalf("全事件@42 total = %d err=%v, want 4", total, err)
	}

	// 分页：page 2 size 2（login_success@42 的第 2 页恰 1 行）+ 归一（page 0
	// → 1、pageSize 0 → 20、>100 clamp 不报错）。
	if got, total, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 42, Event: "login_success", Page: 2, PageSize: 2}); err != nil ||
		total != 3 || len(got) != 1 {
		t.Fatalf("page2 = (%d 行, total=%d, %v), want 1/3", len(got), total, err)
	}
	if _, _, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 42, Page: 0, PageSize: 0}); err != nil {
		t.Fatalf("分页归一不应报错: %v", err)
	}
	if _, _, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 42, Page: 1, PageSize: 150}); err != nil {
		t.Fatalf("pageSize=150 应 clamp 不报错: %v", err)
	}

	// 不存在的用户：空页 + total 0。
	if got, total, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 404, Event: "login_success"}); err != nil ||
		total != 0 || len(got) != 0 {
		t.Fatalf("空集 = (%d 行, total=%d, %v), want 0/0", len(got), total, err)
	}
}

// TestEventLogRepoList 统一事件视图（§5.6 行 1275）：六筛选（均可
// 空）叠加 + §1.7 分页 + 排序（sort 缺省 id DESC、字符集外回落、order 非
// asc 一律 desc、非 id 主序追加 id DESC——orderClause 与 user_repo 同款）。
func TestEventLogRepoList(t *testing.T) {
	rp, db := eventLogTestSetup(t)
	ctx := context.Background()

	// 行集：覆盖 event / actor_type / actor_id / user_id 四维度 + 显式
	// created_at 三档时间（-3h / -2h / -1h），乱序插入。
	base := time.Now().Truncate(time.Second)
	at := func(d time.Duration) time.Time { return base.Add(-d) }
	rows := []model.EventLog{
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, CreatedAt: at(3 * time.Hour)},
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, CreatedAt: at(2 * time.Hour)},
		{Event: "change_password", ActorType: "user", ActorID: 42, UserID: 42, CreatedAt: at(time.Hour)},
		{Event: "admin_disable_user", ActorType: "admin", ActorID: 1, UserID: 7, CreatedAt: at(time.Hour)},
		{Event: "oidc_authorize_no_state", ActorType: "system", ActorID: 0, UserID: 0, CreatedAt: at(time.Hour)},
	}
	if err := rp.BatchInsert(ctx, rows); err != nil {
		t.Fatalf("BatchInsert 失败: %v", err)
	}

	// 无筛选：全部 5 行，缺省 id DESC。
	got, total, err := rp.List(ctx, EventAdminQuery{})
	if err != nil || total != 5 || len(got) != 5 {
		t.Fatalf("无筛选 = (%d 行, total=%d, %v), want 5/5", len(got), total, err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID >= got[i-1].ID {
			t.Fatalf("缺省应 id DESC: %+v", got)
		}
	}

	// 六筛选逐项 + 叠加。
	if _, total, err = rp.List(ctx, EventAdminQuery{Event: "login_success"}); err != nil || total != 2 {
		t.Errorf("event=login_success total = %d err=%v, want 2", total, err)
	}
	if _, total, err = rp.List(ctx, EventAdminQuery{ActorType: "admin"}); err != nil || total != 1 {
		t.Errorf("actor_type=admin total = %d, want 1", total)
	}
	actorID := int64(1)
	if _, total, err = rp.List(ctx, EventAdminQuery{ActorID: &actorID}); err != nil || total != 1 {
		t.Errorf("actor_id=1 total = %d, want 1", total)
	}
	zero := int64(0)
	if _, total, err = rp.List(ctx, EventAdminQuery{ActorID: &zero}); err != nil || total != 1 {
		t.Errorf("actor_id=0（system 合法值）total = %d, want 1", total)
	}
	userID := int64(42)
	if _, total, err = rp.List(ctx, EventAdminQuery{UserID: &userID, Event: "change_password"}); err != nil || total != 1 {
		t.Errorf("user_id=42 + change_password total = %d, want 1", total)
	}

	// 时间窗（闭区间 from <= created_at <= to，Unix 秒）：[-2.5h, -1.5h]
	// 恰含 -2h 的 1 行（-3h 在窗外、-1h 三行在窗外）。
	from := at(5 * time.Hour / 2).Unix()
	to := at(3 * time.Hour / 2).Unix()
	if _, total, err = rp.List(ctx, EventAdminQuery{From: &from, To: &to}); err != nil || total != 1 {
		t.Errorf("时间窗 total = %d, want 1（仅 -2h 行）", total)
	}
	// from 单边：>= -1h 的 3 行。
	fromOnly := at(time.Hour).Unix()
	if _, total, err = rp.List(ctx, EventAdminQuery{From: &fromOnly}); err != nil || total != 3 {
		t.Errorf("from=-1h total = %d, want 3", total)
	}
	// to 单边：<= -2h 的 2 行。
	toOnly := at(2 * time.Hour).Unix()
	if _, total, err = rp.List(ctx, EventAdminQuery{To: &toOnly}); err != nil || total != 2 {
		t.Errorf("to=-2h total = %d, want 2", total)
	}

	// 排序：event asc + id DESC 兜底（同值行跨页不漂移）。
	// 字典序：admin_disable_user < change_password < login_success×2 < oidc_authorize_no_state。
	got, _, err = rp.List(ctx, EventAdminQuery{Sort: "event", Order: "asc"})
	if err != nil || len(got) != 5 {
		t.Fatalf("sort=event asc 失败: %v", err)
	}
	events := []string{got[0].Event, got[1].Event, got[2].Event, got[3].Event, got[4].Event}
	want := []string{"admin_disable_user", "change_password", "login_success", "login_success", "oidc_authorize_no_state"}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("event asc 顺序 = %v, want %v", events, want)
		}
	}
	if got[2].ID <= got[3].ID {
		t.Errorf("同值行应有 id DESC 兜底: [%d]=%d [%d]=%d", 2, got[2].ID, 3, got[3].ID)
	}

	// 排序防注入：字符集外列静默回落 id；order 大小写不敏感（ASC）。
	if got, _, err = rp.List(ctx, EventAdminQuery{Sort: "id; DROP TABLE event_log", Order: "ASC"}); err != nil || len(got) != 5 {
		t.Fatalf("非法 sort 应静默回落 id: %v (rows %d)", err, len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID < got[i-1].ID {
			t.Fatalf("order=ASC 应升序: %+v", got)
		}
	}
	// 注入未执行自证：表仍在。
	count, err := db.NewSelect().Model((*model.EventLog)(nil)).Count(ctx)
	if err != nil || count != 5 {
		t.Fatalf("表应完好 5 行: rows=%d err=%v", count, err)
	}

	// 分页归一 + 空页：page 0 → 1、pageSize 0 → 20、>100 clamp；空集 items 为空切片。
	if got, total, err = rp.List(ctx, EventAdminQuery{Event: "no_such_event", Page: 0, PageSize: 0}); err != nil ||
		total != 0 || len(got) != 0 {
		t.Fatalf("空页 = (%d 行, total=%d, %v), want 0/0", len(got), total, err)
	}
	if _, _, err = rp.List(ctx, EventAdminQuery{Page: 0, PageSize: 200}); err != nil {
		t.Fatalf("pageSize=200 应 clamp 不报错: %v", err)
	}
}

// TestEventLogRepoPartitioning（env-skip，两方言矩阵共用口径）：分区表行为
// 断言——单批跨分区行的 id 回填、超范围数据落兜底不失败、行按 created_at
// 落正确分区、带 created_at 条件查询走分区裁剪。迁移建表只建兜底分区，实体
// 分区由用例内 DDL 补一个（形态对齐分区维护任务的切分 DDL），否则裁剪无从
// 观察。裁剪断言只锁「窗口整体落在实体分区范围内时排除兜底」方向：本地
// MariaDB 12.3 实测窗口整体落入兜底（MAXVALUE）区间时不裁剪实体分区（优化
// 器局限），该方向不作断言；PG 14 两个方向都精确裁剪。无 created_at 条件
// 恒全分区扫描——ListByUser 的已知退化点（分区数上限可接受，仅记录），
// 断言该形态以固化口径。
func TestEventLogRepoPartitioning(t *testing.T) {
	rp, db := eventLogTestSetup(t)
	ctx := context.Background()

	target, err := resolveTestDBEnv()
	if err != nil || target == nil {
		t.Fatalf("eventLogTestSetup 已通过，测试库 env 应可解析")
	}
	isPG := target.driver == config.DriverPostgres

	// 实体分区：上界 2026-01-01（pYYYYMMDD 命名口径）。MySQL REORGANIZE
	// 切分 pmax 兜底；PG 挂载 MINVALUE..上界（此刻兜底为空，无需搬移）。
	if isPG {
		_, err = db.ExecContext(ctx,
			`CREATE TABLE event_log_p20260101 PARTITION OF event_log FOR VALUES FROM (MINVALUE) TO ('2026-01-01')`)
	} else {
		_, err = db.ExecContext(ctx,
			`ALTER TABLE event_log REORGANIZE PARTITION pmax INTO (
  PARTITION p20260101 VALUES LESS THAN (TO_DAYS('2026-01-01')),
  PARTITION pmax VALUES LESS THAN MAXVALUE)`)
	}
	if err != nil {
		t.Fatalf("建实体分区失败: %v", err)
	}

	// 单批跨分区写入：2025 行落实体分区、2099 行超出已建范围落兜底——插入
	// 不失败即兜底承接（数据不丢口径）；回填后各行 id 非零且随插入顺序递增。
	at := func(y int, m time.Month, d int) time.Time {
		return time.Date(y, m, d, 10, 0, 0, 0, time.UTC)
	}
	rows := []model.EventLog{
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, CreatedAt: at(2025, time.June, 15)},
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, CreatedAt: at(2099, time.January, 1)},
	}
	if err := rp.BatchInsert(ctx, rows); err != nil {
		t.Fatalf("跨分区 BatchInsert 失败（兜底应承接超范围数据）: %v", err)
	}
	for i := range rows {
		if rows[i].ID == 0 {
			t.Errorf("rows[%d].ID 应回填", i)
		}
	}
	if rows[1].ID <= rows[0].ID {
		t.Errorf("id 应随插入顺序递增: [0]=%d [1]=%d", rows[0].ID, rows[1].ID)
	}

	// 落分区断言：2025 行在实体分区、2099 行在兜底分区。MySQL 用 PARTITION
	// 选择语法直查；PG 分区即普通表，直查子表名。
	entityQ, fallbackQ := "SELECT COUNT(*) FROM event_log_p20260101", "SELECT COUNT(*) FROM event_log_default"
	if !isPG {
		entityQ = "SELECT COUNT(*) FROM event_log PARTITION (p20260101)"
		fallbackQ = "SELECT COUNT(*) FROM event_log PARTITION (pmax)"
	}
	countPart := func(query, label string, want int64) {
		t.Helper()
		var n int64
		if err := db.NewRaw(query).Scan(ctx, &n); err != nil {
			t.Fatalf("查 %s 行数失败: %v", label, err)
		}
		if n != want {
			t.Errorf("%s 行数 = %d, want %d", label, n, want)
		}
	}
	countPart(entityQ, "实体分区", 1)
	countPart(fallbackQ, "兜底分区", 1)

	// 分区元数据随 -v 输出，作分区形态实证（EXPLAIN 证据见下方 t.Logf）。
	if isPG {
		rows, err := db.QueryContext(ctx,
			`SELECT c.relname FROM pg_catalog.pg_inherits i
			 JOIN pg_catalog.pg_class p ON p.oid = i.inhparent
			 JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
			 WHERE p.relname = 'event_log' ORDER BY c.relname`)
		if err != nil {
			t.Fatalf("查分区元数据失败: %v", err)
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatalf("分区元数据读取失败: %v", err)
			}
			t.Logf("PG 分区子表: %s", name)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("分区元数据遍历失败: %v", err)
		}
		var pkDef string
		if err := db.QueryRowContext(ctx,
			`SELECT pg_get_indexdef(i.indexrelid) FROM pg_index i
			 WHERE i.indrelid = 'event_log'::regclass AND i.indisprimary`).
			Scan(&pkDef); err != nil {
			t.Fatalf("查主键定义失败: %v", err)
		}
		t.Logf("PG 主键定义: %s", pkDef)
		var seqName string
		if err := db.QueryRowContext(ctx,
			`SELECT pg_get_serial_sequence('event_log', 'id')`).Scan(&seqName); err != nil {
			t.Fatalf("查 id 序列绑定失败: %v", err)
		}
		t.Logf("PG id 序列绑定: %s", seqName)
	} else {
		rows, err := db.QueryContext(ctx,
			`SELECT PARTITION_NAME, PARTITION_METHOD, PARTITION_EXPRESSION, PARTITION_DESCRIPTION
			 FROM information_schema.partitions
			 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'event_log'
			 ORDER BY PARTITION_ORDINAL_POSITION`)
		if err != nil {
			t.Fatalf("查分区元数据失败: %v", err)
		}
		for rows.Next() {
			var name, method, expr, desc string
			if err := rows.Scan(&name, &method, &expr, &desc); err != nil {
				t.Fatalf("分区元数据读取失败: %v", err)
			}
			t.Logf("MySQL 分区: name=%s method=%s expr=%s desc=%s", name, method, expr, desc)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("分区元数据遍历失败: %v", err)
		}
		pkRows, err := db.QueryContext(ctx,
			`SELECT SEQ_IN_INDEX, COLUMN_NAME FROM information_schema.statistics
			 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'event_log' AND INDEX_NAME = 'PRIMARY'
			 ORDER BY SEQ_IN_INDEX`)
		if err != nil {
			t.Fatalf("查主键列失败: %v", err)
		}
		var pkCols []string
		for pkRows.Next() {
			var seq int64
			var col string
			if err := pkRows.Scan(&seq, &col); err != nil {
				t.Fatalf("主键列读取失败: %v", err)
			}
			pkCols = append(pkCols, col)
		}
		_ = pkRows.Close()
		if err := pkRows.Err(); err != nil {
			t.Fatalf("主键列遍历失败: %v", err)
		}
		t.Logf("MySQL 复合主键列序: (%s)", strings.Join(pkCols, ", "))
	}

	if isPG {
		plan := func(query string) string {
			t.Helper()
			rs, err := db.QueryContext(ctx, "EXPLAIN (COSTS OFF) "+query)
			if err != nil {
				t.Fatalf("EXPLAIN 失败: %v", err)
			}
			defer rs.Close()
			var sb strings.Builder
			for rs.Next() {
				var line string
				if err := rs.Scan(&line); err != nil {
					t.Fatalf("EXPLAIN 行读取失败: %v", err)
				}
				sb.WriteString(line)
				sb.WriteByte('\n')
			}
			if err := rs.Err(); err != nil {
				t.Fatalf("EXPLAIN 遍历失败: %v", err)
			}
			return sb.String()
		}
		pruned := plan(`SELECT * FROM event_log WHERE created_at >= '2025-01-01' AND created_at <= '2025-12-31'`)
		t.Logf("PG 实体区间窗口 plan:\n%s", pruned)
		if !strings.Contains(pruned, "event_log_p20260101") || strings.Contains(pruned, "event_log_default") {
			t.Errorf("实体区间窗口应裁剪兜底分区，plan:\n%s", pruned)
		}
		pruned = plan(`SELECT * FROM event_log WHERE created_at >= '2030-01-01' AND created_at <= '2030-02-01'`)
		t.Logf("PG 兜底区间窗口 plan:\n%s", pruned)
		if !strings.Contains(pruned, "event_log_default") || strings.Contains(pruned, "event_log_p20260101") {
			t.Errorf("兜底区间窗口应裁剪实体分区，plan:\n%s", pruned)
		}
		full := plan(`SELECT * FROM event_log WHERE user_id = 42`)
		t.Logf("PG 无 created_at 条件 plan:\n%s", full)
		if !strings.Contains(full, "event_log_p20260101") || !strings.Contains(full, "event_log_default") {
			t.Errorf("无 created_at 条件应全分区扫描（已知退化点），plan:\n%s", full)
		}
		return
	}
	partitions := func(query string) string {
		t.Helper()
		rs, err := db.QueryContext(ctx, "EXPLAIN PARTITIONS "+query)
		if err != nil {
			t.Fatalf("EXPLAIN 失败: %v", err)
		}
		defer rs.Close()
		cols, err := rs.Columns()
		if err != nil {
			t.Fatalf("EXPLAIN 列读取失败: %v", err)
		}
		col := -1
		for i, c := range cols {
			if c == "partitions" {
				col = i
			}
		}
		if col < 0 {
			t.Fatalf("EXPLAIN 无 partitions 列: %v", cols)
		}
		out := ""
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for rs.Next() {
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rs.Scan(ptrs...); err != nil {
				t.Fatalf("EXPLAIN 行读取失败: %v", err)
			}
			if s, ok := vals[col].(string); ok {
				out = s
			} else if b, ok := vals[col].([]byte); ok {
				out = string(b)
			}
		}
		if err := rs.Err(); err != nil {
			t.Fatalf("EXPLAIN 遍历失败: %v", err)
		}
		return out
	}
	pruned := partitions(`SELECT * FROM event_log WHERE created_at >= '2025-01-01' AND created_at <= '2025-12-31'`)
	t.Logf("MySQL 实体区间窗口 partitions=%q", pruned)
	if !strings.Contains(pruned, "p20260101") || strings.Contains(pruned, "pmax") {
		t.Errorf("实体区间窗口应裁剪兜底分区, partitions=%q", pruned)
	}
	full := partitions(`SELECT * FROM event_log WHERE user_id = 42`)
	t.Logf("MySQL 无 created_at 条件 partitions=%q", full)
	if !strings.Contains(full, "p20260101") || !strings.Contains(full, "pmax") {
		t.Errorf("无 created_at 条件应全分区扫描（已知退化点）, partitions=%q", full)
	}
}
