// Package postgres PartitionManager 的 PostgreSQL 实现：实体分区从
// pg_catalog.pg_inherits + pg_class 枚举（排除 <表>_default 兜底），新增
// 分区走三步搬移 + ATTACH（事务内，review/eventlog-partition.md §2），淘汰
// 走 DROP TABLE（§3）。决策算法归父包 policy.go，这里只做枚举与 DDL。
package postgres

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/partition"
)

const (
	// defaultTable 分区目标表（后端架构 §4.6 event_log）。
	defaultTable = "event_log"
	// dateLayout 分区上界写进 DDL 字面量的形态（PG 侧用 ISO 日期字面量，
	// 分区键为裸 created_at 列，不做函数包装）。
	dateLayout = "2006-01-02"
	// checkName 挂载前加在新表上、覆盖新分区边界的 CHECK 约束名；约束名
	// 唯一性只落在单表内，各分区表可同名。
	checkName = "ck_partition_range"
)

// Manager 基于 bun 连接的 PostgreSQL 分区维护实现。db 必须来自业务同一连接
// 工厂（repo / migrate），保证枚举与 DDL 落在目标库。
type Manager struct {
	db    *bun.DB
	table string
}

// New 构造 event_log 分区维护 Manager。
func New(db *bun.DB) *Manager {
	return &Manager{db: db, table: defaultTable}
}

// fallbackName 兜底分区名（DEFAULT 分区）：永不 DROP，也不参与决策算法。
// 命名随表派生（event_log → event_log_default）。
func (m *Manager) fallbackName() string {
	return m.table + "_default"
}

// ListPartitions 枚举实体分区：父表按 to_regclass 经 search_path 解析，排除
// 兜底名；非 pYYYYMMDD 命名的分区不进决策（人工建的分区不被算法淘汰），结果
// 按上界日期升序。
func (m *Manager) ListPartitions(ctx context.Context) ([]partition.Partition, error) {
	rows, err := m.db.QueryContext(ctx, `
SELECT c.relname
FROM pg_catalog.pg_inherits i
JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
WHERE i.inhparent = to_regclass(?)
  AND c.relname <> ?
ORDER BY c.relname`, m.table, m.fallbackName())
	if err != nil {
		return nil, fmt.Errorf("partition postgres: list %s: %w", m.table, err)
	}
	defer rows.Close()
	var out []partition.Partition
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("partition postgres: scan %s: %w", m.table, err)
		}
		if name == m.fallbackName() {
			continue
		}
		upper, ok := partition.ParseName(name)
		if !ok {
			continue
		}
		out = append(out, partition.Partition{Name: name, Upper: upper})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("partition postgres: rows %s: %w", m.table, err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Upper.Equal(out[j].Upper) {
			return out[i].Name < out[j].Name
		}
		return out[i].Upper.Before(out[j].Upper)
	})
	return out, nil
}

// EnsurePartition 切新分区：PG 没有 REORGANIZE 等价物，且新增分区前 PG 会
// 扫描 DEFAULT 分区、要求其中不含归属新范围的行，因此在单事务内三步完成
// （§2）——①建实体表并把兜底存量搬进去再从兜底删除；②加覆盖边界的 CHECK
// 让 ATTACH 免扫新表逐行校验；③ATTACH 挂载。事务保证中间态不外泄、兜底里
// 不会残留归属新分区却未搬走的行。新分区下界取既有实体分区最大上界（跨度
// 可能大于间隔天数，数据不丢）；尚无实体分区时下界为 MINVALUE，搬移不带
// 下界条件。ATTACH 相比 CREATE ... PARTITION OF 只持 SHARE UPDATE EXCLUSIVE
// 弱锁，对在线写入干扰更小（默认分区会被 PG 临时独占，属挂载瞬时成本）。
func (m *Manager) EnsurePartition(ctx context.Context, today time.Time, intervalDays int) error {
	parts, err := m.ListPartitions(ctx)
	if err != nil {
		return err
	}
	plan, start, ok := partition.PlanCreate(parts, today, intervalDays)
	if !ok {
		return nil
	}
	upper := plan.Upper.Format(dateLayout)
	rangeStart := "'" + start.Format(dateLayout) + "'"
	moveWhere := "WHERE created_at >= '" + start.Format(dateLayout) + "' AND created_at < '" + upper + "'"
	checkCond := "created_at >= '" + start.Format(dateLayout) + "' AND created_at < '" + upper + "'"
	if start.IsZero() {
		rangeStart = "MINVALUE"
		moveWhere = "WHERE created_at < '" + upper + "'"
		checkCond = "created_at < '" + upper + "'"
	}
	err = m.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// 表名 / 分区名 / 约束名经 bun.Ident 按方言加引号；边界日期字面量
		// 由决策算法的 pYYYYMMDD 名派生，无注入面。
		if _, err := tx.ExecContext(ctx, "CREATE TABLE ? (LIKE ? INCLUDING DEFAULTS)",
			bun.Ident(plan.Name), bun.Ident(m.table)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO ? SELECT * FROM ? "+moveWhere,
			bun.Ident(plan.Name), bun.Ident(m.fallbackName())); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM ? "+moveWhere,
			bun.Ident(m.fallbackName())); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE ? ADD CONSTRAINT ? CHECK ("+checkCond+")",
			bun.Ident(plan.Name), bun.Ident(checkName)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE ? ATTACH PARTITION ? FOR VALUES FROM ("+rangeStart+") TO ('"+upper+"')",
			bun.Ident(m.table), bun.Ident(plan.Name)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("partition postgres: attach %s: %w", plan.Name, err)
	}
	return nil
}

// DropExcess 淘汰超量分区：决策给出待淘汰名单后逐个 DROP TABLE（分区即普通
// 表，DROP 避免批量 DELETE 的 VACUUM 开销）。兜底分区永不 DROP——决策只产出
// 实体分区，此处按名再拦一道双保险。
func (m *Manager) DropExcess(ctx context.Context, maxPartitions int) error {
	parts, err := m.ListPartitions(ctx)
	if err != nil {
		return err
	}
	for _, name := range partition.PlanDrop(parts, maxPartitions) {
		if name == m.fallbackName() {
			continue
		}
		if _, err := m.db.ExecContext(ctx, "DROP TABLE ?", bun.Ident(name)); err != nil {
			return fmt.Errorf("partition postgres: drop %s: %w", name, err)
		}
	}
	return nil
}
