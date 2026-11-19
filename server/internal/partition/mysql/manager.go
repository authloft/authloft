// Package mysql PartitionManager 的 MySQL / MariaDB 实现：实体分区从
// information_schema.partitions 枚举（排除 pmax 兜底），新增分区走
// REORGANIZE 切分 pmax（兜底积压行由数据库自动分流，review/eventlog-partition.md
// §2），淘汰走 DROP PARTITION（§3）。决策算法归父包 policy.go，这里只做
// 枚举与 DDL。
package mysql

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/partition"
)

const (
	// fallbackName 兜底分区名（VALUES LESS THAN MAXVALUE）：永不 DROP，
	// 也不参与决策算法。
	fallbackName = "pmax"
	// defaultTable 分区目标表（后端架构 §4.6 event_log）。
	defaultTable = "event_log"
	// dateLayout 分区上界写进 DDL 字面量的形态（TO_DAYS('YYYY-MM-DD')）。
	dateLayout = "2006-01-02"
)

// Manager 基于 bun 连接的 MySQL 分区维护实现。db 必须来自业务同一连接工厂
// （repo / migrate），保证枚举与 DDL 落在目标库。
type Manager struct {
	db    *bun.DB
	table string
}

// New 构造 event_log 分区维护 Manager。
func New(db *bun.DB) *Manager {
	return &Manager{db: db, table: defaultTable}
}

// ListPartitions 枚举实体分区：限定当前库与目标表，排除 pmax 兜底；非
// pYYYYMMDD 命名的分区不进决策（人工建的分区不被算法淘汰），结果按上界
// 日期升序。
func (m *Manager) ListPartitions(ctx context.Context) ([]partition.Partition, error) {
	rows, err := m.db.QueryContext(ctx, `
SELECT PARTITION_NAME
FROM information_schema.partitions
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = ?
  AND PARTITION_NAME IS NOT NULL
ORDER BY PARTITION_ORDINAL_POSITION`, m.table)
	if err != nil {
		return nil, fmt.Errorf("partition mysql: list %s: %w", m.table, err)
	}
	defer rows.Close()
	var out []partition.Partition
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("partition mysql: scan %s: %w", m.table, err)
		}
		if name == fallbackName {
			continue
		}
		upper, ok := partition.ParseName(name)
		if !ok {
			continue
		}
		out = append(out, partition.Partition{Name: name, Upper: upper})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("partition mysql: rows %s: %w", m.table, err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Upper.Equal(out[j].Upper) {
			return out[i].Name < out[j].Name
		}
		return out[i].Upper.Before(out[j].Upper)
	})
	return out, nil
}

// EnsurePartition 切新分区：决策通过后用 REORGANIZE 切分 pmax，单条 DDL
// 原子完成，兜底里归属新范围的行由数据库自动分流。表名 / 分区名经 bun.Ident
// 按方言加引号；上界日期字面量由决策算法的 pYYYYMMDD 名派生，无注入面。
func (m *Manager) EnsurePartition(ctx context.Context, today time.Time, intervalDays int) error {
	parts, err := m.ListPartitions(ctx)
	if err != nil {
		return err
	}
	plan, _, ok := partition.PlanCreate(parts, today, intervalDays)
	if !ok {
		return nil
	}
	_, err = m.db.ExecContext(ctx, "ALTER TABLE ? REORGANIZE PARTITION ? INTO ("+
		"PARTITION ? VALUES LESS THAN (TO_DAYS('"+plan.Upper.Format(dateLayout)+"')), "+
		"PARTITION ? VALUES LESS THAN MAXVALUE)",
		bun.Ident(m.table), bun.Ident(fallbackName), bun.Ident(plan.Name), bun.Ident(fallbackName))
	if err != nil {
		return fmt.Errorf("partition mysql: reorganize %s: %w", plan.Name, err)
	}
	return nil
}

// DropExcess 淘汰超量分区：决策给出待淘汰名单后逐个 DROP PARTITION。兜底
// 分区永不 DROP——决策只产出实体分区，此处按名再拦一道双保险。
func (m *Manager) DropExcess(ctx context.Context, maxPartitions int) error {
	parts, err := m.ListPartitions(ctx)
	if err != nil {
		return err
	}
	for _, name := range partition.PlanDrop(parts, maxPartitions) {
		if name == fallbackName {
			continue
		}
		if _, err := m.db.ExecContext(ctx, "ALTER TABLE ? DROP PARTITION ?",
			bun.Ident(m.table), bun.Ident(name)); err != nil {
			return fmt.Errorf("partition mysql: drop %s: %w", name, err)
		}
	}
	return nil
}
