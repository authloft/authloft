// Package partition 维护 event_log 按天 RANGE 分区（分区设计见《后端架构》§4.6）：
// 决策算法（何时切新分区、淘汰哪些旧分区）抽成本包的方言无关纯函数，MySQL 与
// PostgreSQL 各自实现分区枚举与 DDL 执行，共同实现 PartitionManager 接口。
//
// 兜底口径：两库各保留一个永不淘汰的兜底分区（MySQL pmax / PG <表>_default）
// 承接超出已建范围的数据——任务延迟期间写入落兜底、不失败；恢复后由
// EnsurePartition 把兜底里归属新范围的行分流出去（MySQL 由 REORGANIZE 自动
// 分流，PG 三步搬移 + ATTACH）。差异只在分流机制，不在兜底语义。
package partition

import (
	"context"
	"time"
)

// Partition 单个实体分区的视图：分区名与上界日期。
//
// Upper 为该分区 RANGE 上界（含）对应的墙钟日期（UTC 零点锚定，见
// names.go 的 dateOnly）。RANGE 语义两库一致：下界含、上界不含，created_at
// 等于上界的行落进下一分区或兜底。
type Partition struct {
	Name  string
	Upper time.Time
}

// PartitionManager event_log 分区维护的方言接口。实现方从各自目录表枚举
// 实体分区——排除兜底分区与非 pYYYYMMDD 命名的分区（人工建的分区不进决策，
// 也就不会被算法误删）——再由本包决策算法产出方案，方言只负责把方案翻译成
// 各自的 DDL。首个实现方是 event_log 分区任务。
type PartitionManager interface {
	// EnsurePartition 切新分区（§2）：today 已越过最后一个实体分区上界
	// （即当前数据正落进兜底）时切一次，新分区上界 = max(既有上界, today) +
	// intervalDays。只切一次不循环补建；intervalDays 越界由决策算法钳制兜底。
	EnsurePartition(ctx context.Context, today time.Time, intervalDays int) error
	// DropExcess 淘汰超量分区（§3）：实体分区按上界日期升序、从最老开始
	// DROP，直到余量等于 maxPartitions；兜底分区永不 DROP，maxPartitions
	// 越界由决策算法钳制兜底。
	DropExcess(ctx context.Context, maxPartitions int) error
	// ListPartitions 枚举实体分区，按上界日期升序。
	ListPartitions(ctx context.Context) ([]Partition, error)
}
