package partition

import (
	"sort"
	"time"
)

// 决策参数取值边界：settings 侧已按 §4 校验 N/X ∈ [1, 365]，本包作为消费
// 侧再钳制一次兜底——越界取值不会产出非法 DDL（如 0 天上界、负数余量）。
const (
	minIntervalDays  = 1
	maxIntervalDays  = 365
	minMaxPartitions = 1
	maxMaxPartitions = 365
)

func clampIntervalDays(n int) int {
	if n < minIntervalDays {
		return minIntervalDays
	}
	if n > maxIntervalDays {
		return maxIntervalDays
	}
	return n
}

func clampMaxPartitions(x int) int {
	if x < minMaxPartitions {
		return minMaxPartitions
	}
	if x > maxMaxPartitions {
		return maxMaxPartitions
	}
	return x
}

// PlanCreate 切新分区决策（§2，方言无关纯算法）。
//
//   - U = 实体分区最大上界（无实体分区时为零值）；
//   - 仅当 today >= U（当前数据正落进兜底）才切，否则不动——已建范围还
//     覆盖得住今天就不产生新分区；
//   - 新分区上界 = max(U, today) + intervalDays 天，命名 p<上界>；today
//     早于 U 但等于上界的当天（today == U）同样要切，因为上界含即落兜底；
//   - 只切一次不循环补建：计划名已存在（含输入不一致的防御场景）不再切。
//
// 返回：newPart = 新分区（Name + Upper）；start = 新分区的下界，即既有实体
// 分区的最大上界 U（零值表示尚无实体分区，PG 侧翻译为 MINVALUE，MySQL 无需
// 下界）；cut = 是否需要切。
func PlanCreate(parts []Partition, today time.Time, intervalDays int) (newPart Partition, start time.Time, cut bool) {
	n := clampIntervalDays(intervalDays)
	today = dateOnly(today)
	var lastUpper time.Time
	for _, p := range parts {
		if p.Upper.After(lastUpper) {
			lastUpper = p.Upper
		}
	}
	if today.Before(lastUpper) {
		return Partition{}, time.Time{}, false
	}
	base := today
	if lastUpper.After(base) {
		base = lastUpper
	}
	plan := Partition{
		Name:  NameForDate(base.AddDate(0, 0, n)),
		Upper: dateOnly(base.AddDate(0, 0, n)),
	}
	for _, p := range parts {
		if p.Name == plan.Name {
			return Partition{}, time.Time{}, false
		}
	}
	return plan, lastUpper, true
}

// PlanDrop 淘汰决策（§3，方言无关纯算法）：实体分区按上界日期升序，数量
// 超过 maxPartitions 时从最老开始淘汰，直到余量恰好达标；返回待淘汰分区名
// （升序，供方言从老到新依次执行）。上界缺失的条目不参与淘汰——防御输入
// 异常时误删不可评估的分区。
func PlanDrop(parts []Partition, maxPartitions int) []string {
	x := clampMaxPartitions(maxPartitions)
	if len(parts) <= x {
		return nil
	}
	sorted := make([]Partition, len(parts))
	copy(sorted, parts)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Upper.Equal(sorted[j].Upper) {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Upper.Before(sorted[j].Upper)
	})
	quota := len(sorted) - x
	drop := make([]string, 0, quota)
	for _, p := range sorted {
		if len(drop) == quota {
			break
		}
		if p.Upper.IsZero() {
			continue
		}
		drop = append(drop, p.Name)
	}
	if len(drop) == 0 {
		return nil
	}
	return drop
}
