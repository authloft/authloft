package partition

import (
	"strings"
	"time"
)

// 实体分区名口径：一律 pYYYYMMDD。兜底分区名不在本口径内（MySQL 恒为
// pmax，PG 为 <表>_default），由各 Manager 自行排除；解析失败的名字一律
// 视为非实体分区，不参与决策。
const (
	partitionNamePrefix = "p"
	partitionNameLayout = "20060102"
	partitionNameLen    = len(partitionNamePrefix) + len("20060102")
)

// dateOnly 取墙钟日期并重新锚定为 UTC 零点。分区上界统一用「UTC 零点表达
// 的墙钟日期」参与决策与名字解析：比较只看 Y/M/D，不受调用方时区的时钟
// 部分影响；DDL 侧按同一日期派生字面量，保证两库边界一致。
func dateOnly(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// NameForDate 生成墙钟日期对应的实体分区名 pYYYYMMDD。
func NameForDate(d time.Time) string {
	return partitionNamePrefix + dateOnly(d).Format(partitionNameLayout)
}

// ParseName 解析实体分区名 pYYYYMMDD 为上界日期（UTC 零点）。长度、前缀、
// 数字性与日期合法性（月/日越界）逐一校验；非本口径命名（含兜底 pmax 与
// PG 兜底名）返回 false。
func ParseName(name string) (time.Time, bool) {
	if len(name) != partitionNameLen || !strings.HasPrefix(name, partitionNamePrefix) {
		return time.Time{}, false
	}
	digits := name[len(partitionNamePrefix):]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return time.Time{}, false
		}
	}
	d, err := time.Parse(partitionNameLayout, digits)
	if err != nil {
		return time.Time{}, false
	}
	return d, true
}
