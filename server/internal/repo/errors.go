// 驱动错误归一：散在各 repo 的
// *mysql.MySQLError 直接判定收口到本文件，向上只暴露语义化判定
// （IsDuplicateKey / IsDeadlock / IsNoSuchTable），调用方拿语义不拿驱动
// 类型。分派按错误对象自带的驱动身份进行——MySQLError 只可能来自
// MySQL/MariaDB、pgdriver.Error 只可能来自 PG，单进程单库下产生错误的
// 驱动即当前驱动，无需为分派保留 driver 状态。
package repo

import (
	"errors"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun/driver/pgdriver"
)

// MariaDB 服务端错误码（ER_DUP_ENTRY / ER_LOCK_DEADLOCK / ER_NO_SUCH_TABLE）。
const (
	mysqlErrDuplicateEntry = 1062
	mysqlErrLockDeadlock   = 1213
	mysqlErrNoSuchTable    = 1146
)

// PG SQLSTATE 错误码（unique_violation / deadlock_detected /
// undefined_table，errcodes-appendix）。按精确码判定：23505 是唯一键冲突，
// 23503 外键等同类约束错误不并入。
const (
	pgUniqueViolation  = "23505"
	pgDeadlockDetected = "40P01"
	pgUndefinedTable   = "42P01"
)

// IsDuplicateKey 判唯一键冲突：MariaDB 1062 / PG 23505。repo 各 Err*Duplicate
// 哨兵的判据收口于此，错误码 / 文案对外口径不变。
func IsDuplicateKey(err error) bool {
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number == mysqlErrDuplicateEntry
	}
	return pgErrCodeIs(err, pgUniqueViolation)
}

// IsDeadlock 判死锁回滚：MariaDB 1213 / PG 40P01。oidc_consent 并发首插的
// 合并重试依赖本判定——PG 侧必须覆盖 40P01，否则重试在 PG 下失效。
func IsDeadlock(err error) bool {
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number == mysqlErrLockDeadlock
	}
	return pgErrCodeIs(err, pgDeadlockDetected)
}

// IsNoSuchTable 判表不存在：MariaDB 1146 / PG 42P01。migrate 的安装判据
// 与本判定同码表，但因 repo 包内测试 import migrate、本包不能被 migrate
// 反向 import（否则测试期 import cycle），migrate 只能本地复制判据——两处
// 码表改动须同步。
func IsNoSuchTable(err error) bool {
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number == mysqlErrNoSuchTable
	}
	return pgErrCodeIs(err, pgUndefinedTable)
}

// pgErrCodeIs 按 SQLSTATE 精确码判 PG 错误。pgdriver.Error 以值接收器实现
// error，包装链上的错误经 errors.As 解出。
func pgErrCodeIs(err error, code string) bool {
	var pgErr pgdriver.Error
	return errors.As(err, &pgErr) && pgErr.Field('C') == code
}
