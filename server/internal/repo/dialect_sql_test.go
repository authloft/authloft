// 两方言 SQL 生成断言（离线，无需 DSN）：bun 的查询经 String() 在不触库的
// 前提下按 dialect 渲染整条 SQL。仓储层四类方言敏感写法在此锁定两库各自的
// 目标形态——upsert 子句（applyUpsert）、epoch 回绕表达式、POSITION 字面
// 匹配、排序列引用（bun.Ident）。MySQL 侧行为回归见各 *_test.go 的
// env-skip 集成用例；连接串为自造假值，不含真实凭证。
package repo

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/schema"

	"authloft/internal/repo/model"
)

// bunDialectDB 构造指定方言、不触库的 bun 连接（sql.Open 惰性建连 +
// String() 纯 SQL 构造）。mysql 方言 Init 的 version() 探测失败仅落一条
// 日志、基础能力位（含 ODKU）不受影响；pg 方言 Init 无操作。
func bunDialectDB(t *testing.T, dialect schema.Dialect, driverName, dsn string) *bun.DB {
	t.Helper()
	sqldb, err := sql.Open(driverName, dsn)
	if err != nil {
		t.Fatalf("sql.Open(%s) 失败: %v", driverName, err)
	}
	db := bun.NewDB(sqldb, dialect)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// bunMySQLSQLDB / bunPGSQLDB 两方言离线连接。
func bunMySQLSQLDB(t *testing.T) *bun.DB {
	return bunDialectDB(t, newMySQLDialect(), "mysql", "u:p@tcp(127.0.0.1:3306)/x?parseTime=true")
}

func bunPGSQLDB(t *testing.T) *bun.DB {
	return bunDialectDB(t, pgdialect.New(), "pg", "postgres://u:p@127.0.0.1:1/x?sslmode=disable")
}

// TestUpsertSQLTwoDialects 三处 upsert 目标在两方言下的冲突分支形态：
// settings（主键 k）、oidc_consent（uk_user_client，created_at 不在覆盖集）、
// user_profile（主键 user_id）。MySQL 生成 ODKU col=VALUES(col)；PG 生成
// ON CONFLICT (k) DO UPDATE SET col=EXCLUDED.col，且冲突列须与唯一键一致。
func TestUpsertSQLTwoDialects(t *testing.T) {
	mysqlDB := bunMySQLSQLDB(t)
	pgDB := bunPGSQLDB(t)

	settingsRows := []model.Setting{{K: "site_name", V: "Authloft"}}
	consentRow := model.OidcConsent{UserID: 1, ClientID: "app", Scopes: "openid"}
	profileRow := model.UserProfile{UserID: 1, Locale: "zh-CN"}

	cases := []struct {
		name     string
		build    func(*bun.DB) string
		mysql    string
		postgres string
	}{
		{
			name: "settings PK k",
			build: func(db *bun.DB) string {
				return applyUpsert(db.NewInsert().Model(&settingsRows),
					[]string{"k"}, []string{"v", "updated_at", "updated_by"}).String()
			},
			mysql:    "ON DUPLICATE KEY UPDATE v = VALUES(v), updated_at = VALUES(updated_at), updated_by = VALUES(updated_by)",
			postgres: "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by",
		},
		{
			name: "oidc_consent uk_user_client（created_at 不覆盖）",
			build: func(db *bun.DB) string {
				return applyUpsert(db.NewInsert().Model(&consentRow),
					[]string{"user_id", "client_id"}, []string{"scopes", "updated_at"}).String()
			},
			mysql:    "ON DUPLICATE KEY UPDATE scopes = VALUES(scopes), updated_at = VALUES(updated_at)",
			postgres: "ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at",
		},
		{
			name: "user_profile PK user_id",
			build: func(db *bun.DB) string {
				return applyUpsert(db.NewInsert().Model(&profileRow),
					[]string{"user_id"},
					[]string{"gender", "birthday", "locale", "timezone", "extra", "updated_at"}).String()
			},
			mysql:    "ON DUPLICATE KEY UPDATE gender = VALUES(gender), birthday = VALUES(birthday), locale = VALUES(locale), timezone = VALUES(timezone), extra = VALUES(extra), updated_at = VALUES(updated_at)",
			postgres: "ON CONFLICT (user_id) DO UPDATE SET gender = EXCLUDED.gender, birthday = EXCLUDED.birthday, locale = EXCLUDED.locale, timezone = EXCLUDED.timezone, extra = EXCLUDED.extra, updated_at = EXCLUDED.updated_at",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mysqlSQL := c.build(mysqlDB)
			if !strings.Contains(mysqlSQL, c.mysql) {
				t.Errorf("MySQL SQL 缺冲突分支 %q:\n%s", c.mysql, mysqlSQL)
			}
			if strings.Contains(mysqlSQL, "EXCLUDED") || strings.Contains(mysqlSQL, "ON CONFLICT") {
				t.Errorf("MySQL SQL 混入 PG 语法:\n%s", mysqlSQL)
			}
			pgSQL := c.build(pgDB)
			if !strings.Contains(pgSQL, c.postgres) {
				t.Errorf("PG SQL 缺冲突分支 %q:\n%s", c.postgres, pgSQL)
			}
			if strings.Contains(pgSQL, "DUPLICATE KEY") {
				t.Errorf("PG SQL 混入 MySQL 语法:\n%s", pgSQL)
			}
		})
	}
}

// TestEpochBumpSetTwoDialects epoch 递增回绕表达式为 ANSI CASE WHEN，两方言
// 原样渲染（MySQL 方言函数 IF() 不得残留）。
func TestEpochBumpSetTwoDialects(t *testing.T) {
	for _, tc := range []struct {
		name string
		db   *bun.DB
	}{
		{"mysql", bunMySQLSQLDB(t)},
		{"postgres", bunPGSQLDB(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sqlStr := tc.db.NewUpdate().Model((*model.User)(nil)).
				Set(epochBumpSet).
				Set("updated_at = ?", time.Now()).
				Where("id = ?", 1).
				String()
			if !strings.Contains(sqlStr,
				"epoch = CASE WHEN epoch + 1 > 30000 THEN 1 ELSE epoch + 1 END") {
				t.Errorf("SQL 缺 CASE WHEN 回绕表达式:\n%s", sqlStr)
			}
			if strings.Contains(sqlStr, "IF(") {
				t.Errorf("SQL 残留 MySQL 方言函数 IF():\n%s", sqlStr)
			}
		})
	}
}

// TestListFilterPositionSQLTwoDialects Q 模糊匹配与 ExcludeDeleted 前缀过滤
// 在两方言下均为 POSITION 字面匹配：%/ _ 不经转义直接参与匹配（两方言渲染
// 一致）；\ 按字面量参与匹配（渲染差异仅在字符串字面量转义层：MySQL 翻倍、
// PG 原样，与 LIKE 模式层转义无关）。SQL 中不再出现 LIKE 与 ESCAPE。
func TestListFilterPositionSQLTwoDialects(t *testing.T) {
	for _, tc := range []struct {
		name string
		db   *bun.DB
	}{
		{"mysql", bunMySQLSQLDB(t)},
		{"postgres", bunPGSQLDB(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := NewUserRepo(tc.db)
			sqlStr := rp.listUsersFilter(context.Background(), UserListQuery{
				Q: "100%_", ExcludeDeleted: true,
			}).String()
			for _, want := range []string{
				"POSITION('100%_' IN username) > 0",
				"POSITION('100%_' IN nickname) > 0",
				"POSITION('100%_' IN email) > 0",
				"POSITION('100%_' IN phone) > 0",
				"POSITION('deleted_' IN LOWER(username)) <> 1",
			} {
				if !strings.Contains(sqlStr, want) {
					t.Errorf("SQL 缺 %q:\n%s", want, sqlStr)
				}
			}
			if strings.Contains(sqlStr, " LIKE ") || strings.Contains(sqlStr, "ESCAPE") {
				t.Errorf("SQL 残留 LIKE / ESCAPE 形态:\n%s", sqlStr)
			}

			// \ 按字面量参与匹配：MySQL 渲染把字面量内的 \ 翻倍（字符串转义
			// 层，服务端还原为单 \），PG 原样——两库语义同为字面反斜杠。
			sqlStr = rp.listUsersFilter(context.Background(), UserListQuery{Q: `win\dows`}).String()
			want := `POSITION('win\\dows' IN username) > 0`
			if tc.name == "postgres" {
				want = `POSITION('win\dows' IN username) > 0`
			}
			if !strings.Contains(sqlStr, want) {
				t.Errorf("SQL 缺 %q:\n%s", want, sqlStr)
			}
		})
	}
}

// TestOrderClauseTwoDialects 非缺省排序列随方言引用（MySQL 反引号 / PG 双
// 引号）且恒追加 id 次序；缺省 / 字符集外回落 id 无引用、无追加。
func TestOrderClauseTwoDialects(t *testing.T) {
	mysqlDB := bunMySQLSQLDB(t)
	pgDB := bunPGSQLDB(t)

	clause, args := (UserListQuery{Sort: "username", Order: "asc"}).orderClause()
	mysqlSQL := mysqlDB.NewSelect().Model((*model.User)(nil)).
		OrderExpr(clause, args...).String()
	if !strings.Contains(mysqlSQL, "`username` ASC, id DESC") {
		t.Errorf("MySQL 排序缺反引号 Ident 形态:\n%s", mysqlSQL)
	}
	pgSQL := pgDB.NewSelect().Model((*model.User)(nil)).
		OrderExpr(clause, args...).String()
	if !strings.Contains(pgSQL, `"username" ASC, id DESC`) {
		t.Errorf("PG 排序缺双引号 Ident 形态:\n%s", pgSQL)
	}
	if strings.Contains(mysqlSQL, `"username"`) || strings.Contains(pgSQL, "`username`") {
		t.Errorf("排序列引用形态跨方言串扰:\nmysql: %s\npg: %s", mysqlSQL, pgSQL)
	}

	defClause, defArgs := (UserListQuery{Sort: "id; DROP TABLE user"}).orderClause()
	if defClause != "id DESC" || defArgs != nil {
		t.Errorf("非法 sort 回落 = (%q, %v), want (\"id DESC\", nil)", defClause, defArgs)
	}

	// client / eventlog 两处 orderClause 与 user_repo 同形态（Ident 引用 +
	// id 次序追加）。
	cClause, cArgs := (ClientListQuery{Sort: "name"}).orderClause()
	if cClause != "? DESC, id DESC" || len(cArgs) != 1 {
		t.Errorf("ClientListQuery orderClause = (%q, %v)", cClause, cArgs)
	}
	eClause, eArgs := (EventAdminQuery{Sort: "event", Order: "asc"}).orderClause()
	if eClause != "? ASC, id DESC" || len(eArgs) != 1 {
		t.Errorf("EventAdminQuery orderClause = (%q, %v)", eClause, eArgs)
	}
}
