// paths.go 两条安装路径的执行与状态机（docs/后端架构.md §3.15）：
// 执行顺序即状态机，每步成功才进下一步、失败即终止并返回明确错误码，
// 不产生半初始化状态；迁移幂等（版本表）+ 管理员存在性判定兜底（§3.16）。
// setup 状态不落盘：进程中断后重跑安装，按同一路径继续。
package setup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"

	"authloft/internal/config"
	"authloft/internal/migrate"
	"authloft/internal/security"
)

// §13 域内错误码（接口文档 §13 域码清单；业务码开放，Connect 化后由
// setup.go 的 setupFail 映射为 connect.NewError + ErrorInfo detail 承载
// ——域码语义不变，标准码映射见 setupCodeFor）。
const (
	CodeConfigInvalid    = "config_invalid"
	CodeDBUnreachable    = "db_unreachable"
	CodeRedisUnreachable = "redis_unreachable"
	CodeMigrationFailed  = "migration_failed"
	CodeAdminMissing     = "admin_missing"
	CodeUsernameInvalid  = "username_invalid"
	CodePasswordWeak     = "password_weak"
)

// stepTimeout 单步连通检查超时（文档未规定，取安装场景可接受的短超时）。
const stepTimeout = 3 * time.Second

// PathError 安装路径步骤失败：Code 进信封 error.code，Message 为固定安全
// 文案（不透出底层细节），Err 为底层原因——只进服务端日志且经 redact 脱敏
// （§3.15：不打印 DSN 密码段、admin_password、密钥明文）。
type PathError struct {
	Code    string
	Message string
	Err     error
}

func (e *PathError) Error() string {
	if e.Err == nil {
		return e.Code + ": " + e.Message
	}
	return e.Code + ": " + e.Message + ": " + e.Err.Error()
}

func (e *PathError) Unwrap() error { return e.Err }

// bizErr 包一步失败为 PathError。
func bizErr(code, message string, err error) error {
	return &PathError{Code: code, Message: message, Err: err}
}

// UploadConfig 路径 A：上传已有 config（§3.15 / 接口文档 §13.2）。
// ① 完整性校验（复用 config 结构与 Validate，缺 sign_key 同属不完整 →
// config_invalid，不自动补写）② DB 连通 ③ Redis 连通 ④ 迁移（幂等）
// ⑤ 管理员（ID=1）存在性检查 ⑥ 原子写入上传原文。成功后由调用方触发重启。
// 方言取上传 config 的 db.driver（空值回落 mysql），连通 / 迁移 / 管理员
// 判定全程按同一 driver 走统一连接工厂与方言感知 SQL。
func UploadConfig(ctx context.Context, configPath, text string) error {
	slog.Info("setup: path A (upload config) start")
	cfg, err := parseUploadedConfig(text)
	if err != nil {
		return err
	}
	driver := cfg.DB.EffectiveDriver()
	if err := checkDB(ctx, driver, cfg.DB.DSN); err != nil {
		return err
	}
	if err := checkRedis(ctx, cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB); err != nil {
		return err
	}
	if err := migrate.UpDriver(ctx, driver, cfg.DB.DSN); err != nil {
		return bizErr(CodeMigrationFailed, "database migration failed", err)
	}
	if err := requireAdmin(ctx, driver, cfg.DB.DSN); err != nil {
		return err
	}
	if err := WriteConfigFile(configPath, []byte(text)); err != nil {
		return err
	}
	slog.Info("setup: path A done, config written", "path", configPath)
	return nil
}

// FreshInstall 路径 B：全新安装（§3.15 / 接口文档 §13.3 行 1911）。
// ① 字段校验（root 必填且 host 为域名 / localhost，rpId 缺省取 root 的
// host 后同为域名校验——缺失 / IP / 非法 →
// config_invalid）② 连接性检查 ③ 迁移 ④ 插入管理员（固定 ID=1，已存在
// 则跳过（幂等）；用户名 / 密码校验在此步）⑤ 生成完整 config（所填项 +
// 随机密钥 + 默认值）原子写入。成功后由调用方触发重启。DB 方言按
// InstallInput.DBDriver（零值回落 mysql），⑤ 生成的 config 写入同一
// driver，重启后正常模式按同方言建连。
func FreshInstall(ctx context.Context, configPath string, in InstallInput) error {
	slog.Info("setup: path B (fresh install) start")
	driver := effectiveInstallDriver(in.DBDriver)
	if err := validateInstallInput(in); err != nil {
		return err
	}
	if err := checkDB(ctx, driver, in.DBDSN); err != nil {
		return err
	}
	if err := checkRedis(ctx, in.RedisAddr, in.RedisPassword, in.RedisDB); err != nil {
		return err
	}
	if err := migrate.UpDriver(ctx, driver, in.DBDSN); err != nil {
		return bizErr(CodeMigrationFailed, "database migration failed", err)
	}
	if err := installAdmin(ctx, driver, in.DBDSN, in.AdminUsername, in.AdminPassword); err != nil {
		return err
	}
	cfg, err := BuildInstallConfig(in)
	if err != nil {
		return err
	}
	out, err := marshalConfig(cfg)
	if err != nil {
		return err
	}
	if err := WriteConfigFile(configPath, out); err != nil {
		return err
	}
	slog.Info("setup: path B done, config written", "path", configPath)
	return nil
}

// effectiveInstallDriver 归一安装请求的 DB 方言：proto3 零值（空串）与
// mysql 等价（与 db.driver 空值回落口径一致）。未知值不在此拦——方言
// 合法性归 handler 的参数校验（invalid_request），直连调用方传入未知值
// 时由工厂建连期报错兜底。
func effectiveInstallDriver(v config.Driver) config.Driver {
	if v == "" {
		return config.DriverMySQL
	}
	return v
}

// parseUploadedConfig 路径 A 步骤 ①：上传 config 全文 → 解析 → Validate
// （§3.15：复用 internal/config 的结构与 Validate()，不自建一套；env 是
// 进程级注入，不参与上传内容的校验）。任一失败 → config_invalid。
func parseUploadedConfig(text string) (*config.Config, error) {
	var c config.Config
	if err := yaml.Unmarshal([]byte(text), &c); err != nil {
		return nil, bizErr(CodeConfigInvalid, "uploaded config is invalid or incomplete", err)
	}
	if err := c.Validate(); err != nil {
		return nil, bizErr(CodeConfigInvalid, "uploaded config is invalid or incomplete", err)
	}
	return &c, nil
}

// checkDB 步骤「DB 连通性」：按 driver 先做 DSN 形态校验再建连并 Ping；
// 任一失败 → db_unreachable（§13.3②：连接性失败不走 config_invalid，
// 也不允许建连期 panic 逸出为 500——pgdriver 的 WithDSN 对 url.Parse
// 失败的 DSN 在构造期直接 panic，故建连前必须拦截形态错误）。
// DSN 格式随 driver 解释（mysql / PG 两种形态）；路径 A 的上传 config
// 已在 parseUploadedConfig 校验过，此处幂等复核。
func checkDB(ctx context.Context, driver config.Driver, dsn string) error {
	if err := config.ValidateDBDSN(driver, dsn); err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	db, err := openDB(driver, dsn)
	if err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	return nil
}

// checkRedis 步骤「Redis 连通性」：RESP 直连 PING（带密码先 AUTH、非 0 库
// 先 SELECT）；失败 → redis_unreachable。不引客户端依赖，只用标准库。
func checkRedis(ctx context.Context, addr, password string, db int) error {
	d := net.Dialer{Timeout: stepTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return bizErr(CodeRedisUnreachable, "cannot connect to redis", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(stepTimeout)); err != nil {
		return bizErr(CodeRedisUnreachable, "cannot connect to redis", err)
	}
	r := bufio.NewReader(conn)
	if password != "" {
		if err := redisCommand(conn, r, "AUTH", password); err != nil {
			return bizErr(CodeRedisUnreachable, "cannot connect to redis", err)
		}
	}
	if db != 0 {
		if err := redisCommand(conn, r, "SELECT", strconv.Itoa(db)); err != nil {
			return bizErr(CodeRedisUnreachable, "cannot connect to redis", err)
		}
	}
	if err := redisCommand(conn, r, "PING"); err != nil {
		return bizErr(CodeRedisUnreachable, "cannot connect to redis", err)
	}
	return nil
}

// redisCommand 发送一条 RESP 命令并读单行响应：+ 开头为成功，其余（-ERR 等）
// 视为失败。
func redisCommand(conn net.Conn, r *bufio.Reader, args ...string) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write %s: %w", args[0], err)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read %s reply: %w", args[0], err)
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) > 0 && line[0] == '+' {
		return nil
	}
	return fmt.Errorf("redis replied %q to %s", line, args[0])
}

// requireAdmin 路径 A 步骤 ⑤：版本已最新但管理员（ID=1）缺失 →
// admin_missing（提示改走全新安装）。
func requireAdmin(ctx context.Context, driver config.Driver, dsn string) error {
	db, err := openDB(driver, dsn)
	if err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	var n int
	if err := db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE id = 1", migrate.UserTable(driver)),
	).Scan(&n); err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	if n == 0 {
		return bizErr(CodeAdminMissing, "admin account missing, use fresh install instead", nil)
	}
	return nil
}

// installAdmin 管理员行与权限行的「已存在则跳过」必须各自独立判定：管理员
// 已存在但权限行缺失时仍要补写，否则重装后管理员会永久失去权限（§3.15）。
// 三行同事务写出，任一步失败整套回滚，避免留下可登录却无权限的半初始化态。
// 方言差异（§4.2）：user 是 PG 保留字（标识符引用归 migrate.UserTable）；
// pgdriver 只认 $n 占位符（不翻译 ?）；PG 的 user.id 为 IDENTITY BY
// DEFAULT，显式 id=1 不推进底层序列，插入后须 setval 复位——否则后续
// 按默认值建号的业务写入会撞主键（nextval 从序列起点 1 重新开始）。
func installAdmin(ctx context.Context, driver config.Driver, dsn, username, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := validatePassword(username, password); err != nil {
		return err
	}
	db, err := openDB(driver, dsn)
	if err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	defer db.Close()
	var existing int
	if err := db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE id = 1", migrate.UserTable(driver)),
	).Scan(&existing); err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	var hash string
	if existing == 0 {
		h, err := hashPasswordArgon2id(password)
		if err != nil {
			return fmt.Errorf("setup: hash admin password: %w", err)
		}
		hash = h
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	defer tx.Rollback()
	if existing == 0 {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf(
				"INSERT INTO %s (id, username, user_status, created_at, updated_at) VALUES (1, %s, 1, NOW(), NOW())",
				migrate.UserTable(driver), placeholder(driver, 1),
			),
			username,
		); err != nil {
			return bizErr(CodeDBUnreachable, "cannot create admin user", err)
		}
		// IDENTITY 序列复位（PG 分支，紧随显式 id 插入）：BY DEFAULT 语义下
		// 显式 id 不推进底层序列，不复位则下一次按默认值建号的业务写入从
		// 序列起点 1 取值、撞主键。setval 到当前最大 id（is_called=true，
		// 下一次 nextval 返回 max+1）；此分支 freshly 插入后 max(id) ≥ 1，
		// 幂等可重跑。pg_get_serial_sequence 对 IDENTITY 列同样适用，表名
		// 串内自带双引号（PG 对保留字表的引用写法）。
		if driver == config.DriverPostgres {
			if _, err := tx.ExecContext(ctx,
				fmt.Sprintf(
					"SELECT setval(pg_get_serial_sequence('%s', 'id'), (SELECT COALESCE(MAX(id), 1) FROM %s), true)",
					`"user"`, migrate.UserTable(driver),
				),
			); err != nil {
				return bizErr(CodeDBUnreachable, "cannot sync user id sequence", err)
			}
		}
		// secret 列按二进制承载（MySQL VARBINARY / PG BYTEA）：argon2id PHC
		// 串以 []byte 传参，两种方言都能落库（PG 侧传 string 会按 bytea
		// 文本格式解析而失败）。
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf(
				"INSERT INTO user_credential (user_id, kind, secret, is_enabled, created_at, updated_at) VALUES (1, 'password', %s, 1, NOW(), NOW())",
				placeholder(driver, 1),
			),
			[]byte(hash),
		); err != nil {
			return bizErr(CodeDBUnreachable, "cannot create admin credential", err)
		}
	} else {
		slog.Info("setup: admin (id=1) already exists, skip creating")
	}
	// 权限行单独判存在性，不复用管理员行的判定结果。
	var permExists int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM user_permission WHERE user_id = 1 AND point = 'superadmin'",
	).Scan(&permExists); err != nil {
		return bizErr(CodeDBUnreachable, "cannot check superadmin permission", err)
	}
	if permExists == 0 {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO user_permission (user_id, point) VALUES (1, 'superadmin')",
		); err != nil {
			return bizErr(CodeDBUnreachable, "cannot grant superadmin permission", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return bizErr(CodeDBUnreachable, "cannot commit admin creation", err)
	}
	slog.Info("setup: admin (id=1) ensured with superadmin permission")
	return nil
}

// deletedUsernamePrefix 删除匿名化保留前缀（§2.3 / §5.4：删除用户把
// username 改写为 "deleted_<id>"，系统保留标记，设置用户名的一切入口一律
// 拒绝（不分大小写，与列表侧 LOWER(username) 过滤同口径）——安装入口为
// 完整性覆盖，实际安装用户名自定）。
const deletedUsernamePrefix = "deleted_"

// hasDeletedPrefix deleted_ 保留前缀判定：不分大小写的字面前缀匹配（uk_username
// 唯一键在 ci collation 下大小写变体同键）。入口校验先行 usernameRE（纯
// ASCII），字节切片不会撕裂多字节字符。
func hasDeletedPrefix(username string) bool {
	return len(username) >= len(deletedUsernamePrefix) &&
		strings.EqualFold(username[:len(deletedUsernamePrefix)], deletedUsernamePrefix)
}

// validateUsername 管理员用户名规则（接口文档 §2.3 行 444——用户名规则的
// 唯一定义处）：^[A-Za-z0-9_]{5,20}$；违规或命中删除匿名化保留前缀
// → username_invalid。
func validateUsername(username string) error {
	if !usernameRE.MatchString(username) || hasDeletedPrefix(username) {
		return bizErr(CodeUsernameInvalid, "admin username must match ^[A-Za-z0-9_]{5,20}$ and must not start with deleted_", nil)
	}
	return nil
}

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9_]{5,20}$`)

// validatePassword 管理员密码策略（接口文档 §5.6 默认值——setup 模式无
// settings，按默认策略）。违规 → password_weak。完整实现：security/policy.go
// （security/policy.go 取代本处安装期过渡副本），错误信息风格保持不变。
func validatePassword(username, password string) error {
	violations := security.ValidatePassword(security.DefaultPasswordPolicy(), username, "", password)
	if len(violations) == 0 {
		return nil
	}
	return bizErr(CodePasswordWeak, "admin password does not meet the policy: "+violations[0].Reason, nil)
}

// hashPasswordArgon2id 生成 PHC 格式 argon2id 哈希串（§4.2：user_credential
// password 行 secret = argon2id 串，含参数与盐）。参数取 §3.2 argon2 默认值
// （安装时 config 尚未生成）：t=3 m=65536 p=4 keylen=32。
func hashPasswordArgon2id(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	const (
		argon2Time = 3
		argon2Mem  = 64 * 1024
		argon2Par  = 4
		argon2Len  = 32
	)
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Mem, argon2Par, argon2Len)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Mem, argon2Time, argon2Par,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// openDB 经统一连接工厂（migrate.NewDB）建连：驱动装配与 parseTime 强制
// 等口径收口在工厂；只建连不 Ping，连通检查由调用方做。driver 由安装
// 请求 / 上传 config 决定（mysql | postgres；非法值在建连期报错，调用方
// 兜底为 db_unreachable）。
func openDB(driver config.Driver, dsn string) (*sql.DB, error) {
	return migrate.NewDB(driver, dsn)
}

// placeholder 方言感知的单值占位符：mysql 用 ?；pgdriver 的 query
// formatter 只内联 $n（不翻译 ?），PG 侧裸 SQL 须写 $n。
func placeholder(driver config.Driver, n int) string {
	if driver == config.DriverPostgres {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

// pgURLPasswordRe 匹配 PG URL DSN 的 userinfo 密码段（postgres://user:pass@
// / postgresql://user:pass@）：userinfo 终止于首个 / 之前的最后一个 @
// （RFC 3986 authority 解析），密码不含未编码的 / 与空白、可含 @。
var pgURLPasswordRe = regexp.MustCompile(`((?:postgres|postgresql)://[A-Za-z0-9._~%-]+:)([^/\s]*)@`)

// mysqlPasswordRe 匹配 go-sql-driver DSN 的密码段（user:pass@tcp(host:port)
// /name）：userinfo 终止于 net( 前最后一个 @（驱动从右往左解析），密码
// 可含 @；锚定 tcp(/unix( 避免误伤同串中的其他 user:pass@ 形态。
var mysqlPasswordRe = regexp.MustCompile(`([A-Za-z0-9._-]+):(.*)@((?:tcp|unix)\()`)

// redact 把字符串中的 DSN 密码段打码后返回（§3.15：日志不打印 DSN 密码段）。
// 两种 DSN 形态分别按各自解析器的 userinfo 语义取段：PG URL 与 MySQL
// tcp/unix 形态；对多 @ 密码按「最后一个 @」边界取全，不残留尾部。
func redact(s string) string {
	s = pgURLPasswordRe.ReplaceAllString(s, "${1}***@")
	return mysqlPasswordRe.ReplaceAllString(s, "$1:***@$3")
}
