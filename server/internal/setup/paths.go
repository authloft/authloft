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

	"github.com/go-sql-driver/mysql"
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
func UploadConfig(ctx context.Context, configPath, text string) error {
	slog.Info("setup: path A (upload config) start")
	cfg, err := parseUploadedConfig(text)
	if err != nil {
		return err
	}
	if err := checkDB(ctx, cfg.DB.DSN); err != nil {
		return err
	}
	if err := checkRedis(ctx, cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB); err != nil {
		return err
	}
	if err := migrate.Up(ctx, cfg.DB.DSN); err != nil {
		return bizErr(CodeMigrationFailed, "database migration failed", err)
	}
	if err := requireAdmin(ctx, cfg.DB.DSN); err != nil {
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
// 随机密钥 + 默认值）原子写入。成功后由调用方触发重启。
func FreshInstall(ctx context.Context, configPath string, in InstallInput) error {
	slog.Info("setup: path B (fresh install) start")
	if err := validateInstallInput(in); err != nil {
		return err
	}
	if err := checkDB(ctx, in.DBDSN); err != nil {
		return err
	}
	if err := checkRedis(ctx, in.RedisAddr, in.RedisPassword, in.RedisDB); err != nil {
		return err
	}
	if err := migrate.Up(ctx, in.DBDSN); err != nil {
		return bizErr(CodeMigrationFailed, "database migration failed", err)
	}
	if err := installAdmin(ctx, in.DBDSN, in.AdminUsername, in.AdminPassword); err != nil {
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

// checkDB 步骤「DB 连通性」：解析 DSN 建连并 Ping；失败 → db_unreachable。
func checkDB(ctx context.Context, dsn string) error {
	db, err := openDB(dsn)
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
func requireAdmin(ctx context.Context, dsn string) error {
	db, err := openDB(dsn)
	if err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM user WHERE id = 1").Scan(&n); err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	if n == 0 {
		return bizErr(CodeAdminMissing, "admin account missing, use fresh install instead", nil)
	}
	return nil
}

// installAdmin 路径 B 步骤 ③：用户名 / 密码校验后插入管理员（固定 ID=1，
// §4.2；已存在则跳过——幂等，不覆盖既有密码）。user 行与 password 凭证行
// 同一事务写出。
func installAdmin(ctx context.Context, dsn, username, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := validatePassword(username, password); err != nil {
		return err
	}
	db, err := openDB(dsn)
	if err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	defer db.Close()
	var existing int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM user WHERE id = 1").Scan(&existing); err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	if existing > 0 {
		slog.Info("setup: admin (id=1) already exists, skip creating")
		return nil
	}
	hash, err := hashPasswordArgon2id(password)
	if err != nil {
		return fmt.Errorf("setup: hash admin password: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return bizErr(CodeDBUnreachable, "cannot connect to database", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO user (id, username, user_status, created_at, updated_at) VALUES (1, ?, 1, NOW(), NOW())",
		username,
	); err != nil {
		return bizErr(CodeDBUnreachable, "cannot create admin user", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO user_credential (user_id, kind, secret, is_enabled, created_at, updated_at) VALUES (1, 'password', ?, 1, NOW(), NOW())",
		hash,
	); err != nil {
		return bizErr(CodeDBUnreachable, "cannot create admin credential", err)
	}
	if err := tx.Commit(); err != nil {
		return bizErr(CodeDBUnreachable, "cannot commit admin creation", err)
	}
	slog.Info("setup: admin (id=1) created")
	return nil
}

// validateUsername 管理员用户名规则（接口文档 §2.3 行 444——用户名规则的
// 唯一定义处）：^[A-Za-z0-9_]{5,20}$；违规 → username_invalid。
func validateUsername(username string) error {
	if usernameRE.MatchString(username) {
		return nil
	}
	return bizErr(CodeUsernameInvalid, "admin username must match ^[A-Za-z0-9_]{5,20}$", nil)
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

// openDB 解析并规范化 DSN 后建立连接（强制 parseTime，与 migrate 包同
// 口径）；只建连不 Ping，连通检查由调用方做。
func openDB(dsn string) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ParseTime = true
	return sql.Open("mysql", cfg.FormatDSN())
}

// dsnPasswordRe 匹配 go-sql-driver DSN 的密码段（user:pass@）。
var dsnPasswordRe = regexp.MustCompile(`([A-Za-z0-9._-]+):([^@\s]*)@`)

// redact 把字符串中的 DSN 密码段打码后返回（§3.15：日志不打印 DSN 密码段）。
func redact(s string) string {
	return dsnPasswordRe.ReplaceAllString(s, "$1:***@")
}
