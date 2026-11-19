// user / user_profile 表读写（后端架构 §3.9 / §4.2）。DDL 归 migrations/
// （§3.16），本文件只做行级读写与文档明确的查询最小集；事务边界在 service
// （§3.9）。掩码（接口文档 §3.1）、extra 的 msgpack 编解码、al:pwdep 缓存
// 同步（§5.1）均归上层——repo 层拿到什么存什么。
package repo

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/repo/model"
)

// ErrUserDuplicate Create 命中唯一键（uk_username / uk_phone / uk_email
// 之一，§4.2）时的可判别错误；具体冲突键与值在底层 *mysql.MySQLError 中。
var ErrUserDuplicate = errors.New("user repo: duplicate unique key")

// epochBumpSet epoch 递增 + 回绕的 SET 表达式（§4.2：递增结果 > 30000 置 1、
// 跳过 0）。CASE WHEN 为 ANSI 写法两库通用；MySQL 方言函数 IF() 不能跨库，
// IncEpoch 与 AnonymizeUser 共用同一表达式防两处口径漂移。
const epochBumpSet = "epoch = CASE WHEN epoch + 1 > 30000 THEN 1 ELSE epoch + 1 END"

// UserRepo user / user_profile 表数据访问（§3.9：表与文件对应
// user(+user_profile) → user_repo.go）。
type UserRepo struct {
	db *bun.DB
}

// NewUserRepo 按 bun 连接构造。
func NewUserRepo(db *bun.DB) *UserRepo {
	return &UserRepo{db: db}
}

// FindByID 按主键取用户；未命中返回包装的 sql.ErrNoRows。
func (r *UserRepo) FindByID(ctx context.Context, id int64) (*model.User, error) {
	var u model.User
	if err := r.db.NewSelect().Model(&u).
		Where("id = ?", id).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("user repo: find by id: %w", err)
	}
	return &u, nil
}

// FindByUsername 按唯一键 uk_username 取用户；未命中返回包装的
// sql.ErrNoRows。
func (r *UserRepo) FindByUsername(ctx context.Context, username string) (*model.User, error) {
	var u model.User
	if err := r.db.NewSelect().Model(&u).
		Where("username = ?", username).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("user repo: find by username: %w", err)
	}
	return &u, nil
}

// FindByPhone 按唯一键 uk_phone 取用户；未命中返回包装的 sql.ErrNoRows。
func (r *UserRepo) FindByPhone(ctx context.Context, phone string) (*model.User, error) {
	var u model.User
	if err := r.db.NewSelect().Model(&u).
		Where("phone = ?", phone).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("user repo: find by phone: %w", err)
	}
	return &u, nil
}

// FindByEmail 按唯一键 uk_email 取用户；未命中返回包装的 sql.ErrNoRows。
func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	var u model.User
	if err := r.db.NewSelect().Model(&u).
		Where("email = ?", email).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("user repo: find by email: %w", err)
	}
	return &u, nil
}

// Create 插入用户；命中唯一键（username / phone / email）返回
// ErrUserDuplicate（errors.Is 可判别），其余错误原样包装。created_at /
// updated_at 零值时由本方法补齐（bun 无时间列自动填充）；default
// tag 列（user_status=1 / mfa_required=0 等）零值经 DEFAULT 占位由 DB 默认
// 值填充（CODE_GUIDE §3.5 bun 零值口径）。
func (r *UserRepo) Create(ctx context.Context, u *model.User) error {
	now := time.Now()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = now
	}
	if _, err := r.db.NewInsert().Model(u).Exec(ctx); err != nil {
		if isUserDuplicateKey(err) {
			return fmt.Errorf("user repo: create: %w: %w", ErrUserDuplicate, err)
		}
		return fmt.Errorf("user repo: create: %w", err)
	}
	return nil
}

// CreateWithCredential 建号写入在同一事务内完成（后端架构 §7.4）：单事务内
// 先 INSERT user、再 INSERT user_credential（c.UserID 由 user INSERT 回填的
// 自增 ID 关联后写入），任一失败整体回滚——两跳非同事务会在 credential 失败
// 时留下无凭证 user 行，username / email / phone 占位无自愈。c 为 nil 时只
// INSERT user（三方免密建号，§12.5：免密建号不设密码，user_credential 无
// password 行，setPassReset 的「无行补建」分支即为其后置密码出口）。user 表
// 唯一键冲突（username / phone / email）仍返回 ErrUserDuplicate（errors.Is
// 可判别，判别口径与错误包装同 Create）；user_credential 的 created_at /
// updated_at 零值时由本方法补齐。
func (r *UserRepo) CreateWithCredential(ctx context.Context, u *model.User, c *model.UserCredential) error {
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		now := time.Now()
		if u.CreatedAt.IsZero() {
			u.CreatedAt = now
		}
		if u.UpdatedAt.IsZero() {
			u.UpdatedAt = now
		}
		if _, err := tx.NewInsert().Model(u).Exec(ctx); err != nil {
			return err
		}
		if c == nil {
			return nil
		}
		c.UserID = u.ID
		if c.CreatedAt.IsZero() {
			c.CreatedAt = now
		}
		if c.UpdatedAt.IsZero() {
			c.UpdatedAt = now
		}
		_, err := tx.NewInsert().Model(c).Exec(ctx)
		return err
	})
	if err != nil {
		if isUserDuplicateKey(err) {
			return fmt.Errorf("user repo: create with credential: %w: %w", ErrUserDuplicate, err)
		}
		return fmt.Errorf("user repo: create with credential: %w", err)
	}
	return nil
}

// GetEpoch 读 user.epoch：§11.1 第 3 步缓存 miss 时的回源路径。
// 用户不存在返回包装的 sql.ErrNoRows。
func (r *UserRepo) GetEpoch(ctx context.Context, id int64) (int16, error) {
	var u model.User
	err := r.db.NewSelect().Model(&u).
		Column("id", "epoch").
		Where("id = ?", id).
		Limit(1).
		Scan(ctx)
	if err != nil {
		return 0, fmt.Errorf("user repo: get epoch: %w", err)
	}
	return u.Epoch, nil
}

// IncEpoch 递增 epoch 并返回递增后的新值（供上层同步 al:pwdep:{uid} 缓存，
// §5.1）：递增结果 > 30000 时回绕为 1、跳过 0（0 是初始值，回绕到 0 会让
// 回绕前签发、仍在有效期内的旧令牌重新匹配通过，等于复活全部旧令牌；§4.2）。
// 递增、回绕与 updated_at 刷新在同一条 UPDATE 语句内原子完成。用户不存在
// 返回包装的 sql.ErrNoRows（epoch 递增必产生变更，rows=0 即行不存在）。
func (r *UserRepo) IncEpoch(ctx context.Context, id int64) (int16, error) {
	var epoch int16
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewUpdate().Model((*model.User)(nil)).
			Where("id = ?", id).
			Set(epochBumpSet).
			Set("updated_at = ?", time.Now()).
			Exec(ctx)
		if err != nil {
			return err
		}
		if err := requireChangedRow(ctx, tx, res, (*model.User)(nil),
			"", "id = ?", id); err != nil {
			return err
		}
		return tx.NewSelect().Model((*model.User)(nil)).
			ColumnExpr("epoch").
			Where("id = ?", id).
			Scan(ctx, &epoch)
	})
	if err != nil {
		return 0, fmt.Errorf("user repo: inc epoch: %w", err)
	}
	return epoch, nil
}

// UpdateLastLogin 更新 last_login_at（§5.2 延迟写入队列 worker 消费；「同
// user_id 合并、只保留最新时间」归队列合并策略，repo 只写一行），updated_at
// 一并刷新。用户不存在返回包装的 sql.ErrNoRows。MySQL 驱动默认 changed-rows
// 语义：同值 UPDATE（§5.2 队列幂等重放）RowsAffected=0 与行不存在不可区分，
// 故 rows=0 时补 SELECT 存在性判定——行仍在则视为幂等成功，查无此行才报
// sql.ErrNoRows。
func (r *UserRepo) UpdateLastLogin(ctx context.Context, id int64, at time.Time) error {
	res, err := r.db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", id).
		Set("last_login_at = ?", at).
		Set("updated_at = ?", time.Now()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("user repo: update last login: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.User)(nil),
		"user repo: update last login", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// UpdateProfileColumns 列级更新 user 表资料列 nickname / avatar_url
// （接口文档 §3.2 UpdateProfile：可选字段部分更新——用户名 / 手机号 / 邮箱
// 不可改、未传字段不覆盖）。nil = 该列未传、不写入；updated_at 一并刷新。
// 用户不存在返回包装的 sql.ErrNoRows。MySQL 驱动默认 changed-rows 语义：
// 同值 UPDATE RowsAffected=0 与行不存在不可区分，故 rows=0 时补 SELECT
// 存在性判定——行仍在则视为幂等成功，查无此行才报 sql.ErrNoRows（口径同
// UpdateLastLogin）。
func (r *UserRepo) UpdateProfileColumns(ctx context.Context, id int64, nickname, avatarURL *string) error {
	upd := r.db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", id).
		Set("updated_at = ?", time.Now())
	if nickname != nil {
		upd = upd.Set("nickname = ?", *nickname)
	}
	if avatarURL != nil {
		upd = upd.Set("avatar_url = ?", *avatarURL)
	}
	res, err := upd.Exec(ctx)
	if err != nil {
		return fmt.Errorf("user repo: update profile columns: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.User)(nil),
		"user repo: update profile columns", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// UpdateContactColumns 列级更新 user 表联系方式列 phone / email 与对应
// verified 位（接口文档 §3.4 BindPhone / BindEmail verify 步落库——目标列 +
// phone_verified / email_verified 置 1；BindContactStore 窄接口契约）。
// 指针语义 nil = 该列不写入；指针非 nil 且值为空串 = 显式清空，写 NULL 而
// 非空串（uk_phone / uk_email 对空串仍唯一，多个清空行互撞；NULL 不参与
// 唯一约束，匿名化同口径，§4.2 删除匿名化列改写）——绑定链路既有调用恒传
// 非空值，不受该归一影响。updated_at 一并刷新。目标被他人抢占命中
// uk_phone / uk_email 唯一键（MySQL 1062）返回 errors.Is 可判别的
// ErrUserDuplicate（UserRepo.Create 判别同源——challenge 拦截后 verify 落库
// 前的 TOCTOU 占用由 service 层回补 target_taken，《后端架构》§10.2）。
// 用户不存在返回包装的 sql.ErrNoRows：MySQL 驱动默认 changed-rows 语义，
// rows=0 时补 SELECT 存在性判定（口径同 UpdateProfileColumns）。
func (r *UserRepo) UpdateContactColumns(ctx context.Context, id int64, phone, email *string, phoneVerified, emailVerified *int8) error {
	upd := r.db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", id).
		Set("updated_at = ?", time.Now())
	if phone != nil {
		if *phone == "" {
			upd = upd.Set("phone = ?", nil)
		} else {
			upd = upd.Set("phone = ?", *phone)
		}
	}
	if email != nil {
		if *email == "" {
			upd = upd.Set("email = ?", nil)
		} else {
			upd = upd.Set("email = ?", *email)
		}
	}
	if phoneVerified != nil {
		upd = upd.Set("phone_verified = ?", *phoneVerified)
	}
	if emailVerified != nil {
		upd = upd.Set("email_verified = ?", *emailVerified)
	}
	res, err := upd.Exec(ctx)
	if err != nil {
		if isUserDuplicateKey(err) {
			return fmt.Errorf("user repo: update contact columns: %w: %w", ErrUserDuplicate, err)
		}
		return fmt.Errorf("user repo: update contact columns: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.User)(nil),
		"user repo: update contact columns", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// deletedUserPrefix 删除匿名化的用户名保留前缀（《后端架构》§4.2）：
// username 改写为 "deleted_<id>"，列表默认排除该前缀行（§5.4，过滤不分
// 大小写——LOWER(username) 固定口径，见 listUsersFilter）。
const deletedUserPrefix = "deleted_"

// UserListQuery ListUsers 入参：UserStatus 为 nil 时不过滤（§5.4 筛选入参）；
// Q 非空时对 username / nickname / email / phone 四列做模糊匹配（跨方言
// 口径：POSITION 字面子串匹配，%/_/\ 等字符一律按字面量参与匹配，无转义
// 语义）；时间维度为 Unix 秒闭区间，nil 表示该维度不过滤；MfaRequired 为
// nil 时不过滤；CredentialKind 非空时筛持有该类型凭证的用户；ExcludeDeleted
// 为 true 时排除 deleted_ 前缀的匿名化行。分页按 §1.7（page 从 1 开始、
// pageSize 默认 20、上限 100）。Sort / Order 取值由前端限定（§1.7 后端不做
// 白名单强制校验）——repo 只做字符集防注入（非 [a-z0-9_] 列名静默回落 id，
// order 非 asc 一律 desc），不拒绝请求。
type UserListQuery struct {
	UserStatus *int8
	Q          string
	Sort       string
	Order      string
	Page       int
	PageSize   int

	CreatedFrom    *int64
	CreatedTo      *int64
	LastLoginFrom  *int64
	LastLoginTo    *int64
	MfaRequired    *int8
	CredentialKind string
	ExcludeDeleted bool
}

// userSortColumnPattern 排序列名字符集（小写字母 / 数字 / 下划线——user 表
// 列名均在该集合内；字符集校验是防 ORDER BY 注入的格式约束，不是取值
// 白名单：§1.7 后端不做白名单强制校验）。
var userSortColumnPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// userDefaultSortColumn 默认排序列（缺省 / 非法 sort 的回落值）。
const userDefaultSortColumn = "id"

// ListUsers 分页列表：返回当页行与过滤后总数（§1.7 响应
// {items, total, page, pageSize} 的数据来源）。
func (r *UserRepo) ListUsers(ctx context.Context, q UserListQuery) ([]model.User, int64, error) {
	page, size := q.normalize()
	filter := func() *bun.SelectQuery { return r.listUsersFilter(ctx, q) }
	total, err := filter().Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("user repo: list count: %w", err)
	}
	var rows []model.User
	clause, orderArgs := q.orderClause()
	err = filter().
		OrderExpr(clause, orderArgs...).
		Limit(int64(size)).
		Offset(int64((page-1)*size)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, 0, fmt.Errorf("user repo: list: %w", err)
	}
	return rows, total, nil
}

// listUsersFilter 构造 §5.4 列表筛选的 WHERE 集（Count 与 Scan 共用同一
// 过滤集，避免两处条件漂移）。测试以 String() 断言 SQL 形态。
func (r *UserRepo) listUsersFilter(ctx context.Context, q UserListQuery) *bun.SelectQuery {
	sq := r.db.NewSelect().Model((*model.User)(nil))
	if q.UserStatus != nil {
		sq = sq.Where("user_status = ?", *q.UserStatus)
	}
	if q.Q != "" {
		// 字面子串匹配走 POSITION(? IN col)（ANSI，两库通用）：LIKE %q% 需按
		// 方言转义 %/_/通配符且 PG 默认无 \ 转义，字面语义无法跨库保证；
		// POSITION 不解释通配符，%/_/\ 天然按字面量参与匹配。大小写敏感性
		// 跟随列 collation，与原 LIKE %q% 口径一致（不额外 LOWER）。
		sq = sq.Where(
			"POSITION(? IN username) > 0 OR POSITION(? IN nickname) > 0 OR "+
				"POSITION(? IN email) > 0 OR POSITION(? IN phone) > 0",
			q.Q, q.Q, q.Q, q.Q,
		)
	}
	if q.ExcludeDeleted {
		// POSITION(...) <> 1 是「NOT LIKE '前缀_%'」的字面等价：= 1 即从前缀
		// 字符起命中（= 原 LIKE 命中态），0 = 不含、>1 = 前缀出现在串中部
		// （= 原 LIKE 未命中态，行保留）。兼作大小写口径固定：LOWER() 使
		// deleted_ / DELETED_ 变体行均被过滤（§5.4 默认过滤与 §2.3 前缀禁用
		// 同口径；生产实例列 collation 不可从仓库判定——不依赖列 collation
		// 的 ci 行为，cs / binary 列上亦不漏筛）。系统只写小写 "deleted_<id>"，
		// 任何大小写变体行都已被建号入口拒绝，此处过滤的是「已匿名化行」与
		// 「理论上的变体行」。
		sq = sq.Where("POSITION(? IN LOWER(username)) <> 1", deletedUserPrefix)
	}
	if q.CreatedFrom != nil {
		sq = sq.Where("created_at >= ?", time.Unix(*q.CreatedFrom, 0).UTC())
	}
	if q.CreatedTo != nil {
		sq = sq.Where("created_at <= ?", time.Unix(*q.CreatedTo, 0).UTC())
	}
	if q.LastLoginFrom != nil {
		sq = sq.Where("last_login_at >= ?", time.Unix(*q.LastLoginFrom, 0).UTC())
	}
	if q.LastLoginTo != nil {
		sq = sq.Where("last_login_at <= ?", time.Unix(*q.LastLoginTo, 0).UTC())
	}
	if q.MfaRequired != nil {
		sq = sq.Where("mfa_required = ?", *q.MfaRequired)
	}
	if q.CredentialKind != "" {
		sub := r.db.NewSelect().
			Model((*model.UserCredential)(nil)).
			ColumnExpr("user_id").
			Where("kind = ?", q.CredentialKind)
		sq = sq.Where("id IN (?)", sub)
	}
	return sq
}

// orderClause 排序子句：sort 缺省 / 字符集外回落 id，order 仅 asc / desc
// （大小写不敏感，其余含缺省一律 desc——与既有固定排序的方向一致）；非 id
// 主序恒追加 id 次序保证分页全序稳定（同值行跨页不漂移，口径同
// webauthn_repo.ListByUser）。列名经 bun.Ident 随方言引用（MySQL 反引号 /
// PG 双引号），反引号写死只对 MySQL 成立；白名单仍是防注入前置，Ident 只
// 负责引用形态，不替代字符集校验。
func (q UserListQuery) orderClause() (string, []any) {
	col := q.Sort
	if col == "" || !userSortColumnPattern.MatchString(col) {
		col = userDefaultSortColumn
	}
	dir := "DESC"
	if strings.EqualFold(q.Order, "asc") {
		dir = "ASC"
	}
	if col == userDefaultSortColumn {
		return col + " " + dir, nil
	}
	return "? " + dir + ", id DESC", []any{bun.Ident(col)}
}

// UpdateUserStatus 列级更新 user_status（§5.4 禁用 / 启用——禁用入口是列级
// UPDATE，不受 Create 的 default:1 tag 影响，见 model.User 注释；启用态同
// 构造）。updated_at 一并刷新。用户不存在返回包装的 sql.ErrNoRows；同值
// 重放幂等成功（changed-rows 语义下 rows=0 补 SELECT 存在性判定，口径同
// UpdateProfileColumns）。
func (r *UserRepo) UpdateUserStatus(ctx context.Context, id int64, userStatus int8) error {
	res, err := r.db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", id).
		Set("user_status = ?", userStatus).
		Set("updated_at = ?", time.Now()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("user repo: update user status: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.User)(nil),
		"user repo: update user status", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// UpdateMfaRequired 列级更新 user 表两步验证开关（§3.5 SetMfa 唯一写入端）。
// 只写 mfa_required 列：开关切换不改变登录凭据，不递增 epoch、不失效会话。
// updated_at 一并刷新。用户不存在返回包装的 sql.ErrNoRows；同值重放幂等
// 成功（changed-rows 语义下 rows=0 补 SELECT 存在性判定，口径同
// UpdateUserStatus）。
func (r *UserRepo) UpdateMfaRequired(ctx context.Context, id int64, mfaRequired int8) error {
	res, err := r.db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", id).
		Set("mfa_required = ?", mfaRequired).
		Set("updated_at = ?", time.Now()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("user repo: update mfa required: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.User)(nil),
		"user repo: update mfa required", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// normalize 分页参数归一（§1.7：page 1 起、pageSize 默认 20 上限 100）。
func (q UserListQuery) normalize() (page, size int) {
	page, size = q.Page, q.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}

// ListByIDs 批量按主键读 user 行与对应 user_profile 行（接口文档 §7.2
// GetUserProfiles 批量读，上限 / 缺失 / 顺序 / 去重口径归 handler）：user 表
// 与 user_profile 表各一条 IN 语句、零循环单查——handler 一次调用完成整批
// 读取（N+1 禁止，§7.2 理由）。结果顺序不保证（IN 无序），调用方按入参 ids
// 定位回填顺序自管（§7.2：响应顺序 = 入参去重后顺序）；缺失 id 的行自然
// 缺席（§7.2 跳过不占位），缺失 profile 行由调用方以 nil 组装零值 profile
// 消息（同 GetProfile 口径：行缺失不视为错误）。ids 为空时返回双 nil、不触
// 库（空批量空集语义，§7.2）。
func (r *UserRepo) ListByIDs(ctx context.Context, ids []int64) ([]model.User, []model.UserProfile, error) {
	if len(ids) == 0 {
		return nil, nil, nil
	}
	var users []model.User
	if err := r.db.NewSelect().Model(&users).
		Where("id IN (?)", bun.In(ids)).
		Scan(ctx); err != nil {
		return nil, nil, fmt.Errorf("user repo: list by ids: %w", err)
	}
	var profiles []model.UserProfile
	if err := r.db.NewSelect().Model(&profiles).
		Where("user_id IN (?)", bun.In(ids)).
		Scan(ctx); err != nil {
		return nil, nil, fmt.Errorf("user repo: list profiles by ids: %w", err)
	}
	return users, profiles, nil
}

// GetProfile 取 user_profile 行（§3.1 profile 字段的数据来源）；未命中返回
// 包装的 sql.ErrNoRows。
func (r *UserRepo) GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error) {
	var p model.UserProfile
	if err := r.db.NewSelect().Model(&p).
		Where("user_id = ?", userID).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("user repo: get profile: %w", err)
	}
	return &p, nil
}

// SaveProfile 整行 UPSERT user_profile（主键 user_id 冲突更新指定列覆盖：
// gender / birthday / locale / timezone / extra / updated_at；upsert 子句按
// 方言分派，applyUpsert）。接口文档 §3.2 UpdateProfile 的可选字段部分更新
// 语义归 service（先读后拼整行）；extra 为 msgpack 字节，编解码归上层。
// updated_at 零值时由本方法补齐（bun 无时间列自动填充）。
func (r *UserRepo) SaveProfile(ctx context.Context, p *model.UserProfile) error {
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now()
	}
	if _, err := applyUpsert(r.db.NewInsert().Model(p),
		[]string{"user_id"},
		[]string{"gender", "birthday", "locale", "timezone", "extra", "updated_at"}).
		Exec(ctx); err != nil {
		return fmt.Errorf("user repo: save profile: %w", err)
	}
	return nil
}

// AnonymizeUser 删除用户的单事务匿名化改写（§4.2：等价软删除，不物理删行、
// 不新增字段，deleted_ 前缀为唯一标记）。单事务内依次：① user 行改写——
// user_status=0、username="deleted_<id>"（十进制 id 占用 uk_username，id 唯一
// 故不冲突）、nickname/avatar_url 清空、phone/email 置 NULL、phone_verified /
// email_verified / mfa_required 置 0，last_login_at / created_at 保留供审计；
// epoch 递增与回绕同语句原子完成（语义同 IncEpoch，§4.2 回绕 >30000 置 1）；
// ② user_profile 行存在则清空 gender / birthday / locale / timezone / extra
// （行缺失容忍——profile 行本就可选）；③ 凭证全清（password / totp /
// webauthn / recovery_code 一并删除，含 WebAuthn 附加表）；④ 第三方绑定全清
// （全行 DELETE，Union 连带行随之清零，§12.7）。跨表事务收编 repo（先例
// CreateWithCredential / WebauthnRepo.Create）：拆多次调用非同事务会在中途
// 失败时留下半删除态。已匿名化行的拒绝（再删返回 not_found）与权限门禁归
// 上层（§4.2 / §4.8），本方法只保证行存在性与事务原子性。用户不存在返回
// 包装的 sql.ErrNoRows；返回递增后的新 epoch 供上层同步 al:pwdep:{uid}
// （§5.1）。
func (r *UserRepo) AnonymizeUser(ctx context.Context, id int64, at time.Time) (int16, error) {
	var epoch int16
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewUpdate().Model((*model.User)(nil)).
			Where("id = ?", id).
			Set("username = ?", fmt.Sprintf("deleted_%d", id)).
			Set("phone = ?", nil).
			Set("email = ?", nil).
			Set("phone_verified = ?", 0).
			Set("email_verified = ?", 0).
			Set("nickname = ?", "").
			Set("avatar_url = ?", "").
			Set("user_status = ?", 0).
			Set("mfa_required = ?", 0).
			Set(epochBumpSet).
			Set("updated_at = ?", at).
			Exec(ctx)
		if err != nil {
			return err
		}
		// epoch 递增必产生变更，rows=0 即行不存在（changed-rows 语义）。
		if err := requireChangedRow(ctx, tx, res, (*model.User)(nil), "", "id = ?", id); err != nil {
			return err
		}
		if err := tx.NewSelect().Model((*model.User)(nil)).
			ColumnExpr("epoch").
			Where("id = ?", id).
			Scan(ctx, &epoch); err != nil {
			return err
		}
		if _, err := tx.NewUpdate().Model((*model.UserProfile)(nil)).
			Where("user_id = ?", id).
			Set("gender = ?", 0).
			Set("birthday = ?", nil).
			Set("locale = ?", "").
			Set("timezone = ?", "").
			Set("extra = ?", nil).
			Set("updated_at = ?", at).
			Exec(ctx); err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*model.UserCredential)(nil)).
			Where("user_id = ?", id).
			Exec(ctx); err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*model.UserCredentialWebauthn)(nil)).
			Where("user_id = ?", id).
			Exec(ctx); err != nil {
			return err
		}
		_, err = tx.NewDelete().Model((*model.UserThirdpartyBind)(nil)).
			Where("user_id = ?", id).
			Exec(ctx)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("user repo: anonymize user: %w", err)
	}
	return epoch, nil
}

// isUserDuplicateKey 判唯一键冲突（MariaDB 1062 / PG 23505），判定归同包
// 语义化 helper IsDuplicateKey，命中后归一为 ErrUserDuplicate；webauthn
// 侧判别复用本函数。
func isUserDuplicateKey(err error) bool {
	return IsDuplicateKey(err)
}
