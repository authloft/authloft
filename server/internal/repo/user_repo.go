// user / user_profile 表读写（后端架构 §3.9 行 415 / §4.2）。DDL 归
// migrations/（§3.16），本文件只做行级读写与文档明确的查询最小集；
// 事务边界在 service（§3.9）。掩码（接口文档 §3.1）、extra 的 msgpack
// 编解码、al:pwdep 缓存同步（§5.1）均归上层——repo 层拿到什么存什么。
package repo

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"authloft/internal/repo/model"
)

// ErrUserDuplicate Create 命中唯一键（uk_username / uk_phone / uk_email
// 之一，§4.2 行 635-637）时的可判别错误；具体冲突键与值在底层
// *mysql.MySQLError 中。
var ErrUserDuplicate = errors.New("user repo: duplicate unique key")

// UserRepo user / user_profile 表数据访问（§3.9：表与文件对应
// user(+user_profile) → user_repo.go）。
type UserRepo struct {
	db *gorm.DB
}

// NewUserRepo 按 GORM 连接构造。
func NewUserRepo(db *gorm.DB) *UserRepo {
	return &UserRepo{db: db}
}

// FindByID 按主键取用户；未命中返回包装的 gorm.ErrRecordNotFound。
func (r *UserRepo) FindByID(ctx context.Context, id int64) (*model.User, error) {
	var u model.User
	if err := r.db.WithContext(ctx).Take(&u, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("user repo: find by id: %w", err)
	}
	return &u, nil
}

// FindByUsername 按唯一键 uk_username 取用户；未命中返回包装的
// gorm.ErrRecordNotFound。
func (r *UserRepo) FindByUsername(ctx context.Context, username string) (*model.User, error) {
	var u model.User
	if err := r.db.WithContext(ctx).Take(&u, "username = ?", username).Error; err != nil {
		return nil, fmt.Errorf("user repo: find by username: %w", err)
	}
	return &u, nil
}

// FindByPhone 按唯一键 uk_phone 取用户；未命中返回包装的
// gorm.ErrRecordNotFound。
func (r *UserRepo) FindByPhone(ctx context.Context, phone string) (*model.User, error) {
	var u model.User
	if err := r.db.WithContext(ctx).Take(&u, "phone = ?", phone).Error; err != nil {
		return nil, fmt.Errorf("user repo: find by phone: %w", err)
	}
	return &u, nil
}

// FindByEmail 按唯一键 uk_email 取用户；未命中返回包装的
// gorm.ErrRecordNotFound。
func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	var u model.User
	if err := r.db.WithContext(ctx).Take(&u, "email = ?", email).Error; err != nil {
		return nil, fmt.Errorf("user repo: find by email: %w", err)
	}
	return &u, nil
}

// Create 插入用户；命中唯一键（username / phone / email）返回
// ErrUserDuplicate（errors.Is 可判别），其余错误原样包装。
func (r *UserRepo) Create(ctx context.Context, u *model.User) error {
	err := r.db.WithContext(ctx).Create(u).Error
	if err != nil {
		if isUserDuplicateKey(err) {
			return fmt.Errorf("user repo: create: %w: %w", ErrUserDuplicate, err)
		}
		return fmt.Errorf("user repo: create: %w", err)
	}
	return nil
}

// CreateWithCredential 建号写入在同一事务内完成（后端架构 §7.4 行 1025）：
// 单 gorm Transaction 内先 INSERT user、再 INSERT user_credential（c.UserID
// 由 user INSERT 回填的自增 ID 关联后写入），任一失败整体回滚——两跳非同
// 事务会在 credential 失败时留下无凭证 user 行，username / email / phone
// 占位无自愈。user 表唯一键冲突（username / phone / email）仍返回
// ErrUserDuplicate（errors.Is 可判别，判别口径与错误包装同 Create）；user 表
// gorm default tag 的回填语义同 Create（user_status=1 / mfa_required=0 零值
// 被 tag 值显式写入 INSERT 并回填 struct，见 model.User 注释）。
func (r *UserRepo) CreateWithCredential(ctx context.Context, u *model.User, c *model.UserCredential) error {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(u).Error; err != nil {
			return err
		}
		c.UserID = u.ID
		return tx.Create(c).Error
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
// 用户不存在返回包装的 gorm.ErrRecordNotFound。
func (r *UserRepo) GetEpoch(ctx context.Context, id int64) (int16, error) {
	var u model.User
	err := r.db.WithContext(ctx).
		Select("id", "epoch").
		Where("id = ?", id).
		Take(&u).Error
	if err != nil {
		return 0, fmt.Errorf("user repo: get epoch: %w", err)
	}
	return u.Epoch, nil
}

// IncEpoch 递增 epoch 并返回递增后的新值（供上层同步 al:pwdep:{uid}
// 缓存，§5.1 行 850）：递增结果 > 30000 时回绕为 1、跳过 0（0 是初始
// 值，回绕到 0 会让回绕前签发、仍在有效期内的旧令牌重新匹配通过，
// 等于复活全部旧令牌；§4.2 行 685）。递增与回绕在同一条 UPDATE 语句
// 内原子完成。用户不存在返回包装的 gorm.ErrRecordNotFound。
func (r *UserRepo) IncEpoch(ctx context.Context, id int64) (int16, error) {
	var epoch int16
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.User{}).
			Where("id = ?", id).
			Update("epoch", gorm.Expr("IF(epoch + 1 > 30000, 1, epoch + 1)"))
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return tx.Model(&model.User{}).
			Select("epoch").
			Where("id = ?", id).
			Scan(&epoch).Error
	})
	if err != nil {
		return 0, fmt.Errorf("user repo: inc epoch: %w", err)
	}
	return epoch, nil
}

// UpdateLastLogin 更新 last_login_at（§5.2 延迟写入队列 worker 消费；
// 「同 user_id 合并、只保留最新时间」归队列合并策略，repo 只写一行）。
// 用户不存在返回包装的 gorm.ErrRecordNotFound。MySQL 驱动默认
// changed-rows 语义：同值 UPDATE（§5.2 队列幂等重放）RowsAffected=0
// 与行不存在不可区分，故 rows=0 时补 SELECT 存在性判定——行仍在则视
// 为幂等成功，查无此行才报 ErrRecordNotFound。
func (r *UserRepo) UpdateLastLogin(ctx context.Context, id int64, at time.Time) error {
	res := r.db.WithContext(ctx).
		Model(&model.User{}).
		Where("id = ?", id).
		Update("last_login_at", at)
	if res.Error != nil {
		return fmt.Errorf("user repo: update last login: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.User{}).
			Select("COUNT(*)").
			Where("id = ?", id).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("user repo: update last login: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("user repo: update last login: %w", gorm.ErrRecordNotFound)
		}
	}
	return nil
}

// UpdateProfileColumns 列级更新 user 表资料列 nickname / avatar_url
//（接口文档 §3.2 UpdateProfile：可选字段部分更新——用户名 / 手机号 /
// 邮箱不可改、未传字段不覆盖，§3.10 行 428 表-文件对应归 user_repo）。
// nil = 该列未传、不写入；updated_at 一并刷新。用户不存在返回包装的
// gorm.ErrRecordNotFound。MySQL 驱动默认 changed-rows 语义：同值 UPDATE
// RowsAffected=0 与行不存在不可区分，故 rows=0 时补 SELECT 存在性判定
//——行仍在则视为幂等成功，查无此行才报 ErrRecordNotFound（口径同
// UpdateLastLogin）。
func (r *UserRepo) UpdateProfileColumns(ctx context.Context, id int64, nickname, avatarURL *string) error {
	cols := map[string]any{"updated_at": time.Now()}
	if nickname != nil {
		cols["nickname"] = *nickname
	}
	if avatarURL != nil {
		cols["avatar_url"] = *avatarURL
	}
	res := r.db.WithContext(ctx).
		Model(&model.User{}).
		Where("id = ?", id).
		Updates(cols)
	if res.Error != nil {
		return fmt.Errorf("user repo: update profile columns: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.User{}).
			Select("COUNT(*)").
			Where("id = ?", id).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("user repo: update profile columns: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("user repo: update profile columns: %w", gorm.ErrRecordNotFound)
		}
	}
	return nil
}

// UserListQuery ListUsers 入参：UserStatus 为 nil 时不过滤（§5.4
// ListUsers 筛选入参 {q, userStatus}）；Q 非空时对 username / nickname /
// email / phone 四列做模糊匹配（默认口径：LIKE %q%，LIKE 通配
// 符 %/_/\ 按 \ 转义保证字面匹配，待定）；分页按 §1.7（page 从
// 1 开始、pageSize 默认 20、上限 100）。Sort / Order 取值由前端限定
//（§1.7 后端不做白名单强制校验）——repo 只做字符集防注入（非
// [a-z0-9_] 列名静默回落 id，order 非 asc 一律 desc），不拒绝请求。
type UserListQuery struct {
	UserStatus *int8
	Q          string
	Sort       string
	Order      string
	Page       int
	PageSize   int
}

// userSortColumnPattern 排序列名字符集（小写字母 / 数字 / 下划线——user
// 表列名均在该集合内；字符集校验是防 ORDER BY 注入的格式约束，不是取值
// 白名单：§1.7 行 277 后端不做白名单强制校验）。
var userSortColumnPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// userDefaultSortColumn 默认排序列（缺省 / 非法 sort 的回落值）。
const userDefaultSortColumn = "id"

// escapeLike 转义 LIKE 通配符（%/_）与转义符本身（\），保证 Q 按字面子串
// 匹配；MySQL/MariaDB LIKE 默认转义符即 \。
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// ListUsers 分页列表：返回当页行与过滤后总数（§1.7 响应
// {items, total, page, pageSize} 的数据来源）。
func (r *UserRepo) ListUsers(ctx context.Context, q UserListQuery) ([]model.User, int64, error) {
	page, size := q.normalize()
	filter := func() *gorm.DB {
		tx := r.db.WithContext(ctx).Model(&model.User{})
		if q.UserStatus != nil {
			tx = tx.Where("user_status = ?", *q.UserStatus)
		}
		if q.Q != "" {
			like := "%" + escapeLike(q.Q) + "%"
			tx = tx.Where(
				"username LIKE ? OR nickname LIKE ? OR email LIKE ? OR phone LIKE ?",
				like, like, like, like,
			)
		}
		return tx
	}
	var total int64
	if err := filter().Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("user repo: list count: %w", err)
	}
	var rows []model.User
	err := filter().
		Order(q.orderClause()).
		Limit(size).
		Offset((page - 1) * size).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("user repo: list: %w", err)
	}
	return rows, total, nil
}

// orderClause 排序子句：sort 缺省 / 字符集外回落 id，order 仅 asc / desc
//（大小写不敏感，其余含缺省一律 desc——与既有固定排序的方向一致）；
// 非 id 主序恒追加 id 次序保证分页全序稳定（同值行跨页不漂移，口径同
// webauthn_repo.ListByUser）。
func (q UserListQuery) orderClause() string {
	col := q.Sort
	if col == "" || !userSortColumnPattern.MatchString(col) {
		col = userDefaultSortColumn
	}
	dir := "DESC"
	if strings.EqualFold(q.Order, "asc") {
		dir = "ASC"
	}
	if col == userDefaultSortColumn {
		return col + " " + dir
	}
	return "`" + col + "` " + dir + ", id DESC"
}

// UpdateUserStatus 列级更新 user_status（§5.4 行 1248 禁用 / 启用——禁用
// 入口是列级 UPDATE，不受 Create 的 default:1 tag 影响，见 model.User 注释；
// 启用态同构）。updated_at 一并刷新。用户不存在返回包装的
// gorm.ErrRecordNotFound；同值重放幂等成功（changed-rows 语义下 rows=0
// 补 SELECT 存在性判定，口径同 UpdateProfileColumns）。
func (r *UserRepo) UpdateUserStatus(ctx context.Context, id int64, userStatus int8) error {
	res := r.db.WithContext(ctx).
		Model(&model.User{}).
		Where("id = ?", id).
		Updates(map[string]any{"user_status": userStatus, "updated_at": time.Now()})
	if res.Error != nil {
		return fmt.Errorf("user repo: update user status: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.User{}).
			Select("COUNT(*)").
			Where("id = ?", id).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("user repo: update user status: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("user repo: update user status: %w", gorm.ErrRecordNotFound)
		}
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

// GetProfile 取 user_profile 行（§3.1 profile 字段的数据来源）；
// 未命中返回包装的 gorm.ErrRecordNotFound。
func (r *UserRepo) GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error) {
	var p model.UserProfile
	if err := r.db.WithContext(ctx).Take(&p, "user_id = ?", userID).Error; err != nil {
		return nil, fmt.Errorf("user repo: get profile: %w", err)
	}
	return &p, nil
}

// SaveProfile 整行 UPSERT user_profile（主键 user_id，ON DUPLICATE KEY
// UPDATE 全列覆盖）。接口文档 §3.2 UpdateProfile 的可选字段部分更新
// 语义归 service（先读后拼整行）；extra 为 msgpack 字节，编解码归上层。
func (r *UserRepo) SaveProfile(ctx context.Context, p *model.UserProfile) error {
	err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"gender", "birthday", "locale", "timezone", "extra", "updated_at",
		}),
	}).Create(p).Error
	if err != nil {
		return fmt.Errorf("user repo: save profile: %w", err)
	}
	return nil
}

// isUserDuplicateKey 判 MySQL/MariaDB 1062（duplicate entry）唯一键冲突。
func isUserDuplicateKey(err error) bool {
	var me *mysqldriver.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}
