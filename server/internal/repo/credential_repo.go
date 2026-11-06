// user_credential 表读写（后端架构 §3.9 行 415 / §4.2 行 651-663；接口
// 文档 §12.2 CredentialMeta）。DDL 归 migrations/（§3.16），本文件只做
// kind 行读写最小集；事务边界在 service（§3.9）。「一行一种凭证」（行
// 680-684：password / totp / recovery_code 各一行）由 service 先查后写
// 保证，idx_user_kind 非唯一、表上无数据库级约束；secret 只存取不校验
//（password=argon2id 串、totp=Base32 明文密钥，行 681-682，哈希与口令
// 校验归 security 层）；meta 列的 CredentialMeta Protobuf 编解码封装在
// 本文件，service 不直接拼 proto.Marshal。
package repo

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	"authloft/gen/go/credential"
	"authloft/internal/repo/model"
)

// CredentialRepo user_credential 表数据访问（§3.9：表与文件对应
// credential → credential_repo.go；webauthn 凭据的建行走
// WebauthnRepo.Create 同事务路径，单行读与启用态切换在本 repo）。
type CredentialRepo struct {
	db *gorm.DB
}

// NewCredentialRepo 按 GORM 连接构造。
func NewCredentialRepo(db *gorm.DB) *CredentialRepo {
	return &CredentialRepo{db: db}
}

// FindByUserAndKind 按 idx_user_kind（行 662）取该用户该 kind 的凭证行。
// password / totp / recovery_code 各一行（行 680-684），取「该行」的唯一
// 入口；webauthn 每凭据一行、列表走 WebauthnRepo.ListByUser，本方法命中
// 多行时取首行（表无非唯一约束下的防御口径，正常数据不会发生）。未命中
// 返回包装的 gorm.ErrRecordNotFound。
func (r *CredentialRepo) FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error) {
	var c model.UserCredential
	if err := r.db.WithContext(ctx).Take(&c, "user_id = ? AND kind = ?", userID, kind).Error; err != nil {
		return nil, fmt.Errorf("credential repo: find by user kind: %w", err)
	}
	return &c, nil
}

// ListByUser 按 idx_user_kind 取该用户全部凭证行（admin GetUser 凭证概览
// 的数据源，接口文档 §5.4 行 1247）：含全部 kind（password / totp /
// webauthn（每凭据一行）/ recovery_code / mfa_setting），id 正序保证列表
// 全序稳定（口径同 bind_repo.ListByUserID）；secret 恒在行内，由上层
// 投影裁剪绝不透出（user.proto UserCredentialSummary 注释）。空集返回
// 空切片。
func (r *CredentialRepo) ListByUser(ctx context.Context, userID int64) ([]model.UserCredential, error) {
	var rows []model.UserCredential
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("id ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("credential repo: list by user: %w", err)
	}
	return rows, nil
}

// Create 插入凭证行（kind / secret 拿到什么存什么，repo 不做白名单与
// 口令校验；webauthn 凭据行不经此方法，走 WebauthnRepo.Create 同事务
// 建两行）。
func (r *CredentialRepo) Create(ctx context.Context, c *model.UserCredential) error {
	if err := r.db.WithContext(ctx).Create(c).Error; err != nil {
		return fmt.Errorf("credential repo: create: %w", err)
	}
	return nil
}

// Update 按主键整行更新可变列（行 681 改密 = UPDATE 这一行；行 684
// 恢复码消费一个 = 更新该行 meta）：secret / label / meta / is_enabled /
// updated_at。id / user_id / kind / created_at 不在更新集（行 680-684
// 的归属口径：一行一种凭证，不可改迁移归属）。id 未命中返回包装的
// gorm.ErrRecordNotFound；同值重放（MySQL changed-rows 语义下
// RowsAffected=0 但行仍在）幂等成功——rows=0 时补 SELECT 存在性判定，
// 口径同 user_repo.UpdateLastLogin。updated_at 由调用方显式传入。
func (r *CredentialRepo) Update(ctx context.Context, c *model.UserCredential) error {
	res := r.db.WithContext(ctx).
		Model(&model.UserCredential{}).
		Where("id = ?", c.ID).
		Updates(map[string]interface{}{
			"secret":     c.Secret,
			"label":      c.Label,
			"meta":       c.Meta,
			"is_enabled": c.IsEnabled,
			"updated_at": c.UpdatedAt,
		})
	if res.Error != nil {
		return fmt.Errorf("credential repo: update: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.UserCredential{}).
			Select("COUNT(*)").
			Where("id = ?", c.ID).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("credential repo: update: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("credential repo: update: %w", gorm.ErrRecordNotFound)
		}
	}
	return nil
}

// SetEnabled 切换启用态（is_enabled 1/0，行 658；mfa_setting.go 用户
// 自助停用 / 管理接口共用）。行不存在返回包装的 gorm.ErrRecordNotFound；
// 同值切换幂等成功（changed-rows 语义下 rows=0 补存在性判定，口径同
// Update / UpdateLastLogin）。
func (r *CredentialRepo) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	v := int8(0)
	if enabled {
		v = 1
	}
	res := r.db.WithContext(ctx).
		Model(&model.UserCredential{}).
		Where("id = ?", id).
		Update("is_enabled", v)
	if res.Error != nil {
		return fmt.Errorf("credential repo: set enabled: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.UserCredential{}).
			Select("COUNT(*)").
			Where("id = ?", id).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("credential repo: set enabled: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("credential repo: set enabled: %w", gorm.ErrRecordNotFound)
		}
	}
	return nil
}

// DeleteByUserAndKind 按 user_id + kind 定位删除凭证行（credential 职责
// 含增删改查，§3 行 388 / 行 704；调用方：SetMfa 关闭 = 删除 mfa_setting
// 行，接口文档 §3.2 行 862「行存在即顶层 enabled=true」⇒ 关闭 ⇔ 行不存在，
// 既定口径）。「一行一种凭证」由 service 先查后写保证
//（行 680-684，idx_user_kind 非唯一），本方法不做行数断言——多行命中
// 一并删除属脏数据防御，正常数据不发生；未命中返回包装的
// gorm.ErrRecordNotFound（幂等语义归 service 判定）。
func (r *CredentialRepo) DeleteByUserAndKind(ctx context.Context, userID int64, kind string) error {
	res := r.db.WithContext(ctx).
		Where("user_id = ? AND kind = ?", userID, kind).
		Delete(&model.UserCredential{})
	if res.Error != nil {
		return fmt.Errorf("credential repo: delete by user kind: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("credential repo: delete by user kind: %w", gorm.ErrRecordNotFound)
	}
	return nil
}

// MarshalCredentialMeta 将 CredentialMeta（接口文档 §12.2 行 1703-1717，
// 对应 user_credential.meta 列，VARBINARY Protobuf 序列化）编码为存储
// 字节。nil 输入返回 nil（「无 meta」写入 NULL 列）；编码错误原样包装。
func MarshalCredentialMeta(m *credential.CredentialMeta) ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	b, err := proto.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("credential repo: marshal meta: %w", err)
	}
	return b, nil
}

// UnmarshalCredentialMeta 从 user_credential.meta 列字节解码
// CredentialMeta；NULL / 空列返回空 meta（非 nil 指针，调用方免判空）；
// 解码错误原样包装。与 MarshalCredentialMeta 互为逆运算。
func UnmarshalCredentialMeta(b []byte) (*credential.CredentialMeta, error) {
	m := &credential.CredentialMeta{}
	if len(b) == 0 {
		return m, nil
	}
	if err := proto.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("credential repo: unmarshal meta: %w", err)
	}
	return m, nil
}
