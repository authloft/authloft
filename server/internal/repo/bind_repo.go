// user_thirdparty_bind 表读写（后端架构 §3.9 行 415 / §4.3 / §12）。
// DDL 归 migrations/（§3.16），本文件只做行级读写与文档明确的查询
// 最小集；事务边界在 service（§3.9）。(provider_key, open_id) 判重后的
// 分支（已绑本人幂等 / 已绑他人 target_taken，§12.5 步骤 4）与 Union
// 归并联动（§12.7 解除任一 Provider 同步解绑 Union Provider）归
// service/thirdparty.go（§3.9 行 406），repo 只提供查询原语。extra 列
// 只透传字节不解析（§4.3 行 708：仅排查用、不参与任何业务判定，msgpack
// 编解码与超 1 MiB 整条丢弃降级归上层）；Union Provider 行是否展示 /
// 计入已绑定数归 service（接口文档 §3.7）。
package repo

import (
	"context"
	"errors"
	"fmt"

	mysqldriver "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"

	"authloft/internal/repo/model"
)

// ErrBindDuplicate Create 命中唯一键 uk_provider_openid（§4.3 行 702）
// 时的可判别错误——同一 (provider_key, open_id) 已绑其他用户（§12.5
// 步骤 4「已绑其他 uid」的判重依据）；冲突键与值在底层
// *mysql.MySQLError 中。
var ErrBindDuplicate = errors.New("bind repo: duplicate unique key")

// ErrBindNotOwned Unbind 时行存在但 user_id 与操作者不符（归属校验
// 失败——解绑只能解自己的，接口文档 §3.7）。
var ErrBindNotOwned = errors.New("bind repo: row not owned by user")

// BindRepo user_thirdparty_bind 表数据访问（§3.9：表与文件对应
// bind → bind_repo.go）。
type BindRepo struct {
	db *gorm.DB
}

// NewBindRepo 按 GORM 连接构造。
func NewBindRepo(db *gorm.DB) *BindRepo {
	return &BindRepo{db: db}
}

// FindByProviderOpenID 按唯一键 uk_provider_openid 取绑定行（§12.5
// 步骤 4 登录 / 绑定链路的判重查询）；未命中返回包装的
// gorm.ErrRecordNotFound。
func (r *BindRepo) FindByProviderOpenID(ctx context.Context, providerKey, openID string) (*model.UserThirdpartyBind, error) {
	var b model.UserThirdpartyBind
	err := r.db.WithContext(ctx).
		Where("provider_key = ? AND open_id = ?", providerKey, openID).
		Take(&b).Error
	if err != nil {
		return nil, fmt.Errorf("bind repo: find by provider openid: %w", err)
	}
	return &b, nil
}

// ListByUserID 按用户取全部绑定行（idx_user；接口文档 §3.7 绑定列表
// 的数据来源）。Union Provider 行是否展示 / 计数归 service。
func (r *BindRepo) ListByUserID(ctx context.Context, userID int64) ([]model.UserThirdpartyBind, error) {
	var rows []model.UserThirdpartyBind
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("id ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("bind repo: list by user: %w", err)
	}
	return rows, nil
}

// Create 插入绑定行；命中 uk_provider_openid（open_id 已绑他人）返回
// ErrBindDuplicate（errors.Is 可判别），其余错误原样包装。
func (r *BindRepo) Create(ctx context.Context, b *model.UserThirdpartyBind) error {
	err := r.db.WithContext(ctx).Create(b).Error
	if err != nil {
		if isBindDuplicateKey(err) {
			return fmt.Errorf("bind repo: create: %w: %w", ErrBindDuplicate, err)
		}
		return fmt.Errorf("bind repo: create: %w", err)
	}
	return nil
}

// Unbind 按 id 删除且校验归属（id + user_id 双条件，防用户 A 解绑用户
// B 的绑定行）：DELETE 的 rows=0 时行不存在与归属不符不可区分，补
// SELECT by id 判别——行存在则 ErrBindNotOwned，不存在则包装的
// gorm.ErrRecordNotFound。
func (r *BindRepo) Unbind(ctx context.Context, id, userID int64) error {
	res := r.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", id, userID).
		Delete(&model.UserThirdpartyBind{})
	if res.Error != nil {
		return fmt.Errorf("bind repo: unbind: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var b model.UserThirdpartyBind
		err := r.db.WithContext(ctx).
			Where("id = ?", id).
			Take(&b).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("bind repo: unbind: %w", gorm.ErrRecordNotFound)
		}
		if err != nil {
			return fmt.Errorf("bind repo: unbind: %w", err)
		}
		return fmt.Errorf("bind repo: unbind: id=%d owned by user_id=%d, not %d: %w", id, b.UserID, userID, ErrBindNotOwned)
	}
	return nil
}

// isBindDuplicateKey 判 MySQL/MariaDB 1062（duplicate entry）唯一键冲突。
func isBindDuplicateKey(err error) bool {
	var me *mysqldriver.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}
