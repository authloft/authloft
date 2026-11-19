// user_thirdparty_bind 表读写（后端架构 §3.9 / §4.3 / §12）。DDL 归
// migrations/（§3.16），本文件只做行级读写与文档明确的查询最小集；跨聚合
// 业务事务在 service（§3.9），聚合内原子写归 repo 单事务（§3.10 既定口径）。
// (provider_key, open_id) 判重后的分支（已绑本人幂等 / 已绑他人
// target_taken，§12.5 步骤 4）与绑定侧 Union 归并联动归
// service/thirdparty.go（§3.9）；解绑侧 Union 连带删除现收编为
// UnbindWithUnionCascade 单事务方法（§12.7）。extra 列只透传字节不解析
// （§4.3：仅排查用、不参与任何业务判定，msgpack 编解码与超 1 MiB 整条
// 丢弃降级归上层）；Union Provider 行是否展示 / 计入已绑定数归 service
// （接口文档 §3.7）。
package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun"

	"authloft/internal/repo/model"
)

// ErrBindDuplicate Create 命中唯一键 uk_provider_openid（§4.3）时的可判别
// 错误——同一 (provider_key, open_id) 已绑其他用户（§12.5 步骤 4「已绑其他
// uid」的判重依据）；冲突键与值在底层 *mysql.MySQLError 中。
var ErrBindDuplicate = errors.New("bind repo: duplicate unique key")

// ErrBindNotOwned Unbind 时行存在但 user_id 与操作者不符（归属校验失败——
// 解绑只能解自己的，接口文档 §3.7）。
var ErrBindNotOwned = errors.New("bind repo: row not owned by user")

// providerCategoryUnion provider 表 category=union（§12.7：Union Provider
// 是虚拟 Provider 仅用于归并）；UnbindWithUnionCascade 级联判定依据。
// service/admin 与 handler/admin 各持同款私有常量（包内不共享，字面量
// 对齐 provider.go Category 列注释）。
const providerCategoryUnion = "union"

// BindRepo user_thirdparty_bind 表数据访问（§3.9：表与文件对应
// bind → bind_repo.go）。
type BindRepo struct {
	db *bun.DB
}

// NewBindRepo 按 bun 连接构造。
func NewBindRepo(db *bun.DB) *BindRepo {
	return &BindRepo{db: db}
}

// FindByProviderOpenID 按唯一键 uk_provider_openid 取绑定行（§12.5 步骤 4
// 登录 / 绑定链路的判重查询）；未命中返回包装的 sql.ErrNoRows。
func (r *BindRepo) FindByProviderOpenID(ctx context.Context, providerKey, openID string) (*model.UserThirdpartyBind, error) {
	var b model.UserThirdpartyBind
	err := r.db.NewSelect().Model(&b).
		Where("provider_key = ? AND open_id = ?", providerKey, openID).
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("bind repo: find by provider openid: %w", err)
	}
	return &b, nil
}

// ListByUserID 按用户取全部绑定行（idx_user；接口文档 §3.7 绑定列表的数据
// 来源）。Union Provider 行是否展示 / 计数归 service。
func (r *BindRepo) ListByUserID(ctx context.Context, userID int64) ([]model.UserThirdpartyBind, error) {
	var rows []model.UserThirdpartyBind
	err := r.db.NewSelect().Model(&rows).
		Where("user_id = ?", userID).
		OrderExpr("id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("bind repo: list by user: %w", err)
	}
	return rows, nil
}

// Create 插入绑定行；命中 uk_provider_openid（open_id 已绑他人）返回
// ErrBindDuplicate（errors.Is 可判别），其余错误原样包装。created_at 零值
// 时由本方法补齐（bun 无时间列自动填充）。
func (r *BindRepo) Create(ctx context.Context, b *model.UserThirdpartyBind) error {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	if _, err := r.db.NewInsert().Model(b).Exec(ctx); err != nil {
		if isBindDuplicateKey(err) {
			return fmt.Errorf("bind repo: create: %w: %w", ErrBindDuplicate, err)
		}
		return fmt.Errorf("bind repo: create: %w", err)
	}
	return nil
}

// Unbind 按 id 删除且校验归属（id + user_id 双条件，防用户 A 解绑用户 B 的
// 绑定行）：DELETE 的 rows=0 时行不存在与归属不符不可区分，补 SELECT by id
// 判别——行存在则 ErrBindNotOwned，不存在则包装的 sql.ErrNoRows。
func (r *BindRepo) Unbind(ctx context.Context, id, userID int64) error {
	res, err := r.db.NewDelete().Model((*model.UserThirdpartyBind)(nil)).
		Where("id = ? AND user_id = ?", id, userID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("bind repo: unbind: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("bind repo: unbind: %w", err)
	}
	if rows == 0 {
		var b model.UserThirdpartyBind
		err := r.db.NewSelect().Model(&b).
			Where("id = ?", id).
			Limit(1).
			Scan(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("bind repo: unbind: %w", sql.ErrNoRows)
		}
		if err != nil {
			return fmt.Errorf("bind repo: unbind: %w", err)
		}
		return fmt.Errorf("bind repo: unbind: id=%d owned by user_id=%d, not %d: %w", id, b.UserID, userID, ErrBindNotOwned)
	}
	return nil
}

// CreateWithUnion 单事务创建方向的 Union 联动写入（§12.7「首次登录 / 绑定
// 写入普通行时，若该 Provider 关联了 Union Provider 且适配器返回 unionid，
// 则同事务追加写 Union Provider + unionid 行」；既定口径 §3.10：聚合内
// 原子写归 repo 单事务，创建方向与解绑方向 UnbindWithUnionCascade 对称）：
// 单 tx 内写普通绑定行 → unionProviderKey 非空且 unionID 非空时追加写
// Union 行（open_id=unionid）。任一跳命中 uk_provider_openid（普通行或
// Union 行已绑他人）返回 ErrBindDuplicate 并整体回滚——Union 行被他人占用
// 时普通行不留库（否则孤立普通行无 Union 归并且占用唯一键）。
// unionProviderKey 为空表示无关联 Union Provider，只写普通行（语义同
// Create，供 service 单一写入口复用）。两行的 created_at 零值时由本方法
// 补齐（bun 无时间列自动填充）。
func (r *BindRepo) CreateWithUnion(ctx context.Context, b *model.UserThirdpartyBind, unionProviderKey, unionID string) error {
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if b.CreatedAt.IsZero() {
			b.CreatedAt = time.Now()
		}
		if _, err := tx.NewInsert().Model(b).Exec(ctx); err != nil {
			return err
		}
		if unionProviderKey == "" || unionID == "" {
			return nil
		}
		u := &model.UserThirdpartyBind{
			UserID:      b.UserID,
			ProviderKey: unionProviderKey,
			OpenID:      unionID,
			CreatedAt:   time.Now(),
		}
		_, err := tx.NewInsert().Model(u).Exec(ctx)
		return err
	})
	if err != nil {
		if isBindDuplicateKey(err) {
			return fmt.Errorf("bind repo: create with union: %w: %w", ErrBindDuplicate, err)
		}
		return fmt.Errorf("bind repo: create with union: %w", err)
	}
	return nil
}

// UnbindWithUnionCascade 单事务级联解绑（既定口径 §3.10：聚合内原子写归
// repo 单事务，先例 UserRepo.CreateWithCredential）：单 tx 内删普通绑定行
// （id + user_id 双条件，归属判别语义同 Unbind）→ 查该用户剩余绑定行 →
// 按 provider.category 判定已无任何非 Union 行时连带删 unionProviderKey
// 指向的该用户 Union 行（§12.7；仍有非 Union 行则保留，供其他关联
// Provider 继续归并）。unionProviderKey 为空表示无关联 Union Provider，
// 只删普通行。第二跳失败时普通行删除一并回滚——两跳非同事务时普通行已
// 删、用户重试 404 无法自愈，孤行 Union 行永久占用 uk_provider_openid，
// 本方法即为此收编。剩余行的 Union / 非 Union 判定在 tx 内查 provider 行；
// 查询失败 / 行缺失（脏数据）按非 Union 处理（保守保留 Union 行，宁可多
// 留不可误删）；Union 行不存在（并发已删）幂等收敛。行不存在 / 归属不符
// 返回包装的 sql.ErrNoRows / ErrBindNotOwned（errors.Is 可判别）。
func (r *BindRepo) UnbindWithUnionCascade(ctx context.Context, id, userID int64, unionProviderKey string) error {
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewDelete().Model((*model.UserThirdpartyBind)(nil)).
			Where("id = ? AND user_id = ?", id, userID).
			Exec(ctx)
		if err != nil {
			return err
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			var b model.UserThirdpartyBind
			err := tx.NewSelect().Model(&b).
				Where("id = ?", id).
				Limit(1).
				Scan(ctx)
			if errors.Is(err, sql.ErrNoRows) {
				return sql.ErrNoRows
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("id=%d owned by user_id=%d, not %d: %w", id, b.UserID, userID, ErrBindNotOwned)
		}
		if unionProviderKey == "" {
			return nil
		}
		var remaining []model.UserThirdpartyBind
		if err := tx.NewSelect().Model(&remaining).
			Where("user_id = ?", userID).
			Scan(ctx); err != nil {
			return err
		}
		for i := range remaining {
			if remaining[i].ProviderKey == unionProviderKey {
				continue
			}
			var p model.Provider
			err := tx.NewSelect().Model(&p).
				Where("provider_key = ?", remaining[i].ProviderKey).
				Limit(1).
				Scan(ctx)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil // 脏数据：provider 行缺失按非 Union 处理，保留 Union 行
				}
				return err
			}
			if p.Category != providerCategoryUnion {
				return nil // 仍有非 Union 绑定行 → 保留 Union 行（§12.7）
			}
		}
		_, err = tx.NewDelete().Model((*model.UserThirdpartyBind)(nil)).
			Where("user_id = ? AND provider_key = ?", userID, unionProviderKey).
			Exec(ctx)
		return err
	})
	if err != nil {
		return fmt.Errorf("bind repo: unbind with union cascade: %w", err)
	}
	return nil
}

// isBindDuplicateKey 判 MySQL/MariaDB 1062（duplicate entry）唯一键冲突。
func isBindDuplicateKey(err error) bool {
	var me *mysqldriver.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}
