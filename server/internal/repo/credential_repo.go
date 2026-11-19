// user_credential 表读写（后端架构 §3.9 / §4.2；接口文档 §12.2
// CredentialMeta）。DDL 归 migrations/（§3.16），本文件只做 kind 行读写
// 最小集；事务边界在 service（§3.9）。「一行一种凭证」（password / totp /
// recovery_code 各一行）由 service 先查后写保证，idx_user_kind 非唯一、
// 表上无数据库级约束；secret 只存取不校验（password=argon2id 串、
// totp=Base32 明文密钥，哈希与口令校验归 security 层）；meta 列的
// CredentialMeta Protobuf 编解码封装在本文件，service 不直接拼
// proto.Marshal。
package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
	"google.golang.org/protobuf/proto"

	"authloft/gen/go/credential"
	"authloft/internal/repo/model"
)

// CredentialRepo user_credential 表数据访问（§3.9：表与文件对应
// credential → credential_repo.go；webauthn 凭据的建行走
// WebauthnRepo.Create 同事务路径，单行读与启用态切换在本 repo）。
type CredentialRepo struct {
	db *bun.DB
}

// NewCredentialRepo 按 bun 连接构造。
func NewCredentialRepo(db *bun.DB) *CredentialRepo {
	return &CredentialRepo{db: db}
}

// FindByUserAndKind 按 idx_user_kind 取该用户该 kind 的凭证行。
// password / totp / recovery_code 各一行，取「该行」的唯一入口；webauthn
// 每凭据一行、列表走 WebauthnRepo.ListByUser，本方法命中多行时取首行
// （表无非唯一约束下的防御口径，正常数据不会发生）。未命中返回包装的
// sql.ErrNoRows。
func (r *CredentialRepo) FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error) {
	var c model.UserCredential
	if err := r.db.NewSelect().Model(&c).
		Where("user_id = ? AND kind = ?", userID, kind).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("credential repo: find by user kind: %w", err)
	}
	return &c, nil
}

// ListByUser 按 idx_user_kind 取该用户全部凭证行（admin GetUser 凭证概览
// 的数据源，接口文档 §5.4）：含全部 kind（password / totp / webauthn
// （每凭据一行）/ recovery_code），id 正序保证列表全序稳定（口径同
// bind_repo.ListByUserID）；secret 恒在行内，由上层投影裁剪绝不透出
// （user.proto UserCredentialSummary 注释）。空集返回空切片。
func (r *CredentialRepo) ListByUser(ctx context.Context, userID int64) ([]model.UserCredential, error) {
	var rows []model.UserCredential
	err := r.db.NewSelect().Model(&rows).
		Where("user_id = ?", userID).
		OrderExpr("id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("credential repo: list by user: %w", err)
	}
	return rows, nil
}

// Create 插入凭证行（kind / secret 拿到什么存什么，repo 不做白名单与口令
// 校验；webauthn 凭据行不经此方法，走 WebauthnRepo.Create 同事务建两行）。
// created_at / updated_at 零值时由本方法补齐（bun 无时间列自动
// 填充）。
func (r *CredentialRepo) Create(ctx context.Context, c *model.UserCredential) error {
	now := time.Now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	if _, err := r.db.NewInsert().Model(c).Exec(ctx); err != nil {
		return fmt.Errorf("credential repo: create: %w", err)
	}
	return nil
}

// Update 按主键整行更新可变列（改密 = UPDATE 这一行；恢复码消费一个 =
// 更新该行 meta）：secret / label / meta / is_enabled / updated_at。
// id / user_id / kind / created_at 不在更新集（一行一种凭证的归属口径：
// 不可改迁移归属）。id 未命中返回包装的 sql.ErrNoRows；同值重放（MySQL
// changed-rows 语义下 RowsAffected=0 但行仍在）幂等成功——rows=0 时补
// SELECT 存在性判定，口径同 user_repo.UpdateLastLogin。updated_at 由调用方
// 显式传入。
func (r *CredentialRepo) Update(ctx context.Context, c *model.UserCredential) error {
	res, err := r.db.NewUpdate().Model((*model.UserCredential)(nil)).
		Where("id = ?", c.ID).
		Set("secret = ?", c.Secret).
		Set("label = ?", c.Label).
		Set("meta = ?", c.Meta).
		Set("is_enabled = ?", c.IsEnabled).
		Set("updated_at = ?", c.UpdatedAt).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("credential repo: update: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.UserCredential)(nil),
		"credential repo: update", "id = ?", c.ID); err != nil {
		return err
	}
	return nil
}

// FindByID 按主键取凭证行（管理端救援操作按 credentialId 定位，接口文档
// §5.4 SetCredentialEnabled / DeleteCredential）。未命中返回包装的
// sql.ErrNoRows；归属校验（row.UserID 与目标用户比对）由 service 承担，
// 本方法不做 user 维度过滤。
func (r *CredentialRepo) FindByID(ctx context.Context, id int64) (*model.UserCredential, error) {
	var c model.UserCredential
	if err := r.db.NewSelect().Model(&c).
		Where("id = ?", id).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("credential repo: find by id: %w", err)
	}
	return &c, nil
}

// SetEnabled 切换启用态（is_enabled 1/0；管理接口共用），updated_at 一并
// 刷新。行不存在返回包装的 sql.ErrNoRows；同值切换幂等成功（changed-rows
// 语义下 rows=0 补存在性判定，口径同 Update）。
func (r *CredentialRepo) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	v := int8(0)
	if enabled {
		v = 1
	}
	res, err := r.db.NewUpdate().Model((*model.UserCredential)(nil)).
		Where("id = ?", id).
		Set("is_enabled = ?", v).
		Set("updated_at = ?", time.Now()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("credential repo: set enabled: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.UserCredential)(nil),
		"credential repo: set enabled", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// DeleteByUserAndKind 按 user_id + kind 定位删除凭证行（credential 职责
// 含增删改查；调用方：UnbindTotp = 删除 kind=totp / recovery_code 行）。
// 「一行一种凭证」由 service 先查后写保证（idx_user_kind 非唯一），本方法
// 不做行数断言——多行命中一并删除属脏数据防御，正常数据不发生；未命中
// 返回包装的 sql.ErrNoRows（幂等语义归 service 判定）。
func (r *CredentialRepo) DeleteByUserAndKind(ctx context.Context, userID int64, kind string) error {
	res, err := r.db.NewDelete().Model((*model.UserCredential)(nil)).
		Where("user_id = ? AND kind = ?", userID, kind).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("credential repo: delete by user kind: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.UserCredential)(nil),
		"credential repo: delete by user kind", "user_id = ? AND kind = ?", userID, kind); err != nil {
		return err
	}
	return nil
}

// DeleteByID 按 id + user_id 定位删除单条凭证行（管理端救援删除，接口文档
// §5.4 DeleteCredential「删除单条凭证（含 WebAuthn 附加行）」）。单事务内
// 先删 user_credential 行（定位失败 = 不存在或归属不符，两者同包装
// sql.ErrNoRows 不区分，避免泄露归属），再删 user_credential_webauthn 同 id
// 附加行——webauthn 行与凭证行主键同值（§4.2），非 webauthn kind 无同值
// 附加行、删除零命中属正常，故附加行不作存在性断言（WebauthnRepo.Delete
// 反向口径：该路径附加行为准、两行齐备才删）。任一步失败整体回滚。
func (r *CredentialRepo) DeleteByID(ctx context.Context, userID, id int64) error {
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewDelete().Model((*model.UserCredential)(nil)).
			Where("id = ? AND user_id = ?", id, userID).
			Exec(ctx)
		if err != nil {
			return err
		}
		if err := requireChangedRow(ctx, tx, res, (*model.UserCredential)(nil),
			"", "id = ? AND user_id = ?", id, userID); err != nil {
			return err
		}
		_, err = tx.NewDelete().Model((*model.UserCredentialWebauthn)(nil)).
			Where("id = ? AND user_id = ?", id, userID).
			Exec(ctx)
		return err
	})
	if err != nil {
		return fmt.Errorf("credential repo: delete by id: %w", err)
	}
	return nil
}

// MarshalCredentialMeta 将 CredentialMeta（接口文档 §12.2，对应
// user_credential.meta 列，VARBINARY Protobuf 序列化）编码为存储字节。
// nil 输入返回 nil（「无 meta」写入 NULL 列）；编码错误原样包装。
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
