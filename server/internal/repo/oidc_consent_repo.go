// oidc_consent 表读写（后端架构 §3.10：表与文件对应 oidc_consent →
// oidc_consent_repo.go；§4.5 DDL 与读写口径）。DDL 归 migrations/（§3.16），
// 本文件只做行级读写。scopes 的解析、子集判定与并集计算归上层（§4.5：两套
// 分隔口径的解析统一收进授权参数校验工具，不散落调用点）——本层提供行锁
// 合并原语保证读-算-写原子性，合并口径由上层回调注入。
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

// OidcConsentRepo oidc_consent 表数据访问，只暴露授权口径的两个窄操作
// （§4.5）：读已授权并集、按行锁单事务合并写回。
type OidcConsentRepo struct {
	db *bun.DB
}

// NewOidcConsentRepo 按 bun 连接构造。
func NewOidcConsentRepo(db *bun.DB) *OidcConsentRepo {
	return &OidcConsentRepo{db: db}
}

// GetConsentScopes 取该用户对该客户端的已授权 scope 并集原文（空格分隔，
// §4.5）。无授权记录（从未同意，属正常稳态）返回包装的 sql.ErrNoRows，
// 由上层按空集口径参与免同意判定（§4.5：请求 scope ⊆ 已授权 scopes）。
func (r *OidcConsentRepo) GetConsentScopes(ctx context.Context, userID int64, clientID string) (string, error) {
	var row model.OidcConsent
	if err := r.db.NewSelect().Model(&row).
		Where("user_id = ? AND client_id = ?", userID, clientID).
		Limit(1).
		Scan(ctx); err != nil {
		return "", fmt.Errorf("oidc consent repo: get consent scopes: %w", err)
	}
	return row.Scopes, nil
}

// consentMergeRetryLimit 行锁合并的首插竞态重试上限（同键并发授权两三次
// 内必收敛，超限按存储故障上抛）。
const consentMergeRetryLimit = 3

// MergeConsent 行锁合并写回（§4.5 只扩不缩的落库口径）：单事务内
// SELECT … FOR UPDATE 锁 (user_id, client_id) 行读现值（无记录 = 空集）→
// merge 回调算新值 → 按 uk_user_client 冲突更新写回（命中唯一键只刷 scopes
// 与 updated_at，created_at 保持首次授权时刻；未命中整行插入）。
//
// merge 回调必须为纯函数：首插竞态（两事务同时锁到不存在的行，先后插入
// 后提交方胜出）触发 uk 冲突 / 死锁时整事务回滚重试，回调会以重读后的
// 现值再次执行；回调返回错误则整个事务回滚并原样上抛。
func (r *OidcConsentRepo) MergeConsent(ctx context.Context, userID int64, clientID string, merge func(current string) (string, error)) error {
	for attempt := 1; ; attempt++ {
		err := r.mergeConsentOnce(ctx, userID, clientID, merge)
		if err == nil {
			return nil
		}
		if attempt < consentMergeRetryLimit && (isConsentDuplicateKey(err) || isConsentDeadlock(err)) {
			continue
		}
		return fmt.Errorf("oidc consent repo: merge consent: %w", err)
	}
}

// mergeConsentOnce 单次行锁事务：FOR UPDATE 读现值 → 回调 → 冲突更新写回。
// upsert 行的 created_at / updated_at 零值时由本方法补齐（bun 无
// 时间列自动填充）：首次插入经 VALUES(created_at) 落当前时刻，冲突更新
// 不覆盖 created_at、updated_at 随行刷新。
func (r *OidcConsentRepo) mergeConsentOnce(ctx context.Context, userID int64, clientID string, merge func(current string) (string, error)) error {
	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var row model.OidcConsent
		err := tx.NewSelect().Model(&row).
			Where("user_id = ? AND client_id = ?", userID, clientID).
			Limit(1).
			For("UPDATE").
			Scan(ctx)
		current := ""
		switch {
		case err == nil:
			current = row.Scopes
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("oidc consent repo: lock consent row: %w", err)
		}
		next, err := merge(current)
		if err != nil {
			return err
		}
		now := time.Now()
		upsert := model.OidcConsent{
			UserID:    userID,
			ClientID:  clientID,
			Scopes:    next,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if _, err := tx.NewInsert().Model(&upsert).
			On("DUPLICATE KEY UPDATE scopes = VALUES(scopes), updated_at = VALUES(updated_at)").
			Exec(ctx); err != nil {
			return fmt.Errorf("oidc consent repo: upsert consent: %w", err)
		}
		return nil
	})
}

// isConsentDuplicateKey 判 MySQL/MariaDB 1062（duplicate entry）唯一键冲突。
func isConsentDuplicateKey(err error) bool {
	var me *mysqldriver.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}

// isConsentDeadlock 判 MySQL/MariaDB 1213：并发首插在行锁下的另一竞态表现
// 形态（gap 锁互斥引发死锁回滚），与 uk 冲突同属可重试。
func isConsentDeadlock(err error) bool {
	var me *mysqldriver.MySQLError
	return errors.As(err, &me) && me.Number == 1213
}
