// settings 表读写（后端架构 §3.10 / §4.7）。DDL 归 migrations/（§3.16），
// 本文件只做行级读写；键名白名单与值类型校验归 internal/settings（§3.12），
// JSON 编解码归调用方——repo 层拿到什么存什么。
package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/repo/model"
)

// SettingsRepo settings 表数据访问。
type SettingsRepo struct {
	db *bun.DB
}

// NewSettingsRepo 按 bun 连接构造。
func NewSettingsRepo(db *bun.DB) *SettingsRepo {
	return &SettingsRepo{db: db}
}

// LoadAll 全量读 settings 表（启动预热与热更新重载共用，§4.7）。
func (r *SettingsRepo) LoadAll(ctx context.Context) ([]model.Setting, error) {
	var rows []model.Setting
	if err := r.db.NewSelect().Model(&rows).Scan(ctx); err != nil {
		return nil, fmt.Errorf("settings repo: load all: %w", err)
	}
	return rows, nil
}

// UpsertAll 单事务批量 UPSERT（§4.7 写入口径「单事务 UPSERT」）：按主键 k
// 冲突更新 v / updated_at / updated_by。upsert 子句按方言分派（applyUpsert）：
// MySQL 生成 ON DUPLICATE KEY UPDATE v=VALUES(v)...，PostgreSQL 生成
// ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v...。
// updated_at 零值行由本方法补齐（bun 无时间列自动填充）。
// 空集短路返回，不产生空 VALUES 语句。
func (r *SettingsRepo) UpsertAll(ctx context.Context, rows []model.Setting) error {
	if len(rows) == 0 {
		return nil
	}
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		now := time.Now()
		for i := range rows {
			if rows[i].UpdatedAt.IsZero() {
				rows[i].UpdatedAt = now
			}
		}
		_, err := applyUpsert(tx.NewInsert().Model(&rows),
			[]string{"k"}, []string{"v", "updated_at", "updated_by"}).
			Exec(ctx)
		return err
	})
	if err != nil {
		return fmt.Errorf("settings repo: upsert: %w", err)
	}
	return nil
}

// InsertIgnoreAll 单事务批量「缺则插入」（INSERT IGNORE）：已存在的行不被
// 覆写。供启动预热补齐缺失键（§4.7「幂等」）：多实例并发预热时，他实例
// 刚写入的自定义值不会被本实例的默认值冲掉。updated_at 零值行由本方法
// 补齐（bun 无时间列自动填充）。
func (r *SettingsRepo) InsertIgnoreAll(ctx context.Context, rows []model.Setting) error {
	if len(rows) == 0 {
		return nil
	}
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		now := time.Now()
		for i := range rows {
			if rows[i].UpdatedAt.IsZero() {
				rows[i].UpdatedAt = now
			}
		}
		_, err := tx.NewInsert().Model(&rows).
			Ignore().
			Exec(ctx)
		return err
	})
	if err != nil {
		return fmt.Errorf("settings repo: insert ignore: %w", err)
	}
	return nil
}
