// settings 表读写（后端架构 §3.10 / §4.7）。DDL 归 migrations/（§3.16），
// 本文件只做行级读写；键名白名单与值类型校验归 internal/settings（§3.12），
// JSON 编解码归调用方——repo 层拿到什么存什么。
package repo

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"authloft/internal/repo/model"
)

// SettingsRepo settings 表数据访问。
type SettingsRepo struct {
	db *gorm.DB
}

// NewSettingsRepo 按 GORM 连接构造。
func NewSettingsRepo(db *gorm.DB) *SettingsRepo {
	return &SettingsRepo{db: db}
}

// LoadAll 全量读 settings 表（启动预热与热更新重载共用，§4.7 行 836）。
func (r *SettingsRepo) LoadAll(ctx context.Context) ([]model.Setting, error) {
	var rows []model.Setting
	if err := r.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("settings repo: load all: %w", err)
	}
	return rows, nil
}

// UpsertAll 单事务批量 UPSERT：MySQL 方言生成
// INSERT ... ON DUPLICATE KEY UPDATE v=VALUES(v), updated_at=...,
// updated_by=...（§4.7 行 837 写入口径「单事务 UPSERT」）。
// 空集短路返回，不产生空 VALUES 语句。
func (r *SettingsRepo) UpsertAll(ctx context.Context, rows []model.Setting) error {
	if len(rows) == 0 {
		return nil
	}
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "k"}},
			DoUpdates: clause.AssignmentColumns([]string{"v", "updated_at", "updated_by"}),
		}).Create(&rows).Error
	})
	if err != nil {
		return fmt.Errorf("settings repo: upsert: %w", err)
	}
	return nil
}

// InsertIgnoreAll 单事务批量「缺则插入」：MySQL 方言对 DoNothing 生成
// ON DUPLICATE KEY UPDATE k=k（主键自赋值 no-op），已存在的行不被覆写。
// 供启动预热补齐缺失键（§4.7 行 836「幂等」）：多实例并发预热时，
// 他实例刚写入的自定义值不会被本实例的默认值冲掉。
func (r *SettingsRepo) InsertIgnoreAll(ctx context.Context, rows []model.Setting) error {
	if len(rows) == 0 {
		return nil
	}
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
	})
	if err != nil {
		return fmt.Errorf("settings repo: insert ignore: %w", err)
	}
	return nil
}
