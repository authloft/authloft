// Store：本地缓存快照 + 预热 + 写入口径（后端架构 §3.12 / §4.7 行 836-837）。
// 快照为 copy-on-write（atomic.Pointer 换整个 map）：读路径无锁，
// 写路径（Set / 预热 / 重载）整体替换，35 键的 map 复制成本可忽略。
package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"authloft/internal/cache"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// Store 系统配置内存快照。生命周期：NewStore（种子默认值）→ Preload
// （全量预热 + 缺失补齐，bootstrap fail-fast）→ 服务期 Get* 只读 / Set 写。
type Store struct {
	rp  *repo.SettingsRepo
	rdb *redis.Client
	cur atomic.Pointer[map[string]any]
}

// NewStore 构造 Store：初始快照 = 全量默认值（Preload 失败时进程不会进入
// 服务期，此种子值仅为未预热先读的兜底，与 §5.6 setup 无表口径一致）。
func NewStore(rp *repo.SettingsRepo, rdb *redis.Client) *Store {
	s := &Store{rp: rp, rdb: rdb}
	def := Defaults()
	s.cur.Store(&def)
	return s
}

// Preload 启动全量预热（§4.7 行 836）：全量读入内存 → 缺失键按默认值
// 补齐并写回（InsertIgnore，幂等）→ 快照就绪。库中存在但 JSON 损坏 /
// 类型不符的行直接报错（fail-fast：配置表被外写破坏应尽早暴露，不静默
// 回落默认值）。白名单外的存量行不进快照也不删除（写入侧已拒绝，
// 读侧不做破坏性动作）。
func (s *Store) Preload(ctx context.Context) error {
	rows, err := s.rp.LoadAll(ctx)
	if err != nil {
		return fmt.Errorf("settings: preload: %w", err)
	}
	snap, missingRows, err := loadSnapshot(rows)
	if err != nil {
		return fmt.Errorf("settings: preload: %w", err)
	}
	if len(missingRows) > 0 {
		if err := s.rp.InsertIgnoreAll(ctx, missingRows); err != nil {
			return fmt.Errorf("settings: preload: %w", err)
		}
	}
	s.cur.Store(&snap)
	return nil
}

// reload 热更新重载（watcher 收到 al:settings:chg 后调用；包内私有）：
// 全量重读并整体换快照。与 Preload 的差异：缺失键只在内存按默认值兜底、
// **不写回**——避免多实例同时收到通知时对同一缺失键反复补齐写库
// （补齐是启动预热的职责，行被外部删除的窗口由下次重启闭环）。
func (s *Store) reload(ctx context.Context) error {
	rows, err := s.rp.LoadAll(ctx)
	if err != nil {
		return fmt.Errorf("settings: reload: %w", err)
	}
	snap, _, err := loadSnapshot(rows)
	if err != nil {
		return fmt.Errorf("settings: reload: %w", err)
	}
	s.cur.Store(&snap)
	return nil
}

// loadSnapshot 由表行构造快照（缺失键按默认值填入快照）。返回：完整
// 快照、缺失键补齐行（Preload 写回用；reload 不写）。
func loadSnapshot(rows []model.Setting) (map[string]any, []model.Setting, error) {
	snap := make(map[string]any, len(defs))
	present := make(map[string]struct{}, len(defs))
	for _, r := range rows {
		if _, ok := byKey[r.K]; !ok {
			continue // 白名单外存量行：不进快照、不报错、不删除
		}
		v, err := DecodeValue(r.K, r.V)
		if err != nil {
			return nil, nil, err
		}
		snap[r.K] = v
		present[r.K] = struct{}{}
	}
	now := time.Now()
	var missingRows []model.Setting
	for _, d := range defs {
		if _, ok := present[d.Key]; !ok {
			raw, err := EncodeValue(d.Default)
			if err != nil {
				return nil, nil, err
			}
			missingRows = append(missingRows, model.Setting{
				K: d.Key, V: raw, UpdatedAt: now, UpdatedBy: 0,
			})
			snap[d.Key] = cloneValue(d.Default)
		}
	}
	return snap, missingRows, nil
}

// Get 读单键当前值；第二返回值 false = 键不在白名单（不会发生类型不符
// ——快照值均经注册类型解码）。[]string 为副本，调用方可安全修改。
func (s *Store) Get(key string) (any, bool) {
	m := *s.cur.Load()
	v, ok := m[key]
	return cloneValue(v), ok
}

// Snapshot 读全量快照副本（admin GET /settings 用）。
func (s *Store) Snapshot() map[string]any {
	m := *s.cur.Load()
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

// GetString / GetInt64 / GetBool / GetStringSlice 类型化读：键不存在或
// 内部类型不符（不应发生）时返回零值 + false。
func (s *Store) GetString(key string) (string, bool) {
	v, ok := s.Get(key)
	sv, ok2 := v.(string)
	return sv, ok && ok2
}

func (s *Store) GetInt64(key string) (int64, bool) {
	v, ok := s.Get(key)
	iv, ok2 := v.(int64)
	return iv, ok && ok2
}

func (s *Store) GetBool(key string) (bool, bool) {
	v, ok := s.Get(key)
	bv, ok2 := v.(bool)
	return bv, ok && ok2
}

func (s *Store) GetStringSlice(key string) ([]string, bool) {
	v, ok := s.Get(key)
	sv, ok2 := v.([]string)
	return sv, ok && ok2
}

// Set 写入单个配置（SetMany 的单键封装）。
func (s *Store) Set(ctx context.Context, key string, value any, updatedBy int64) error {
	return s.SetMany(ctx, map[string]any{key: value}, updatedBy)
}

// SetMany 写入路径（§4.7 行 837 / §15.3 行 1684）：全部键先过白名单 +
// 值类型校验（任一不过则整批拒绝，不产生半截写入）→ 单事务 UPSERT →
// 刷新本实例内存（写方立即生效）→ PUBLISH al:settings:chg 通知其余
// 实例（payload = 排序后的变更键 JSON 数组，仅作排障参考；订阅方一律
// 全量重载，不解析语义）。PUBLISH 失败时数据已落库，返回错误由调用方
// 决定重试 / 记日志——各实例在下一次变更通知或重启时收敛。
func (s *Store) SetMany(ctx context.Context, kv map[string]any, updatedBy int64) error {
	if len(kv) == 0 {
		return nil
	}
	normalized := make(map[string]any, len(kv))
	rows := make([]model.Setting, 0, len(kv))
	now := time.Now()
	for k, v := range kv {
		nv, err := Validate(k, v)
		if err != nil {
			return err
		}
		raw, err := EncodeValue(nv)
		if err != nil {
			return err
		}
		normalized[k] = nv
		rows = append(rows, model.Setting{K: k, V: raw, UpdatedAt: now, UpdatedBy: updatedBy})
	}
	if err := s.rp.UpsertAll(ctx, rows); err != nil {
		return fmt.Errorf("settings: set: %w", err)
	}
	s.apply(normalized)
	return s.rdb.Publish(ctx, cache.SettingsChgKey(), changedKeys(kv)).Err()
}

// apply 把已落库的值合并进本实例快照（CAS 循环应对并发 reload）。
func (s *Store) apply(kv map[string]any) {
	for {
		old := s.cur.Load()
		next := make(map[string]any, len(*old)+len(kv))
		for k, v := range *old {
			next[k] = v
		}
		for k, v := range kv {
			next[k] = v
		}
		if s.cur.CompareAndSwap(old, &next) {
			return
		}
	}
}

// changedKeys 取排序后的变更键列表作 PUBLISH payload（JSON 数组，
// 单键形如 ["pwd_min_length"]）。订阅方不解析，仅供 redis-cli 排障。
func changedKeys(kv map[string]any) string {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b, err := json.Marshal(keys)
	if err != nil {
		return "" // []string 序列化不会失败；兜底空 payload 不影响订阅方全量重载
	}
	return string(b)
}
