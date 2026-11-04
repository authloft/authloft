// 自绘图形码的一次性存取（docs/后端架构.md §3.10 行 419、§9.2 行 1088）：
// 生成侧 SET al:cap:{id} {answer} EX 300；校验侧 Lua 原子 GET+DEL 再比对
// （正确 / 错误都消费，一次性语义与第三方 token 一致，接口文档 §2.5 行 519）。
// 图形码生成 / 绘制算法不在本文件（NON-GOALS，归 captcha/ 包与后续实现）。
// Redis 客户端经构造注入（叶子件，不 import config / repo，同 code.go 口径）。
package cache

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:embed lua/verify_captcha.lua
var verifyCaptchaScript string

// captchaTTL 自绘图形码有效期（§5.1 行 841：300s；接口文档 §2.5 行 494
// expiresIn=300）。
const captchaTTL = 300 * time.Second

// captchaRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入 fake，不暴露整个 Cmdable，同 codeRedis 口径）。
type captchaRedis interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

// CaptchaStore 自绘图形码唯一存储与校验实现。
type CaptchaStore struct {
	rdb captchaRedis
}

// NewCaptchaStore 构造图形码存储。rdb 为已连通的 go-redis 客户端。
func NewCaptchaStore(rdb captchaRedis) *CaptchaStore {
	return &CaptchaStore{rdb: rdb}
}

// Set 生成侧写入 al:cap:{id} = answer，TTL 300s（§5.1 行 841）。
// 生成算法 / 幂等由调用方负责（本方法只落库）。
func (s *CaptchaStore) Set(ctx context.Context, id, answer string) error {
	if err := s.rdb.Set(ctx, CaptchaKey(id), answer, captchaTTL).Err(); err != nil {
		return fmt.Errorf("cache: set captcha: %w", err)
	}
	return nil
}

// Verify 校验 id + answer：Lua 原子 GET+DEL，键在比对前删除——正确与错误
// 都消费（一次性，接口文档 §2.5 行 519）。返回 false 表示答案错误、id
// 缺失、已消费或已过期；仅 Redis 故障返回 error（供上层映射 internal_error）。
func (s *CaptchaStore) Verify(ctx context.Context, id, answer string) (bool, error) {
	n, err := s.rdb.Eval(ctx, verifyCaptchaScript, []string{CaptchaKey(id)}, answer).Int64()
	if err != nil {
		return false, fmt.Errorf("cache: verify captcha eval: %w", err)
	}
	return n == 1, nil
}
