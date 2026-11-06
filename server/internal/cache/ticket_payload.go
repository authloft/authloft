// ticket_payload.go al:ticket:payload:{ticket_id} 快照键读写：
// docs/后端架构.md §5.1 行 863、§11.6.4 行 1350；docs/接口文档.md §2.8 行
// 719、§2.7.4 行 658）：CreateQrcode 时 1 次写入（TTL = exp − iat，与
// ticket 同寿命，默认 600s），值为 TicketPayload 整值加密快照（复用
// §11.6.1 封装、purpose=ticket）——小程序端 LoginOauth 提交通道 wire 仅
// 携带 ticket_id（微信码图 scene 上限 32 字符仅容 ticket_id，小程序端物理
// 拿不到完整加密串），服务端据此校验 scene / expiry / provider_key，
// 快照缺失即不存在 / 已过期。
//
// 键构造（TicketPayloadKey）落位本文件：可改范围为 cache/ticket.go
// 或同包新文件（未含 keys.go），故就近定义；§5.1「键的唯一出处」语义由本
// 函数单独承担，业务代码禁止裸拼字符串。
//
// 风格对齐 TicketStore：加密实现不在本包（sealer 由装配方注入，
// purpose=ticket 固定在实现内，本包不自造加密、不引 security 真密钥）；
// Redis 客户端经构造注入（叶子件，不 import config / repo）。
package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"authloft/gen/go/token"
)

// ticketPayloadKeyPrefix 快照键前缀（§5.1 行 863：al:ticket:payload:{ticket_id}）。
const ticketPayloadKeyPrefix = "al:ticket:payload:"

// TicketPayloadKey 返回快照键（§5.1 行 863，String、TTL 与 ticket 同寿命
// （= exp，默认 600s）、CreateQrcode 1 次写入）。ticket_id 与 TicketPayload.
// ticket_id 全链路同一值（§11.6.4）。
func TicketPayloadKey(ticketID string) string {
	return ticketPayloadKeyPrefix + ticketID
}

// TicketPayloadSealer TicketPayload 与存储串互转（§11.6.1 / §11.6.4：整值
// 加密，purpose=ticket 由实现内固定，本包不感知密钥与算法）。
type TicketPayloadSealer interface {
	// Seal 加密整值，返回可写入 Redis 的串。
	Seal(*token.TicketPayload) (string, error)
	// Open 解密存储串为 TicketPayload。
	Open(string) (*token.TicketPayload, error)
}

// ticketPayloadRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入 fake，同 ticketRedis 口径）。
type ticketPayloadRedis interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
}

// TicketPayloadStore al:ticket:payload:{ticket_id} 快照读写封装。
type TicketPayloadStore struct {
	rdb    ticketPayloadRedis
	sealer TicketPayloadSealer
}

// NewTicketPayloadStore 构造快照存储。rdb 为已连通的 go-redis 客户端，
// sealer 为 §11.6.1 封装的注入实现。
func NewTicketPayloadStore(rdb ticketPayloadRedis, sealer TicketPayloadSealer) *TicketPayloadStore {
	return &TicketPayloadStore{rdb: rdb, sealer: sealer}
}

// Write 写快照（CreateQrcode 1 次，接口文档 §2.8 行 719）：TTL = exp − iat
// （§11.6.4 行 1350；缺省 / 非法回落 600s 缺省，同 defaultTicketTTL）。
func (s *TicketPayloadStore) Write(ctx context.Context, payload *token.TicketPayload) error {
	if payload == nil {
		return errors.New("cache: seal ticket payload: nil payload")
	}
	if payload.GetTicketId() == "" {
		return errors.New("cache: seal ticket payload: empty ticket_id")
	}
	sealed, err := s.sealer.Seal(payload)
	if err != nil {
		return fmt.Errorf("cache: seal ticket payload: %w", err)
	}
	if err := s.rdb.Set(ctx, TicketPayloadKey(payload.GetTicketId()), sealed, payloadTTL(payload)).Err(); err != nil {
		return fmt.Errorf("cache: set ticket payload: %w", err)
	}
	return nil
}

// Read 读快照：缺失返回 (nil, nil)——快照缺失即不存在 / 已过期（§5.1 行
// 863），调用方据此拒绝；其余错误为基础设施故障。
func (s *TicketPayloadStore) Read(ctx context.Context, ticketID string) (*token.TicketPayload, error) {
	raw, err := s.rdb.Get(ctx, TicketPayloadKey(ticketID)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cache: get ticket payload: %w", err)
	}
	payload, err := s.sealer.Open(raw)
	if err != nil {
		return nil, fmt.Errorf("cache: open ticket payload: %w", err)
	}
	return payload, nil
}

// payloadTTL 快照键寿命：exp − iat（§11.6.4 行 1350），缺省 / 非法（<1s）
// 回落 600s 缺省，不产生无 TTL 的键。
func payloadTTL(payload *token.TicketPayload) time.Duration {
	if d := time.Duration(payload.GetExp()-payload.GetIat()) * time.Second; d >= time.Second {
		return d
	}
	return defaultTicketTTL
}
