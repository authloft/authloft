// sealer.go `al:ticket` 域加密 sealer（docs/后端架构.md §3.7、§11.6.5）：
// TicketResult 与 TicketPayload 的整值加密读写，供装配层注入
// cache.NewTicketStore / cache.NewTicketPayloadStore。
package ticket

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/security"
)

// NewTicketResultSealer 构造生产 TicketSealer（cache.TicketSealer 实现，
// 装配层注入 cache.NewTicketStore）：TicketResult 按 protojson（§1.6 行
// 86 MarshalOptions）序列化后整值加密（复用 §11.6.1 封装、purpose=ticket，
// §11.6.5 行 1347——Redis 内不留明文）；读取方遇未知结构版本按失败处理
// （§11.6.5 行 1351）。protojson 字节经 BytesValue 包封进 §11.6.1 封装
// （该封装以 protobuf 消息为载荷单位，BytesValue 是服务端内部的字节
// 载体，不新增对外结构）。
func NewTicketResultSealer(codec *security.Codec) cache.TicketSealer {
	return &ticketResultSealer{codec: codec}
}

type ticketResultSealer struct {
	codec *security.Codec
}

// Seal protojson → 整值加密。
func (s *ticketResultSealer) Seal(res *token.TicketResult) (string, error) {
	if res == nil {
		return "", errors.New("qrcode: seal ticket result: nil result")
	}
	raw, err := protojson.Marshal(res)
	if err != nil {
		return "", fmt.Errorf("qrcode: marshal ticket result: %w", err)
	}
	sealed, err := s.codec.Seal(security.PurposeTicket, &wrapperspb.BytesValue{Value: raw})
	if err != nil {
		return "", fmt.Errorf("qrcode: seal ticket result: %w", err)
	}
	return sealed, nil
}

// Open 解密 → protojson → 版本校验（未知版本按失败处理）。
func (s *ticketResultSealer) Open(sealed string) (*token.TicketResult, error) {
	w, err := security.Open[wrapperspb.BytesValue](s.codec, security.PurposeTicket, sealed)
	if err != nil {
		return nil, fmt.Errorf("qrcode: open ticket result: %w", err)
	}
	res := &token.TicketResult{}
	if err := protojson.Unmarshal(w.GetValue(), res); err != nil {
		return nil, fmt.Errorf("qrcode: unmarshal ticket result: %w", err)
	}
	if res.GetV() != TicketResultV {
		return nil, fmt.Errorf("qrcode: unknown ticket result version %d", res.GetV())
	}
	return res, nil
}

// NewTicketPayloadSealer 构造快照 sealer（cache.TicketPayloadSealer 实现，
// 装配层注入 cache.NewTicketPayloadStore）：TicketPayload 全标量
// 字段，直接经 §11.6.1 封装整值加密（purpose=ticket，与 ticket 串同一
// 封装路径——§5.1 行 863「TicketPayload 加密快照」，无需 protojson +
// BytesValue 包封）。
func NewTicketPayloadSealer(codec *security.Codec) cache.TicketPayloadSealer {
	return &ticketPayloadSealer{codec: codec}
}

type ticketPayloadSealer struct {
	codec *security.Codec
}

// Seal 整值加密。
func (s *ticketPayloadSealer) Seal(p *token.TicketPayload) (string, error) {
	if p == nil {
		return "", errors.New("qrcode: seal ticket payload: nil payload")
	}
	return s.codec.Seal(security.PurposeTicket, p)
}

// Open 解密（§11.6.1 封装自带认证，篡改 / 跨 purpose 不可解）。
func (s *ticketPayloadSealer) Open(sealed string) (*token.TicketPayload, error) {
	p, err := security.Open[token.TicketPayload](s.codec, security.PurposeTicket, sealed)
	if err != nil {
		return nil, fmt.Errorf("qrcode: open ticket payload: %w", err)
	}
	return p, nil
}
