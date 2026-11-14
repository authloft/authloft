// ticket.go `al:ticket` 域词汇（docs/后端架构.md §3.7）：票据结果 / 快照
// 读写窄接口、结构版本与 scene / status 取值、可判别哨兵错误。本包是
// `al:ticket` 唯一归属（§11.6.5）；依赖方向 `qrcode → ticket` 单向，
// 本包不得 import `service/qrcode`。
package ticket

import (
	"context"
	"errors"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/cache"
)

// al:ticket 域常量（§11.6.4 / §11.6.5）。
const (
	// TicketResultV TicketResult 结构版本（§11.6.5 行 1351：v=1）。
	TicketResultV = 1
	// ChannelQRCode TicketResult.channel（§11.6.5 行 1353：当前仅 qrcode）。
	ChannelQRCode = "qrcode"
	// SceneLogin / SceneBind TicketPayload.scene 取值（§11.6.4 行 1328）。
	SceneLogin = "login"
	SceneBind  = "bind"
	// TicketStatusScanned / TicketStatusMFAPending / TicketStatusSuccess /
	// TicketStatusFailed TicketResult.status（§11.6.5 行 1400：scanned |
	// mfa_pending | success | failed——失败类具体结论由写入方落本字段，轮询侧
	// 映射为 ticket 只报 failed；mfa_pending 为非终态，映射到轮询顶层
	// needs_step_up 且 ticket.status 仍报 scanned）。
	TicketStatusScanned    = "scanned"
	TicketStatusMFAPending = "mfa_pending"
	TicketStatusSuccess    = "success"
	TicketStatusFailed     = "failed"
)

// 可判别哨兵错误（handler 转 Connect 错误体 + ErrorInfo，§1.6 封闭集成员）。
var (
	// ErrQrcodeInvalidRequest 参数缺失 / scene 非法 / 通道不支持。
	ErrQrcodeInvalidRequest = errors.New("qrcode: invalid request")
	// ErrQrcodeUnauthenticated scene=bind 需要会话 / Confirm 会话缺失失效（401）。
	ErrQrcodeUnauthenticated = errors.New("qrcode: authentication required")
	// ErrQrcodeTicketInvalid 扫码票据不存在 / 已过期 / 状态不是 mfa_pending
	// （扫码 step-up 的主体凭证失效，§3.8.5 行 1301 的 token_invalid 口径）。
	ErrQrcodeTicketInvalid = errors.New("qrcode: ticket invalid")
)

// TicketStore al:ticket:{ticket_id} 读写窄接口（§20）：*cache.TicketStore
// 天然满足；测试传 fake。
type TicketStore interface {
	WriteScanned(ctx context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error)
	WriteComplete(ctx context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error)
	Peek(ctx context.Context, id string) (*token.TicketResult, error)
	Take(ctx context.Context, id string) (*token.TicketResult, error)
	Wait(ctx context.Context, id string, timeout time.Duration) error
}

// TicketPayloadStore al:ticket:payload:{ticket_id} 快照读写窄接口（§5.1 行
// 863、§11.6.4 行 1350）：*cache.TicketPayloadStore 天然满足；测试传
// fake。CreateQrcode 写（1 次、TTL = exp − iat），LoginOauth 扫码分支读。
type TicketPayloadStore interface {
	// Write 写快照（CreateQrcode 1 次，TTL = exp − iat，默认 600s）。
	Write(ctx context.Context, payload *token.TicketPayload) error
	// Read 读快照；缺失（不存在 / 已过期）返回 (nil, nil)。
	Read(ctx context.Context, ticketID string) (*token.TicketPayload, error)
}

// SessionVerifier 会话校验器（ConfirmLoginTicket 用，§11.1 四步）；
// *session.Verifier 天然满足。
type SessionVerifier interface {
	Verify(ctx context.Context, sessionToken string) (*token.SessionTokenPayload, error)
}
