// rpc 域的内部模型 → proto 报文转换（docs/接口文档.md §7 行 1391-1393、
// §3.1 行 774-813、§7.1 行 1399-1406）：UserService/GetUserProfile 的 §3.1
// Authloft 结构、TokenService/DecodeSession 的 SessionResponse 平铺载荷，
// 以及 UpdateUserProfile 反向转换（birthday 字符串解析、extra 的
// Struct → msgpack 编码）均以本文件为唯一出口（docs/后端架构.md §3.5：
// 本层只做转换与裁剪，不定义新的跨端结构）。
//
// 明文口径（§3.1 掩码矩阵行 809）：rpc 域 phone / email **明文**——调用方为
// SSO 应用后端，已由 X-Signature + client_secret 完成鉴权（§7），与 account
// 域自助接口的掩码版（account.go）是两套取值，不共用任何掩码函数。
// 嵌套 profile 结构跨包复用 api.account.v1.UserProfile（rpc profile.proto
// 引用 account 定义，「同一结构只定义一次」），其行 → 报文转换与
// extra 的 msgpack 解码直接复用本包 account.go 的私有实现（dto 为单包，无
// 跨包私有问题）。
package dto

import (
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/types/known/structpb"

	rpcv1 "authloft/gen/go/api/rpc/v1"
	"authloft/gen/go/token"
	"authloft/internal/repo/model"
)

// RPCProfile 把 user + user_profile 行组装为 rpc 域的 §3.1 ProfileResponse
//（行 775：各端点响应即下列字段、无信封包裹）。phone / email 明文输出
//（行 809 例外，掩码矩阵其余调用方见 account.go 的掩码版）。profile 行缺失
//（p == nil）时输出零值 profile 消息，不视为错误；u == nil 时返回空响应
//（调用方契约下不可达的防御分支，口径同 AccountProfile）。
func RPCProfile(u *model.User, p *model.UserProfile) *rpcv1.ProfileResponse {
	if u == nil {
		return &rpcv1.ProfileResponse{}
	}
	resp := &rpcv1.ProfileResponse{
		Id:            u.ID,
		Username:      u.Username,
		Nickname:      u.Nickname,
		AvatarUrl:     u.AvatarURL,
		PhoneVerified: int64(u.PhoneVerified),
		EmailVerified: int64(u.EmailVerified),
		UserStatus:    int64(u.UserStatus),
		MfaRequired:   int64(u.MfaRequired),
		Epoch:         int64(u.Epoch),
		CreatedAt:     u.CreatedAt.Unix(),
		UpdatedAt:     u.UpdatedAt.Unix(),
		Profile:       accountUserProfile(p),
	}
	// phone / email：rpc 域明文（§3.1 行 809），绑定（非空）才输出，未绑定
	// 保持零值由 protojson 省略（§1.1 空值口径，与 account 版仅差掩码）。
	if u.Phone != nil && *u.Phone != "" {
		resp.Phone = *u.Phone
	}
	if u.Email != nil && *u.Email != "" {
		resp.Email = *u.Email
	}
	if u.LastLoginAt != nil {
		resp.LastLoginAt = u.LastLoginAt.Unix()
	}
	return resp
}

// RPCSession 把会话载荷平铺为 SessionResponse（§7.1 行 1399-1406：字段与
// SessionTokenPayload 同名同义 + renewed_token 字段 7）。p 取重签后的新载荷
// 时，响应字段与 renewedToken 自洽（decode(renewedToken) == 平铺字段）；
// renewedToken 空串仅出现在调用方明确传入时（§7.1 行 1410 口径下不应发生）。
func RPCSession(p *token.SessionTokenPayload, renewedToken string) *rpcv1.SessionResponse {
	if p == nil {
		return &rpcv1.SessionResponse{RenewedToken: renewedToken}
	}
	return &rpcv1.SessionResponse{
		Id:           p.GetId(),
		Epoch:        p.GetEpoch(),
		Amr:          p.GetAmr(),
		Sid:          p.GetSid(),
		Iat:          p.GetIat(),
		Exp:          p.GetExp(),
		RenewedToken: renewedToken,
	}
}

// ParseRPCProfileBirthday 解析 UpdateUserProfile 入参的 birthday
//（§3.1 行 794：YYYY-MM-DD）。raw 须非空（空串 = 未传，由调用方按部分更新
// 语义跳过，§3.2 行 821）；格式非法返回错误（调用方按 §1.6 invalid_request
// 拒绝）。仅取日期、截断时分秒。
func ParseRPCProfileBirthday(raw string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("dto: parse profile birthday %q: %w", raw, err)
	}
	return t, nil
}

// EncodeRPCProfileExtra 把 UpdateUserProfile 入参的 extra（JSON 对象视图，
// §3.1 行 796 反向）编码为 user_profile.extra 列的 msgpack 字节。nil（未传）
// 返回 nil 字节（列不写入，由调用方按部分更新语义保留旧值）；编码为内存
// 操作，错误仅来自 msgpack 对不可序列化值的拒绝。
func EncodeRPCProfileExtra(extra *structpb.Struct) ([]byte, error) {
	if extra == nil {
		return nil, nil
	}
	raw, err := msgpack.Marshal(extra.AsMap())
	if err != nil {
		return nil, fmt.Errorf("dto: encode profile extra: %w", err)
	}
	return raw, nil
}
