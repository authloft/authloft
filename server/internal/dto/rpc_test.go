package dto

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"authloft/gen/go/token"
	"authloft/internal/repo/model"
)

// rpcTestUser / rpcTestProfile 数据样例（§3.1 行 779-797）。
func rpcTestUser() *model.User {
	phone, email := "13800008000", "alice@example.com"
	lastLogin := time.Unix(1761800000, 0).UTC()
	return &model.User{
		ID: 10086, Username: "zhang_san", Phone: &phone, Email: &email,
		PhoneVerified: 1, EmailVerified: 1, Nickname: "张三",
		AvatarURL: "https://cdn.example.com/a.jpg", UserStatus: 1,
		MfaRequired: 0, Epoch: 3, LastLoginAt: &lastLogin,
		CreatedAt: time.Unix(1761700000, 0).UTC(), UpdatedAt: time.Unix(1761800000, 0).UTC(),
	}
}

func rpcTestProfile() *model.UserProfile {
	extra := []byte{0x81, 0xa7, 'c', 'o', 'm', 'p', 'a', 'n', 'y', 0xa4, 'A', 'c', 'm', 'e'}
	birthday := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	return &model.UserProfile{
		UserID: 10086, Gender: 1, Birthday: &birthday,
		Locale: "zh-CN", Timezone: "Asia/Shanghai", Extra: extra,
	}
}

// TestRPCProfilePlaintext §3.1 全字段 + rpc 域 phone / email 明文（行 809
// 例外——与 account 版 AccountProfile 的掩码断言构成同一数据的两套口径）。
func TestRPCProfilePlaintext(t *testing.T) {
	got := RPCProfile(rpcTestUser(), rpcTestProfile())
	if got.GetId() != 10086 || got.GetUsername() != "zhang_san" || got.GetNickname() != "张三" ||
		got.GetAvatarUrl() != "https://cdn.example.com/a.jpg" {
		t.Errorf("basic fields = %+v", got)
	}
	if got.GetPhone() != "13800008000" {
		t.Errorf("phone = %q, want 13800008000（rpc 域明文，§3.1 行 809）", got.GetPhone())
	}
	if got.GetEmail() != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com（rpc 域明文，§3.1 行 809）", got.GetEmail())
	}
	if got.GetPhoneVerified() != 1 || got.GetEmailVerified() != 1 || got.GetUserStatus() != 1 ||
		got.GetMfaRequired() != 0 || got.GetEpoch() != 3 {
		t.Errorf("status fields = %+v", got)
	}
	if got.GetLastLoginAt() != 1761800000 || got.GetCreatedAt() != 1761700000 || got.GetUpdatedAt() != 1761800000 {
		t.Errorf("timestamps = (%d, %d, %d)", got.GetLastLoginAt(), got.GetCreatedAt(), got.GetUpdatedAt())
	}
	p := got.GetProfile()
	if p == nil || p.GetGender() != 1 || p.GetBirthday() != "1990-01-01" ||
		p.GetLocale() != "zh-CN" || p.GetTimezone() != "Asia/Shanghai" {
		t.Errorf("profile = %+v", p)
	}
	if v := p.GetExtra().GetFields()["company"].GetStringValue(); v != "Acme" {
		t.Errorf("profile.extra.company = %q, want Acme", v)
	}
}

// TestRPCProfileNilAndMissing 边界：u == nil → 空响应；p == nil → 零值
// profile 消息；phone / email 未绑定（nil 指针）→ 空串（protojson 省略，
// §1.1 空值口径）。
func TestRPCProfileNilAndMissing(t *testing.T) {
	if got := RPCProfile(nil, rpcTestProfile()); got.GetId() != 0 || got.GetProfile() != nil {
		t.Errorf("u == nil: got = %+v, want 空响应", got)
	}
	got := RPCProfile(rpcTestUser(), nil)
	if got.GetId() != 10086 {
		t.Errorf("id = %d, want 10086（主信息不受 profile 缺失影响）", got.GetId())
	}
	if p := got.GetProfile(); p == nil || p.GetGender() != 0 || p.GetBirthday() != "" {
		t.Errorf("profile = %+v, want 零值 profile 消息", p)
	}
	unbound := rpcTestUser()
	unbound.Phone, unbound.Email, unbound.LastLoginAt = nil, nil, nil
	got = RPCProfile(unbound, nil)
	if got.GetPhone() != "" || got.GetEmail() != "" || got.GetLastLoginAt() != 0 {
		t.Errorf("未绑定字段 = (phone=%q email=%q lastLoginAt=%d), want 零值", got.GetPhone(), got.GetEmail(), got.GetLastLoginAt())
	}
}

// TestRPCSessionMapping SessionTokenPayload → SessionResponse 平铺映射
//（§7.1 行 1399-1406：字段同名同义 + renewed_token 字段 7）；nil 载荷防御
// 分支只带 renewedToken。
func TestRPCSessionMapping(t *testing.T) {
	p := &token.SessionTokenPayload{
		Id: 10086, Epoch: 3, Amr: []string{"pwd", "otp"}, Sid: "sid-0001",
		Iat: 1761800000, Exp: 1762404800,
	}
	got := RPCSession(p, "renewed-token-value")
	if got.GetId() != 10086 || got.GetEpoch() != 3 || got.GetSid() != "sid-0001" ||
		got.GetIat() != 1761800000 || got.GetExp() != 1762404800 {
		t.Errorf("flat fields = %+v", got)
	}
	if len(got.GetAmr()) != 2 || got.GetAmr()[0] != "pwd" || got.GetAmr()[1] != "otp" {
		t.Errorf("amr = %v, want [pwd otp]", got.GetAmr())
	}
	if got.GetRenewedToken() != "renewed-token-value" {
		t.Errorf("renewedToken = %q", got.GetRenewedToken())
	}
	empty := RPCSession(nil, "")
	if empty.GetId() != 0 || empty.GetSid() != "" || empty.GetRenewedToken() != "" {
		t.Errorf("nil payload: got = %+v, want 仅零值 + renewedToken", empty)
	}
}

// TestParseRPCProfileBirthday YYYY-MM-DD 解析：合法取日期、非法报错
//（错误文案含原值，调用方按 §1.6 invalid_request 映射）。
func TestParseRPCProfileBirthday(t *testing.T) {
	got, err := ParseRPCProfileBirthday("1990-01-01")
	if err != nil {
		t.Fatalf("Parse valid: %v", err)
	}
	if y, m, d := got.Date(); y != 1990 || m != time.January || d != 1 {
		t.Errorf("parsed = %v, want 1990-01-01", got)
	}
	if _, err := ParseRPCProfileBirthday("1990/01/01"); err == nil {
		t.Error("Parse(1990/01/01) = nil error, want 格式拒绝")
	} else if !strings.Contains(err.Error(), "1990/01/01") {
		t.Errorf("error %v 不含原值", err)
	}
	if _, err := ParseRPCProfileBirthday("1990-13-01"); err == nil {
		t.Error("Parse(1990-13-01) = nil error, want 月份越界拒绝")
	}
}

// TestEncodeRPCProfileExtra Struct → msgpack 编码：nil → nil（未传不写列）；
// 单键对象产出与 account 解码方向互逆的字节（decodeProfileExtra 回读一致，
// 锚定编码与既有解码口径兼容）。
func TestEncodeRPCProfileExtra(t *testing.T) {
	raw, err := EncodeRPCProfileExtra(nil)
	if err != nil {
		t.Fatalf("Encode nil: %v", err)
	}
	if raw != nil {
		t.Errorf("Encode nil = %x, want nil（未传不写列）", raw)
	}
	in, err := structpb.NewStruct(map[string]any{"company": "Acme"})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	raw, err = EncodeRPCProfileExtra(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// 与 account 版 wantProfile 的 extra 字节同款（fixmap1 + str7 + str4）。
	if string(raw) != string([]byte{0x81, 0xa7, 'c', 'o', 'm', 'p', 'a', 'n', 'y', 0xa4, 'A', 'c', 'm', 'e'}) {
		t.Errorf("encoded = %x, want account 解码方向的同款字节", raw)
	}
	// 互逆：本包解码（account.go decodeProfileExtra）回读一致。
	back := decodeProfileExtra(raw)
	if v := back.GetFields()["company"].GetStringValue(); v != "Acme" {
		t.Errorf("roundtrip company = %q, want Acme", v)
	}
}
