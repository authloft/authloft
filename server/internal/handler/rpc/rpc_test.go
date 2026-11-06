// rpc 域两个 service handler 的全栈单测：经真实生成的 Connect
// handler + rpc HMAC 拦截器 + 错误包装 + CaptureRawBody（装配层生产形态，
// interceptors.go 行 222 口径），零 ENV.md 实例依赖——NonceStorer /
// SecretLookup / UserStore / epoch 读取链均为 fake。签名 signRPC 按接口文档
// §7 行 1381 五项公式独立实现（固定契约，与被测代码不共享实现，口径同
// internal/connect rpc_test.go 的 rpcSign）。
//
// 覆盖：GetUserProfile 明文断言（§3.1 行 809 例外）与 user_not_found；
// UpdateUserProfile 部分更新合并（未传字段不覆盖）+ 不可改字段行为 + no-op +
// birthday 格式拒绝；DecodeSession 成功（renewedToken 非空、sid/epoch 不变、
// iat/exp 刷新、无 Set-Cookie / X-Authloft-Token 响应头）/ 无效 / 过期 /
// epoch 不符（401 无 renewedToken）/ epoch 读取链故障（500）；拦截链拒绝
// （缺头 / 错签 403）。
package rpc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	accountv1 "authloft/gen/go/api/account/v1"
	commonv1 "authloft/gen/go/api/common/v1"
	rpcv1 "authloft/gen/go/api/rpc/v1"
	"authloft/gen/go/api/rpc/v1/rpcv1connect"
	"authloft/gen/go/token"
	internalconnect "authloft/internal/connect"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/session"
	"gorm.io/gorm"
)

const (
	testClientID = "web-1"
	testSecret   = "s3cr3t"
	testTTL      = 2 * time.Hour
)

// fakeNonceStore 计数型 fake（口径同 internal/connect rpc_test.go，包内私有
// 不可复用；写接口 UpdateUserProfile 的去重路径经它计数）。
type fakeNonceStore struct {
	mu    sync.Mutex
	seen  map[string]bool
	calls int
}

func (f *fakeNonceStore) Store(_ context.Context, clientID, nonce string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	key := clientID + "\x00" + nonce
	if f.seen[key] {
		return false, nil
	}
	if f.seen == nil {
		f.seen = make(map[string]bool)
	}
	f.seen[key] = true
	return true, nil
}

// fakeEpochReader 隔离型 epoch 读取（口径同 handler/account account_test.go；
// err 模拟读取链基础设施故障）。
type fakeEpochReader struct {
	values map[int64]int64
	err    error
}

func (f *fakeEpochReader) Current(_ context.Context, uid int64) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.values[uid], nil
}

// columnUpdate UpdateProfileColumns 的一次调用记录。
type columnUpdate struct {
	id        int64
	nickname  *string
	avatarURL *string
}

// fakeUserStore UserStore 的 fake：可变行 + 调用记录 + 各步错误注入。
// UpdateProfileColumns / SaveProfile 同步改写内存行，供同链路后续
// GetUserProfile 端到端复核。单行（user / profile）服务 GetUserProfile /
// DecodeSession include_user_info 单读路径；批量（usersByID / profilesByUID）
// 服务 GetUserProfiles——ListByIDs 按入参**倒序**返回，模拟 IN 查询行序
// 不保证，逼出 handler 按 ids 定位回填的实现（§7.2 顺序③行 1464）。
type fakeUserStore struct {
	mu            sync.Mutex
	user          *model.User
	profile       *model.UserProfile
	usersByID     map[int64]*model.User
	profilesByUID map[int64]*model.UserProfile
	userErr       error
	profileErr    error
	columnsErr    error
	saveErr       error
	listErr       error
	columnCalls   []columnUpdate
	saveCalls     []*model.UserProfile
	findCalls     int
	getCalls      int
	listCalls     int
	lastListIDs   []int64
}

func (f *fakeUserStore) FindByID(_ context.Context, _ int64) (*model.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.findCalls++
	return f.user, f.userErr
}

func (f *fakeUserStore) GetProfile(_ context.Context, _ int64) (*model.UserProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	return f.profile, f.profileErr
}

// ListByIDs 倒序回填（行序不保证的保守模拟）+ 调用计数（N+1
// 断言依据：listCalls 必须恰 1 次，findCalls / getCalls 恒 0）。
func (f *fakeUserStore) ListByIDs(_ context.Context, ids []int64) ([]model.User, []model.UserProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	f.lastListIDs = append([]int64(nil), ids...)
	if f.listErr != nil {
		return nil, nil, f.listErr
	}
	users := make([]model.User, 0, len(ids))
	profiles := make([]model.UserProfile, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- {
		if u, ok := f.usersByID[ids[i]]; ok {
			users = append(users, *u)
		}
		if p, ok := f.profilesByUID[ids[i]]; ok {
			profiles = append(profiles, *p)
		}
	}
	return users, profiles, nil
}

func (f *fakeUserStore) SaveProfile(_ context.Context, p *model.UserProfile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saveCalls = append(f.saveCalls, p)
	if f.saveErr != nil {
		return f.saveErr
	}
	f.profile = p
	return nil
}

func (f *fakeUserStore) UpdateProfileColumns(_ context.Context, id int64, nickname, avatarURL *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.columnCalls = append(f.columnCalls, columnUpdate{id: id, nickname: nickname, avatarURL: avatarURL})
	if f.columnsErr != nil {
		return f.columnsErr
	}
	if f.user != nil && f.user.ID == id {
		if nickname != nil {
			f.user.Nickname = *nickname
		}
		if avatarURL != nil {
			f.user.AvatarURL = *avatarURL
		}
	}
	return nil
}

func (f *fakeUserStore) columnCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.columnCalls)
}

func (f *fakeUserStore) saveCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.saveCalls)
}

// signRPC 按文档公式独立实现（§7 行 1381）：HMAC-SHA256(key=secret,
// msg="client_id:nonce:path:body:client_secret")，hex 输出。
func signRPC(clientID, nonce, path, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(clientID + ":" + nonce + ":" + path + ":" + body + ":" + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// nonceSeq 每请求递增的 nonce（写接口 30s 去重窗口内不得复用）。
var nonceSeq int64

func nextNonce() string {
	nonceSeq++
	return fmt.Sprintf("n%d", nonceSeq)
}

// newRPCTestMux 构造生产形态的 rpc 域测试链：生成 handler + HMAC 拦截器 +
// 错误包装（内层，connect.Server.HandlerOptions 同序）+ CaptureRawBody
//（RegisterRPC 强制包装口径）。
func newRPCTestMux(t *testing.T, users UserStore, tokens *session.Tokens, epochs *fakeEpochReader) http.Handler {
	t.Helper()
	lookup := func(_ context.Context, clientID string) (string, bool) {
		if clientID == testClientID {
			return testSecret, true
		}
		return "", false
	}
	nonces := &fakeNonceStore{}
	opts := func() []connect.HandlerOption {
		return []connect.HandlerOption{connect.WithInterceptors(
			internalconnect.NewRPCHMACInterceptor(nonces, lookup),
			internalconnect.NewErrorWrapperInterceptor(),
		)}
	}
	userPath, userH := rpcv1connect.NewUserServiceHandler(NewUserHandler(users), opts()...)
	tokenPath, tokenH := rpcv1connect.NewTokenServiceHandler(
		NewTokenHandler(session.NewVerifier(tokens, epochs), session.NewRenewer(tokens, testTTL), users),
		opts()...)
	mux := http.NewServeMux()
	mux.Handle(userPath, internalconnect.CaptureRawBody(userH))
	mux.Handle(tokenPath, internalconnect.CaptureRawBody(tokenH))
	return mux
}

// newTestTokens 自造密钥构造会话令牌签发器（口径同 handler/account
// account_test.go）。
func newTestTokens(t *testing.T) *session.Tokens {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return session.NewTokens(security.NewCodec(ks))
}

// doRPC 打一次带五项签名的 proto 编码 rpc 请求，返回 recorder。
func doRPC(t *testing.T, h http.Handler, procedure string, msg proto.Message) *httptest.ResponseRecorder {
	t.Helper()
	body, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	nonce := nextNonce()
	req := httptest.NewRequest(http.MethodPost, procedure, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("X-Client-ID", testClientID)
	req.Header.Set("X-Nonce-ID", nonce)
	req.Header.Set("X-Signature", signRPC(testClientID, nonce, procedure, string(body), testSecret))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// strPtr UpdateProfile / UpdateUserProfile 的 proto3 optional 字符串字段
//（has 位口径）取地址助手。
func strPtr(s string) *string { return &s }

// connectCodeOf 解 Connect 错误体的标准码（错误体恒 JSON，§1.5）。
func connectCodeOf(t *testing.T, raw string) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	return body.Code
}

// decodeErrorInfoDetail 从 Connect 错误体 details 解出第一枚 ErrorInfo
//（base64 value → proto 解码，§1.5 行 203-210；口径同 handler/admin
// admin_test.go 的 decodeErrorInfo，包内私有不可复用）。
func decodeErrorInfoDetail(t *testing.T, raw string) *commonv1.ErrorInfo {
	t.Helper()
	var body struct {
		Code    string `json:"code"`
		Details []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	if len(body.Details) != 1 {
		t.Fatalf("details 数量 = %d, want 1 (body %s)", len(body.Details), raw)
	}
	if body.Details[0].Type != "api.common.v1.ErrorInfo" {
		t.Fatalf("details[0].type = %q, want api.common.v1.ErrorInfo", body.Details[0].Type)
	}
	buf, err := base64.RawStdEncoding.DecodeString(body.Details[0].Value)
	if err != nil {
		t.Fatalf("decode detail value: %v", err)
	}
	info := &commonv1.ErrorInfo{}
	if err := proto.Unmarshal(buf, info); err != nil {
		t.Fatalf("unmarshal ErrorInfo: %v", err)
	}
	return info
}

// wantUser / wantProfile 数据样例（§3.1 行 779-797，口径同 handler/account
// account_test.go，rpc 域断言差异仅在 phone / email 明文）。
func wantUser() *model.User {
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

func wantProfile(t *testing.T) *model.UserProfile {
	t.Helper()
	// {"company":"Acme"} 的 msgpack 字节（同 handler/account account_test.go）。
	extra := []byte{0x81, 0xa7, 'c', 'o', 'm', 'p', 'a', 'n', 'y', 0xa4, 'A', 'c', 'm', 'e'}
	birthday := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	return &model.UserProfile{
		UserID: 10086, Gender: 1, Birthday: &birthday,
		Locale: "zh-CN", Timezone: "Asia/Shanghai", Extra: extra,
		UpdatedAt: time.Unix(1761800000, 0).UTC(),
	}
}

// sessionToken 签发 uid=10086 epoch=3 的会话令牌（iat 一分钟前、exp 一小时
// 后），epoch 读取链同步放行。
func sessionToken(t *testing.T, tokens *session.Tokens, epochs *fakeEpochReader) (string, *token.SessionTokenPayload) {
	t.Helper()
	p := &token.SessionTokenPayload{
		Id:    10086,
		Epoch: 3,
		Amr:   []string{"pwd", "otp"},
		Sid:   "sid-0001",
		Iat:   time.Now().Add(-time.Minute).Unix(),
		Exp:   time.Now().Add(time.Hour).Unix(),
	}
	epochs.values[p.Id] = p.Epoch
	tok, err := tokens.Sign(p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok, p
}

// TestGetUserProfilePlaintext 端到端：有效签名请求 → 200，§3.1 全字段 +
// rpc 域 phone / email 明文（§3.1 行 809 例外——与 account 域掩码版的关键
// 差异）+ profile 嵌套字段与 extra 透出。
func TestGetUserProfilePlaintext(t *testing.T) {
	users := &fakeUserStore{user: wantUser(), profile: wantProfile(t)}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	rec := doRPC(t, h, rpcv1connect.UserServiceGetUserProfileProcedure, &rpcv1.GetUserProfileRequest{Uid: 10086})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got rpcv1.ProfileResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal response: %v (body %x)", err, rec.Body.Bytes())
	}
	if got.GetId() != 10086 || got.GetUsername() != "zhang_san" || got.GetNickname() != "张三" {
		t.Errorf("basic fields = (id=%d username=%q nickname=%q)", got.GetId(), got.GetUsername(), got.GetNickname())
	}
	// 明文例外：不掩码（account 域同数据为 138****8000 / a***@example.com）。
	if got.GetPhone() != "13800008000" {
		t.Errorf("phone = %q, want 13800008000（rpc 域明文，§3.1 行 809）", got.GetPhone())
	}
	if got.GetEmail() != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com（rpc 域明文，§3.1 行 809）", got.GetEmail())
	}
	if got.GetPhoneVerified() != 1 || got.GetEmailVerified() != 1 {
		t.Errorf("verified = (%d, %d), want (1, 1)", got.GetPhoneVerified(), got.GetEmailVerified())
	}
	if got.GetUserStatus() != 1 || got.GetMfaRequired() != 0 || got.GetEpoch() != 3 {
		t.Errorf("status/mfa/epoch = (%d, %d, %d)", got.GetUserStatus(), got.GetMfaRequired(), got.GetEpoch())
	}
	if got.GetLastLoginAt() != 1761800000 || got.GetCreatedAt() != 1761700000 || got.GetUpdatedAt() != 1761800000 {
		t.Errorf("timestamps = (%d, %d, %d)", got.GetLastLoginAt(), got.GetCreatedAt(), got.GetUpdatedAt())
	}
	if got.GetAvatarUrl() != "https://cdn.example.com/a.jpg" {
		t.Errorf("avatarUrl = %q", got.GetAvatarUrl())
	}
	p := got.GetProfile()
	if p == nil || p.GetGender() != 1 || p.GetBirthday() != "1990-01-01" ||
		p.GetLocale() != "zh-CN" || p.GetTimezone() != "Asia/Shanghai" {
		t.Errorf("profile = %+v", p)
	}
	if v := p.GetExtra().GetFields()["company"].GetStringValue(); v != "Acme" {
		t.Errorf("profile.extra.company = %q, want Acme（msgpack → JSON 对象）", v)
	}
}

// TestGetUserProfileUserNotFound 用户不存在 → 404 not_found + ErrorInfo(rpc,
// user_not_found)（§1.6 封闭集合；HTTP 语义对齐 account GetProfile 先例）。
func TestGetUserProfileUserNotFound(t *testing.T) {
	users := &fakeUserStore{userErr: fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	rec := doRPC(t, h, rpcv1connect.UserServiceGetUserProfileProcedure, &rpcv1.GetUserProfileRequest{Uid: 404})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if got := connectCodeOf(t, rec.Body.String()); got != "not_found" {
		t.Errorf("code = %q, want not_found", got)
	}
	info := decodeErrorInfoDetail(t, rec.Body.String())
	if info.GetDomain() != "rpc" || info.GetCode() != "user_not_found" {
		t.Errorf("ErrorInfo = (domain=%q code=%q), want (rpc, user_not_found)（§1.6 封闭集合）", info.GetDomain(), info.GetCode())
	}
}

// TestUpdateUserProfilePartialMerge 部分更新合并（§3.2 行 821 + SaveProfile
// 行 224 注释「先读后拼整行」）：只传 nickname + profile.timezone →
// user 表仅 nickname 列被写（avatar_url 未传不覆盖）；user_profile 行
// timezone 更新、locale / gender / birthday / extra 未传不覆盖；随后
// GetUserProfile 端到端复核。用户名 / 手机号 / 邮箱不在可改集（proto 无
// 该字段，更新链路亦不触碰），断言更新前后原值保持。
func TestUpdateUserProfilePartialMerge(t *testing.T) {
	users := &fakeUserStore{user: wantUser(), profile: wantProfile(t)}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	rec := doRPC(t, h, rpcv1connect.UserServiceUpdateUserProfileProcedure, &rpcv1.UpdateUserProfileRequest{
		Uid:      10086,
		Nickname: strPtr("李四"),
		Profile:  &accountv1.UserProfile{Timezone: strPtr("Asia/Tokyo")},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	// user 表：恰一次列级更新，只含 nickname（avatar_url = nil = 未传不写）。
	if n := users.columnCallCount(); n != 1 {
		t.Fatalf("UpdateProfileColumns calls = %d, want 1", n)
	}
	cu := users.columnCalls[0]
	if cu.id != 10086 || cu.nickname == nil || *cu.nickname != "李四" {
		t.Errorf("column update = (id=%d nickname=%v), want (10086, 李四)", cu.id, cu.nickname)
	}
	if cu.avatarURL != nil {
		t.Errorf("avatarURL 列被写入 %q, want nil（未传不覆盖）", *cu.avatarURL)
	}
	// user_profile 行：恰一次整行 UPSERT，timezone 更新、其余未传字段保留现行值。
	if n := users.saveCallCount(); n != 1 {
		t.Fatalf("SaveProfile calls = %d, want 1", n)
	}
	saved := users.saveCalls[0]
	if saved.UserID != 10086 || saved.Timezone != "Asia/Tokyo" {
		t.Errorf("saved = (uid=%d timezone=%q), want (10086, Asia/Tokyo)", saved.UserID, saved.Timezone)
	}
	if saved.Locale != "zh-CN" || saved.Gender != 1 {
		t.Errorf("未传字段被覆盖: locale=%q gender=%d, want (zh-CN, 1)", saved.Locale, saved.Gender)
	}
	if saved.Birthday == nil || saved.Birthday.Format("2006-01-02") != "1990-01-01" {
		t.Errorf("birthday = %v, want 1990-01-01（未传不覆盖）", saved.Birthday)
	}
	if string(saved.Extra) != string(wantProfile(t).Extra) {
		t.Errorf("extra = %x, want 原字节（未传不覆盖）", saved.Extra)
	}

	// 端到端复核：GetUserProfile 看到合并后的行。
	rec = doRPC(t, h, rpcv1connect.UserServiceGetUserProfileProcedure, &rpcv1.GetUserProfileRequest{Uid: 10086})
	if rec.Code != http.StatusOK {
		t.Fatalf("GetProfile after update: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got rpcv1.ProfileResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if got.GetNickname() != "李四" {
		t.Errorf("nickname = %q, want 李四（已更新）", got.GetNickname())
	}
	if got.GetAvatarUrl() != "https://cdn.example.com/a.jpg" {
		t.Errorf("avatarUrl = %q, want 原值（未传不覆盖）", got.GetAvatarUrl())
	}
	// 不可改字段：更新链路前后原值保持（§3.2 行 821）。
	if got.GetUsername() != "zhang_san" || got.GetPhone() != "13800008000" || got.GetEmail() != "alice@example.com" {
		t.Errorf("不可改字段被改动: username=%q phone=%q email=%q", got.GetUsername(), got.GetPhone(), got.GetEmail())
	}
	if p := got.GetProfile(); p == nil || p.GetTimezone() != "Asia/Tokyo" || p.GetLocale() != "zh-CN" {
		t.Errorf("profile = %+v, want timezone=Asia/Tokyo locale=zh-CN", p)
	}
}

// TestUpdateUserProfileNoop 全字段未设置 = 纯 no-op：仅 uid → 200 且零存储
// 写入（连 updated_at 都不刷）；profile 消息在场但子字段全未设置（指针
// 全 nil）同样零写入（proto3 optional has 位口径，§3.2 行 837）。
func TestUpdateUserProfileNoop(t *testing.T) {
	users := &fakeUserStore{user: wantUser(), profile: wantProfile(t)}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	for name, req := range map[string]*rpcv1.UpdateUserProfileRequest{
		"uid only": {Uid: 10086},
		// 子消息在场但全字段未设置：has 位无任何置位 → 零写入。
		"empty profile": {Uid: 10086, Profile: &accountv1.UserProfile{}},
		// 标量未设置（nil）与显式空串语义不同：本用例只覆盖前者（后者见
		// TestUpdateUserProfileOptionalSemantics）。
		"nil scalars": {Uid: 10086, Nickname: nil, AvatarUrl: nil},
	} {
		rec := doRPC(t, h, rpcv1connect.UserServiceUpdateUserProfileProcedure, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 (body %s)", name, rec.Code, rec.Body.String())
		}
	}
	if n := users.columnCallCount(); n != 0 {
		t.Errorf("UpdateProfileColumns calls = %d, want 0（no-op 不写库）", n)
	}
	if n := users.saveCallCount(); n != 0 {
		t.Errorf("SaveProfile calls = %d, want 0（no-op 不写库）", n)
	}
}

// TestUpdateUserProfileUserNotFound 用户不存在 → 404 user_not_found（写路径
// 同口径，不落入 UPSERT 隐式建行）。
func TestUpdateUserProfileUserNotFound(t *testing.T) {
	users := &fakeUserStore{userErr: fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	rec := doRPC(t, h, rpcv1connect.UserServiceUpdateUserProfileProcedure, &rpcv1.UpdateUserProfileRequest{Uid: 404, Nickname: strPtr("x")})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	info := decodeErrorInfoDetail(t, rec.Body.String())
	if info.GetDomain() != "rpc" || info.GetCode() != "user_not_found" {
		t.Errorf("ErrorInfo = (domain=%q code=%q), want (rpc, user_not_found)", info.GetDomain(), info.GetCode())
	}
}

// TestUpdateUserProfileBadBirthday birthday 格式非法（非 YYYY-MM-DD）→
// 400 invalid_argument + ErrorInfo(rpc, invalid_request)（§1.6；先例 admin
// GetProviderSchema 入参拒绝）。
func TestUpdateUserProfileBadBirthday(t *testing.T) {
	users := &fakeUserStore{user: wantUser(), profile: wantProfile(t)}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	rec := doRPC(t, h, rpcv1connect.UserServiceUpdateUserProfileProcedure, &rpcv1.UpdateUserProfileRequest{
		Uid:     10086,
		Profile: &accountv1.UserProfile{Birthday: strPtr("1990/01/01")},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if got := connectCodeOf(t, rec.Body.String()); got != "invalid_argument" {
		t.Errorf("code = %q, want invalid_argument", got)
	}
	info := decodeErrorInfoDetail(t, rec.Body.String())
	if info.GetDomain() != "rpc" || info.GetCode() != "invalid_request" {
		t.Errorf("ErrorInfo = (domain=%q code=%q), want (rpc, invalid_request)", info.GetDomain(), info.GetCode())
	}
	if n := users.saveCallCount(); n != 0 {
		t.Errorf("SaveProfile calls = %d, want 0（非法入参不落库）", n)
	}
}

// TestUpdateUserProfileOptionalSemantics proto3 optional 三态回归
//（§3.2 行 837 / 后端架构 §17 行 1789）：显式零值生效——gender=0 覆盖现行 1、
// birthday / locale 显式空串清空现行值；未设置（nil）不覆盖——timezone 未
// 设置保留现行、extra 未设置保留原字节；nickname 显式空串 = user 表列清空
//（avatar_url 未设置保留）。对照旧「零值 = 未传」实现：gender=0 / 空串
// birthday / locale 均曾被静默忽略，本用例锁定三者已改为 has 位生效。
func TestUpdateUserProfileOptionalSemantics(t *testing.T) {
	users := &fakeUserStore{user: wantUser(), profile: wantProfile(t)}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	rec := doRPC(t, h, rpcv1connect.UserServiceUpdateUserProfileProcedure, &rpcv1.UpdateUserProfileRequest{
		Uid:      10086,
		Nickname: strPtr(""),
		Profile: &accountv1.UserProfile{
			Gender:   new(int64), // 显式 0：覆盖现行 1（旧实现 0 被当未传忽略）
			Birthday: strPtr(""), // 显式空串：清空现行 1990-01-01
			Locale:   strPtr(""), // 显式空串：清空现行 zh-CN
			// Timezone / Extra 未设置：保留现行值（has 位缺省不覆盖）
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	// user 表：恰一次列级更新，nickname 显式空串写入（avatar_url 未传不写）。
	if n := users.columnCallCount(); n != 1 {
		t.Fatalf("UpdateProfileColumns calls = %d, want 1", n)
	}
	cu := users.columnCalls[0]
	if cu.nickname == nil || *cu.nickname != "" {
		t.Errorf("column update nickname = %v, want 显式空串（has 位生效）", cu.nickname)
	}
	if cu.avatarURL != nil {
		t.Errorf("avatarURL 列被写入 %q, want nil（未设置不覆盖）", *cu.avatarURL)
	}

	// user_profile 行：恰一次整行 UPSERT，三态逐项断言。
	if n := users.saveCallCount(); n != 1 {
		t.Fatalf("SaveProfile calls = %d, want 1", n)
	}
	saved := users.saveCalls[0]
	if saved.Gender != 0 {
		t.Errorf("gender = %d, want 0（显式置 0 生效，旧实现被忽略）", saved.Gender)
	}
	if saved.Birthday != nil {
		t.Errorf("birthday = %v, want nil（显式空串清空）", saved.Birthday)
	}
	if saved.Locale != "" {
		t.Errorf("locale = %q, want 空串（显式清空）", saved.Locale)
	}
	if saved.Timezone != "Asia/Shanghai" {
		t.Errorf("timezone = %q, want Asia/Shanghai（未设置不覆盖）", saved.Timezone)
	}
	if string(saved.Extra) != string(wantProfile(t).Extra) {
		t.Errorf("extra = %x, want 原字节（未设置不覆盖）", saved.Extra)
	}
	if saved.UpdatedAt.IsZero() {
		t.Error("updated_at 未刷新（changed 路径应刷 updated_at）")
	}
}

// TestDecodeSessionSuccess 成功路径（§7.1 行 1399-1409）：校验通过即重签 →
// renewedToken 非空；新旧 sid / epoch（及 id / amr）不变、iat / exp 刷新；
// 响应平铺字段与 renewedToken 载荷自洽；无 Set-Cookie、无 X-Authloft-Token
// 响应头（renewedToken 只经响应体下发）。
func TestDecodeSessionSuccess(t *testing.T) {
	tokens := newTestTokens(t)
	epochs := &fakeEpochReader{values: map[int64]int64{}}
	h := newRPCTestMux(t, &fakeUserStore{}, tokens, epochs)
	tok, old := sessionToken(t, tokens, epochs)

	rec := doRPC(t, h, rpcv1connect.TokenServiceDecodeSessionProcedure, &rpcv1.DecodeSessionRequest{SessionToken: tok})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got rpcv1.SessionResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if got.GetRenewedToken() == "" {
		t.Fatal("renewedToken 为空（校验通过必须重签，§7.1 行 1408）")
	}
	if got.GetRenewedToken() == tok {
		t.Error("renewedToken 与旧令牌相同（应每次重签，nonce 重新随机）")
	}
	// 响应头边界：不写 Set-Cookie、不设 X-Authloft-Token（§7.1 行 1408）。
	if v := rec.Header().Get("Set-Cookie"); v != "" {
		t.Errorf("Set-Cookie = %q, want 空（本 RPC 不下发 Cookie）", v)
	}
	if v := rec.Header().Get("X-Authloft-Token"); v != "" {
		t.Errorf("X-Authloft-Token = %q, want 空（renewedToken 只经响应体）", v)
	}
	// 新载荷：sid / epoch / id / amr 不变，iat / exp 刷新（exp - iat = TTL）。
	fresh, err := tokens.Parse(got.GetRenewedToken())
	if err != nil {
		t.Fatalf("Parse renewedToken: %v", err)
	}
	if fresh.GetId() != old.GetId() || fresh.GetEpoch() != old.GetEpoch() || fresh.GetSid() != old.GetSid() {
		t.Errorf("载荷身份被改动: (id=%d epoch=%d sid=%q), want (id=%d epoch=%d sid=%q)",
			fresh.GetId(), fresh.GetEpoch(), fresh.GetSid(), old.GetId(), old.GetEpoch(), old.GetSid())
	}
	if len(fresh.GetAmr()) != len(old.GetAmr()) || fresh.GetAmr()[0] != old.GetAmr()[0] || fresh.GetAmr()[1] != old.GetAmr()[1] {
		t.Errorf("amr = %v, want %v", fresh.GetAmr(), old.GetAmr())
	}
	if fresh.GetIat() <= old.GetIat() {
		t.Errorf("iat = %d, want > %d（刷新）", fresh.GetIat(), old.GetIat())
	}
	if fresh.GetExp() <= old.GetExp() {
		t.Errorf("exp = %d, want > %d（刷新）", fresh.GetExp(), old.GetExp())
	}
	if got, want := fresh.GetExp()-fresh.GetIat(), int64(testTTL/time.Second); got != want {
		t.Errorf("exp-iat = %d, want %d（TTL 重签）", got, want)
	}
	// 平铺字段与 renewedToken 载荷自洽（decode(renewedToken) == 平铺字段）。
	if got.GetId() != fresh.GetId() || got.GetEpoch() != fresh.GetEpoch() || got.GetSid() != fresh.GetSid() ||
		got.GetIat() != fresh.GetIat() || got.GetExp() != fresh.GetExp() || len(got.GetAmr()) != len(fresh.GetAmr()) {
		t.Errorf("平铺字段与 renewedToken 载荷不自洽: %+v vs %+v", &got, fresh)
	}
}

// TestDecodeSessionFailures 失败路径（§7.1 行 1410）：session 无效 / 过期 /
// epoch 不一致 → 401 unauthenticated，错误只由 Connect 错误体表达、无
// renewedToken（不得 200 + 空 renewedToken 混用）。
func TestDecodeSessionFailures(t *testing.T) {
	tokens := newTestTokens(t)
	epochs := &fakeEpochReader{values: map[int64]int64{}}
	tok, _ := sessionToken(t, tokens, epochs)

	// 过期令牌：exp 已过（Verifier 步骤 2）。
	expiredP := &token.SessionTokenPayload{
		Id: 10086, Epoch: 3, Amr: []string{"pwd"}, Sid: "sid-0002",
		Iat: time.Now().Add(-2 * time.Hour).Unix(), Exp: time.Now().Add(-time.Hour).Unix(),
	}
	expired, err := tokens.Sign(expiredP)
	if err != nil {
		t.Fatalf("Sign expired: %v", err)
	}

	cases := []struct {
		name  string
		tok   string
		epoch int64 // 读取链返回的当前 epoch（3 = 一致，4 = 不一致）
	}{
		{"invalid token", "not-a-session-token", 3},
		{"expired", expired, 3},
		{"epoch mismatch", tok, 4},
	}
	for _, c := range cases {
		epochs.values[10086] = c.epoch
		h := newRPCTestMux(t, &fakeUserStore{}, tokens, epochs)
		rec := doRPC(t, h, rpcv1connect.TokenServiceDecodeSessionProcedure, &rpcv1.DecodeSessionRequest{SessionToken: c.tok})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401 (body %s)", c.name, rec.Code, rec.Body.String())
		}
		if got := connectCodeOf(t, rec.Body.String()); got != "unauthenticated" {
			t.Errorf("%s: code = %q, want unauthenticated", c.name, got)
		}
		if strings.Contains(rec.Body.String(), "renewed") {
			t.Errorf("%s: 错误体携带 renewedToken 语义 (body %s)", c.name, rec.Body.String())
		}
	}
}

// TestDecodeSessionEpochInfraError epoch 读取链基础设施故障（Redis 与回源
// 均失败）→ 500 internal（verify.go 行 27-29：不得与未登录混同；gateway
// 同款口径）。
func TestDecodeSessionEpochInfraError(t *testing.T) {
	tokens := newTestTokens(t)
	// values 仍需初始化（sessionToken 夹具要写入）；Current 对 err 非 nil
	// 恒先返回故障，values 不会被读到。
	epochs := &fakeEpochReader{values: map[int64]int64{}, err: errors.New("redis down")}
	tok, _ := sessionToken(t, tokens, epochs)
	h := newRPCTestMux(t, &fakeUserStore{}, tokens, epochs)

	rec := doRPC(t, h, rpcv1connect.TokenServiceDecodeSessionProcedure, &rpcv1.DecodeSessionRequest{SessionToken: tok})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
	if got := connectCodeOf(t, rec.Body.String()); got != "internal" {
		t.Errorf("code = %q, want internal", got)
	}
}

// TestChainRejectsWithoutValidHMAC 拦截链在位证明：缺任一鉴权头 / 签名错
// → 403 permission_denied，handler 不可达（拦截器细粒度行为由
// internal/connect rpc_test.go 全栈覆盖，此处只锚定本域装配形态）。
func TestChainRejectsWithoutValidHMAC(t *testing.T) {
	users := &fakeUserStore{user: wantUser(), profile: wantProfile(t)}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	body, err := proto.Marshal(&rpcv1.GetUserProfileRequest{Uid: 10086})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	post := func(headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, rpcv1connect.UserServiceGetUserProfileProcedure, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/proto")
		req.Header.Set("Connect-Protocol-Version", "1")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 缺全部三头。
	if rec := post(map[string]string{}); rec.Code != http.StatusForbidden {
		t.Fatalf("no headers: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	// 三头齐全但签名错（错误密钥）。
	rec := post(map[string]string{
		"X-Client-ID": testClientID,
		"X-Nonce-ID":  "n-bad",
		"X-Signature": signRPC(testClientID, "n-bad", rpcv1connect.UserServiceGetUserProfileProcedure, string(body), "wrong-secret"),
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad signature: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if got := connectCodeOf(t, rec.Body.String()); got != "permission_denied" {
		t.Errorf("bad signature code = %q, want permission_denied", got)
	}
}

// batchUser 造 GetUserProfiles 批量测试的补充用户（id / username 可变；
// 核心样例仍用 wantUser，此处只造最小完备行）。
func batchUser(id int64, username string) *model.User {
	return &model.User{
		ID: id, Username: username, Nickname: username + "-nick",
		UserStatus: 1, MfaRequired: 0,
		CreatedAt: time.Unix(1761700000, 0).UTC(), UpdatedAt: time.Unix(1761800000, 0).UTC(),
	}
}

// batchProfile 造批量测试的 user_profile 行。
func batchProfile(uid int64, locale string) *model.UserProfile {
	return &model.UserProfile{
		UserID: uid, Locale: locale, Timezone: "Asia/Shanghai",
		UpdatedAt: time.Unix(1761800000, 0).UTC(),
	}
}

// TestGetUserProfilesBatchSemantics 批量语义四项口径（§7.2 行 1462-1465）：
// 入参含重复（10010 / 10086 各两次）与缺失（99999）→ 响应顺序 = 入参去重
// 后（10010, 10086, 10011——缺失 99999 跳过不占位）；重复 id 首现位置去重
// 恰返回一条；user_profile 行缺失（10011）输出零值 profile 消息（同
// GetUserProfile 口径）；对存储恰一次 ListByIDs 批量调用（N+1 断言：
// fake listCalls == 1、findCalls / getCalls == 0）且入参为去重后序列。
// fake 倒序返回行，验证 handler 按 ids 定位回填、不依赖存储行序。
func TestGetUserProfilesBatchSemantics(t *testing.T) {
	users := &fakeUserStore{
		usersByID: map[int64]*model.User{
			10086: wantUser(),
			10010: batchUser(10010, "li_si"),
			10011: batchUser(10011, "wang_wu"),
		},
		profilesByUID: map[int64]*model.UserProfile{
			10086: wantProfile(t),
			10010: batchProfile(10010, "zh-CN"),
		},
	}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	ids := []int64{10010, 99999, 10086, 10010, 10011, 10086}
	rec := doRPC(t, h, rpcv1connect.UserServiceGetUserProfilesProcedure, &rpcv1.GetUserProfilesRequest{Ids: ids})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got rpcv1.GetUserProfilesResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal response: %v (body %x)", err, rec.Body.Bytes())
	}
	// 顺序③ + 去重④ + 缺失②：恰 3 条，顺序 = 入参去重后（99999 跳过）。
	order := make([]int64, 0, len(got.GetProfiles()))
	for _, p := range got.GetProfiles() {
		order = append(order, p.GetId())
	}
	wantOrder := []int64{10010, 10086, 10011}
	if len(order) != len(wantOrder) {
		t.Fatalf("条目数 = %d (order %v), want 3 (order %v)", len(order), order, wantOrder)
	}
	for i := range wantOrder {
		if order[i] != wantOrder[i] {
			t.Fatalf("顺序 = %v, want %v（入参去重后；fake 倒序返回行）", order, wantOrder)
		}
	}
	// 行序乱序下的对位：10010 挂自己的 profile（locale zh-CN），10086 挂
	// 样例 profile（timezone Asia/Shanghai + 明文 phone）。
	if p := got.GetProfiles()[0].GetProfile(); p == nil || p.GetLocale() != "zh-CN" || p.GetTimezone() != "Asia/Shanghai" {
		t.Errorf("10010 条 profile = %+v, want locale=zh-CN timezone=Asia/Shanghai", got.GetProfiles()[0].GetProfile())
	}
	if got.GetProfiles()[1].GetPhone() != "13800008000" {
		t.Errorf("10086 条 phone = %q, want 13800008000（rpc 域明文，同 GetUserProfile）", got.GetProfiles()[1].GetPhone())
	}
	if p := got.GetProfiles()[1].GetProfile(); p == nil || p.GetTimezone() != "Asia/Shanghai" {
		t.Errorf("10086 条 profile = %+v, want 样例 profile", got.GetProfiles()[1].GetProfile())
	}
	// 10011 无 user_profile 行 → 零值 profile 消息（非 nil，行缺失不报错）。
	p11 := got.GetProfiles()[2].GetProfile()
	if p11 == nil || p11.GetGender() != 0 || p11.GetLocale() != "" || p11.GetTimezone() != "" ||
		p11.GetBirthday() != "" || p11.GetExtra() != nil {
		t.Errorf("10011 条 profile = %+v, want 零值消息（行缺失同 GetUserProfile 口径）", p11)
	}
	// N+1 断言：批量查询恰一次、单查零调用；入参为去重后序列。
	if users.listCalls != 1 {
		t.Errorf("ListByIDs calls = %d, want 1（一次批量查询，N+1 禁止）", users.listCalls)
	}
	if users.findCalls != 0 || users.getCalls != 0 {
		t.Errorf("FindByID / GetProfile calls = (%d, %d), want (0, 0)（严禁循环单查）", users.findCalls, users.getCalls)
	}
	wantIDs := []int64{10010, 99999, 10086, 10011}
	if len(users.lastListIDs) != len(wantIDs) {
		t.Fatalf("ListByIDs 入参 = %v, want %v（去重后序列）", users.lastListIDs, wantIDs)
	}
	for i := range wantIDs {
		if users.lastListIDs[i] != wantIDs[i] {
			t.Errorf("ListByIDs 入参 = %v, want %v（去重后序列）", users.lastListIDs, wantIDs)
		}
	}
}

// TestGetUserProfilesLimit 上限①（§7.2 行 1462，去重前计数）：
//   - 101 条入参（去重后仅 2 个唯一 id）→ 400 invalid_argument +
//     ErrorInfo(rpc, invalid_request)，整单失败零查询（无部分返回、不截断）；
//     若实现错误地先去重再计数，该用例即漏过；
//   - 100 条唯一 id 入参 → 200 过界（缺失项照常跳过，恰一次批量查询）。
func TestGetUserProfilesLimit(t *testing.T) {
	// 101 拒：50×10086 + 51×10010，去重前 101。
	over := make([]int64, 0, 101)
	for i := 0; i < 50; i++ {
		over = append(over, 10086)
	}
	for i := 0; i < 51; i++ {
		over = append(over, 10010)
	}
	users := &fakeUserStore{usersByID: map[int64]*model.User{10086: wantUser()}}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	rec := doRPC(t, h, rpcv1connect.UserServiceGetUserProfilesProcedure, &rpcv1.GetUserProfilesRequest{Ids: over})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("101 ids: status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if got := connectCodeOf(t, rec.Body.String()); got != "invalid_argument" {
		t.Errorf("101 ids: code = %q, want invalid_argument", got)
	}
	info := decodeErrorInfoDetail(t, rec.Body.String())
	if info.GetDomain() != "rpc" || info.GetCode() != "invalid_request" {
		t.Errorf("101 ids: ErrorInfo = (domain=%q code=%q), want (rpc, invalid_request)（§7.2 ①行 1462）", info.GetDomain(), info.GetCode())
	}
	if users.listCalls != 0 {
		t.Errorf("101 ids: ListByIDs calls = %d, want 0（整单失败不触库）", users.listCalls)
	}

	// 100 过界：唯一 id 1..100，仅 id=1 存在 → 其余跳过。
	atLimit := make([]int64, 100)
	for i := range atLimit {
		atLimit[i] = int64(i + 1)
	}
	users = &fakeUserStore{usersByID: map[int64]*model.User{1: batchUser(1, "u_one")}}
	h = newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})
	rec = doRPC(t, h, rpcv1connect.UserServiceGetUserProfilesProcedure, &rpcv1.GetUserProfilesRequest{Ids: atLimit})
	if rec.Code != http.StatusOK {
		t.Fatalf("100 ids: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got rpcv1.GetUserProfilesResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if n := len(got.GetProfiles()); n != 1 {
		t.Errorf("100 ids: 条目数 = %d, want 1（缺失跳过）", n)
	}
	if users.listCalls != 1 {
		t.Errorf("100 ids: ListByIDs calls = %d, want 1", users.listCalls)
	}
}

// TestGetUserProfilesEmptyIDs ids 缺省 / 空列表 → 空 profiles、不报错、
// 零查询（§7.2 行 1467：空批量是合法的空集语义，非参数错误）。
func TestGetUserProfilesEmptyIDs(t *testing.T) {
	users := &fakeUserStore{usersByID: map[int64]*model.User{10086: wantUser()}}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	rec := doRPC(t, h, rpcv1connect.UserServiceGetUserProfilesProcedure, &rpcv1.GetUserProfilesRequest{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got rpcv1.GetUserProfilesResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if n := len(got.GetProfiles()); n != 0 {
		t.Errorf("条目数 = %d, want 0（空批量空集语义）", n)
	}
	if users.listCalls != 0 {
		t.Errorf("ListByIDs calls = %d, want 0（空批量零查询）", users.listCalls)
	}
}

// TestGetUserProfilesSameAsGetUserProfile 同构（§7.2 行 1438）：批量条目与
// GetUserProfile 单查响应逐字段相等（同一数据源经同一 dto.RPCProfile 投影，
// proto.Equal 深比较）。
func TestGetUserProfilesSameAsGetUserProfile(t *testing.T) {
	users := &fakeUserStore{
		user: wantUser(), profile: wantProfile(t),
		usersByID:     map[int64]*model.User{10086: wantUser()},
		profilesByUID: map[int64]*model.UserProfile{10086: wantProfile(t)},
	}
	h := newRPCTestMux(t, users, newTestTokens(t), &fakeEpochReader{values: map[int64]int64{}})

	recSingle := doRPC(t, h, rpcv1connect.UserServiceGetUserProfileProcedure, &rpcv1.GetUserProfileRequest{Uid: 10086})
	if recSingle.Code != http.StatusOK {
		t.Fatalf("GetUserProfile: status = %d (body %s)", recSingle.Code, recSingle.Body.String())
	}
	var single rpcv1.ProfileResponse
	if err := proto.Unmarshal(recSingle.Body.Bytes(), &single); err != nil {
		t.Fatalf("Unmarshal single: %v", err)
	}

	recBatch := doRPC(t, h, rpcv1connect.UserServiceGetUserProfilesProcedure, &rpcv1.GetUserProfilesRequest{Ids: []int64{10086}})
	if recBatch.Code != http.StatusOK {
		t.Fatalf("GetUserProfiles: status = %d (body %s)", recBatch.Code, recBatch.Body.String())
	}
	var batch rpcv1.GetUserProfilesResponse
	if err := proto.Unmarshal(recBatch.Body.Bytes(), &batch); err != nil {
		t.Fatalf("Unmarshal batch: %v", err)
	}
	if n := len(batch.GetProfiles()); n != 1 {
		t.Fatalf("条目数 = %d, want 1", n)
	}
	if !proto.Equal(batch.GetProfiles()[0], &single) {
		t.Errorf("批量条目与 GetUserProfile 响应不同构:\nbatch  = %+v\nsingle = %+v", batch.GetProfiles()[0], &single)
	}
}

// TestDecodeSessionIncludeUserInfo include_user_info 三态（§7.1 行 1434）：
//   - true 且校验通过 → user_info 填充且与 GetUserProfile 响应同构
//     （proto.Equal），用户读取恰一次单读链（FindByID + GetProfile 各 1）；
//   - false / 缺省 → user_info 不在场、**零额外查询**（fake 计数 0 增量）、
//     响应与现行完全一致；
//   - session 无效 + true → 401 不变（校验先于用户读取），失败路径零用户
//     查询、无 renewedToken / user_info 语义。
func TestDecodeSessionIncludeUserInfo(t *testing.T) {
	tokens := newTestTokens(t)
	epochs := &fakeEpochReader{values: map[int64]int64{}}
	users := &fakeUserStore{user: wantUser(), profile: wantProfile(t)}
	h := newRPCTestMux(t, users, tokens, epochs)
	tok, _ := sessionToken(t, tokens, epochs)

	// 同构基线：GetUserProfile(10086) 的响应（与 user_info 复用同一投影）。
	recSingle := doRPC(t, h, rpcv1connect.UserServiceGetUserProfileProcedure, &rpcv1.GetUserProfileRequest{Uid: 10086})
	if recSingle.Code != http.StatusOK {
		t.Fatalf("GetUserProfile: status = %d", recSingle.Code)
	}
	var single rpcv1.ProfileResponse
	if err := proto.Unmarshal(recSingle.Body.Bytes(), &single); err != nil {
		t.Fatalf("Unmarshal single: %v", err)
	}
	find0, get0, list0 := users.findCalls, users.getCalls, users.listCalls

	// ① true：填充 + 同构 + 恰一次单读链（零批量调用）。
	rec := doRPC(t, h, rpcv1connect.TokenServiceDecodeSessionProcedure, &rpcv1.DecodeSessionRequest{SessionToken: tok, IncludeUserInfo: true})
	if rec.Code != http.StatusOK {
		t.Fatalf("include=true: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	var got rpcv1.SessionResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if got.GetRenewedToken() == "" {
		t.Fatal("include=true: renewedToken 为空（核心产出不受影响）")
	}
	if !proto.Equal(got.GetUserInfo(), &single) {
		t.Errorf("include=true: user_info 与 GetUserProfile 响应不同构:\nuser_info = %+v\nsingle   = %+v", got.GetUserInfo(), &single)
	}
	if users.findCalls != find0+1 || users.getCalls != get0+1 {
		t.Errorf("include=true: FindByID / GetProfile 增量 = (%d, %d), want (1, 1)", users.findCalls-find0, users.getCalls-get0)
	}
	if users.listCalls != list0 {
		t.Errorf("include=true: ListByIDs 增量 = %d, want 0（单读路径不走批量）", users.listCalls-list0)
	}

	// ② false：零额外查询（fake 计数 0 增量）、无 user_info。
	rec = doRPC(t, h, rpcv1connect.TokenServiceDecodeSessionProcedure, &rpcv1.DecodeSessionRequest{SessionToken: tok, IncludeUserInfo: false})
	if rec.Code != http.StatusOK {
		t.Fatalf("include=false: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if err := proto.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if got.GetUserInfo() != nil {
		t.Errorf("include=false: user_info 在场（want 省略，§1.1 / §7.1 行 1434）: %+v", got.GetUserInfo())
	}
	if got.GetRenewedToken() == "" {
		t.Error("include=false: renewedToken 为空（现行语义不受影响）")
	}
	if users.findCalls != find0+1 || users.getCalls != get0+1 || users.listCalls != list0 {
		t.Errorf("include=false: 用户查询增量 = (find %d, get %d, list %d), want (0, 0, 0)（零额外查询）",
			users.findCalls-find0-1, users.getCalls-get0-1, users.listCalls-list0)
	}

	// ③ 缺省：同 false（零额外查询、无 user_info）。
	rec = doRPC(t, h, rpcv1connect.TokenServiceDecodeSessionProcedure, &rpcv1.DecodeSessionRequest{SessionToken: tok})
	if rec.Code != http.StatusOK {
		t.Fatalf("缺省: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if err := proto.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if got.GetUserInfo() != nil {
		t.Errorf("缺省: user_info 在场: %+v", got.GetUserInfo())
	}
	if users.findCalls != find0+1 || users.getCalls != get0+1 || users.listCalls != list0 {
		t.Errorf("缺省: 用户查询增量 = (find %d, get %d, list %d), want (0, 0, 0)（零额外查询）",
			users.findCalls-find0-1, users.getCalls-get0-1, users.listCalls-list0)
	}

	// ④ session 无效 + true：401 不变（失败分支不受 include_user_info 影响），
	// 校验先于用户读取 → 失败路径零用户查询。
	rec = doRPC(t, h, rpcv1connect.TokenServiceDecodeSessionProcedure, &rpcv1.DecodeSessionRequest{SessionToken: "not-a-session-token", IncludeUserInfo: true})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid + include=true: status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	if got := connectCodeOf(t, rec.Body.String()); got != "unauthenticated" {
		t.Errorf("invalid + include=true: code = %q, want unauthenticated", got)
	}
	if users.findCalls != find0+1 || users.getCalls != get0+1 || users.listCalls != list0 {
		t.Errorf("invalid + include=true: 用户查询增量 = (find %d, get %d, list %d), want (0, 0, 0)（401 路径零用户查询）",
			users.findCalls-find0-1, users.getCalls-get0-1, users.listCalls-list0)
	}
}
