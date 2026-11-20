// session 包校验四步 + 令牌签发/解析 + ctx 助手单测。失效检查链用真实
// cache.EpochStore + 计数 fake redis 做集成断言（缺失回源 / MGET 命中 /
// 命令级故障 fail-open）；纯逻辑分支用 fake EpochReader 隔离。
package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/security"
)

// newTestCodec 构造测试 Codec（sign 密钥 version=1 kid=1，可传 legacy）。
func newTestCodec(t *testing.T, legacy ...security.KeyEntry) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	ks, err := security.NewKeyStore(
		security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key}, legacy...)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

// otherKeyCodec 用另一把 kid=2 的密钥构造 Codec（模拟未知 kid / 换钥）。
func otherKeyCodec(t *testing.T) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x80 + i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 2}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

// testPayload 标准测试载荷：exp=2000（配合可控 now=1500 未过期）。
func testPayload() *token.SessionTokenPayload {
	return &token.SessionTokenPayload{
		Id:    42,
		Epoch: 7,
		Amr:   []string{"pwd", "otp"},
		Sid:   "sid-0001",
		Iat:   1000,
		Exp:   2000,
	}
}

// fakeEpochReader 隔离型失效检查（记录调用、返回预设三元组或错误）。
type fakeEpochReader struct {
	mu      sync.Mutex
	calls   []int64
	values  map[int64]int64
	revoked map[string]bool
	err     error
}

func (f *fakeEpochReader) Check(ctx context.Context, uid int64, sid string) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, uid)
	if f.err != nil {
		return 0, false, f.err
	}
	return f.values[uid], f.revoked[sid], nil
}

func (f *fakeEpochReader) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// countingRedis 计数型 fake redis（满足 cache 包 epochRedis 窄接口的
// 方法签名，可传给 cache.NewEpochStore；现接口含 MGet——Check 双键读、
// Del——Sync 写路径的兜底）：记录 GET/MGET/SET 次数、键名与 SET 的 TTL；
// vals 为键值表；mgetErr 非 nil 时 MGET 返回命令级故障。
type countingRedis struct {
	mu       sync.Mutex
	gets     int
	mgets    int
	sets     int
	getKeys  []string
	mgetKeys [][]string
	setKeys  []string
	setTTNs  []time.Duration
	vals     map[string]string
	mgetErr  error
}

func (f *countingRedis) Get(ctx context.Context, key string) cache.StringResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	f.getKeys = append(f.getKeys, key)
	if v, ok := f.vals[key]; ok {
		return cache.NewStringResult(v, nil)
	}
	return cache.NewStringResult("", cache.Nil)
}

func (f *countingRedis) MGet(ctx context.Context, keys ...string) cache.MGetResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mgets++
	f.mgetKeys = append(f.mgetKeys, append([]string(nil), keys...))
	if f.mgetErr != nil {
		return cache.NewMGetResult(nil, f.mgetErr)
	}
	vals := make([]*string, len(keys))
	for i, key := range keys {
		if v, ok := f.vals[key]; ok {
			s := v
			vals[i] = &s
		}
	}
	return cache.NewMGetResult(vals, nil)
}

func (f *countingRedis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) cache.StatusResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets++
	f.setKeys = append(f.setKeys, key)
	f.setTTNs = append(f.setTTNs, expiration)
	if f.vals == nil {
		f.vals = make(map[string]string)
	}
	f.vals[key] = fmt.Sprint(value)
	return cache.NewStatusResult(nil)
}

func (f *countingRedis) Del(ctx context.Context, keys ...string) cache.IntResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, key := range keys {
		delete(f.vals, key)
	}
	return cache.NewIntResult(1, nil)
}

func (f *countingRedis) counts() (gets, mgets, sets int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.mgets, f.sets
}

// newVerifierAt 构造可控时钟的 Verifier（now 固定 Unix 1500，exp=2000
// 的载荷未过期）。
func newVerifierAt(tokens *Tokens, epochs EpochReader) *Verifier {
	v := NewVerifier(tokens, epochs)
	v.now = func() time.Time { return time.Unix(1500, 0) }
	return v
}

// ---- token.go：签发 / 解析 + ctx 助手 ----

// TestTokensSignParseRoundTrip 签发 → 解析往返，字段逐项一致。
func TestTokensSignParseRoundTrip(t *testing.T) {
	tokens := NewTokens(newTestCodec(t))
	want := testPayload()
	tok, err := tokens.Sign(want)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if tok == "" {
		t.Fatal("Sign returned empty token")
	}
	got, err := tokens.Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.GetId() != want.GetId() || got.GetEpoch() != want.GetEpoch() ||
		got.GetSid() != want.GetSid() || got.GetIat() != want.GetIat() || got.GetExp() != want.GetExp() {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
	if len(got.GetAmr()) != len(want.GetAmr()) || got.GetAmr()[0] != "pwd" || got.GetAmr()[1] != "otp" {
		t.Fatalf("amr mismatch: got %v, want %v", got.GetAmr(), want.GetAmr())
	}
}

// TestTokensParseRejectsCrossPurpose 同钥签发的 login purpose 令牌
// 不能当 session 解（§11.6.1 AAD 隔离）。
func TestTokensParseRejectsCrossPurpose(t *testing.T) {
	codec := newTestCodec(t)
	tokens := NewTokens(codec)
	loginTok, err := codec.Seal(security.PurposeLogin, testPayload())
	if err != nil {
		t.Fatalf("Seal login: %v", err)
	}
	if _, err := tokens.Parse(loginTok); err == nil {
		t.Fatal("Parse must reject cross-purpose token")
	}
}

// TestTokensParseUnknownKid 另一把 kid 的密钥签发的令牌被拒
// （§11.1 步骤 1：验 kid → 取密钥，未知即失败）。
func TestTokensParseUnknownKid(t *testing.T) {
	tokens := NewTokens(newTestCodec(t))
	foreign, err := NewTokens(otherKeyCodec(t)).Sign(testPayload())
	if err != nil {
		t.Fatalf("Sign foreign: %v", err)
	}
	if _, err := tokens.Parse(foreign); err == nil {
		t.Fatal("Parse must reject unknown kid")
	}
}

// TestTokensParseGarbage 非令牌串（空串 / 乱码 / 截断）一律失败。
func TestTokensParseGarbage(t *testing.T) {
	tokens := NewTokens(newTestCodec(t))
	for _, tok := range []string{"", "not-a-token", "AAAA", "QUJD"} {
		if _, err := tokens.Parse(tok); err == nil {
			t.Fatalf("Parse(%q) must fail", tok)
		}
	}
}

// TestContextHelpers WithSessionContext 注入后三项 FromContext 可读；
// 空 ctx 全部 false。
func TestContextHelpers(t *testing.T) {
	p := testPayload()
	p.HasAnyPermission = true
	ctx := WithSessionContext(context.Background(), p)
	if uid, ok := UIDFromContext(ctx); !ok || uid != 42 {
		t.Fatalf("UIDFromContext = (%d, %v), want (42, true)", uid, ok)
	}
	amr, ok := AMRFromContext(ctx)
	if !ok || len(amr) != 2 || amr[0] != "pwd" || amr[1] != "otp" {
		t.Fatalf("AMRFromContext = (%v, %v), want ([pwd otp], true)", amr, ok)
	}
	if sid, ok := SIDFromContext(ctx); !ok || sid != "sid-0001" {
		t.Fatalf("SIDFromContext = (%q, %v), want (sid-0001, true)", sid, ok)
	}
	if !HasAnyPermissionFromContext(ctx) {
		t.Fatal("HasAnyPermissionFromContext = false, want true（标记随载荷注入）")
	}

	plain := context.Background()
	if _, ok := UIDFromContext(plain); ok {
		t.Fatal("UIDFromContext on plain ctx must be false")
	}
	if _, ok := AMRFromContext(plain); ok {
		t.Fatal("AMRFromContext on plain ctx must be false")
	}
	if _, ok := SIDFromContext(plain); ok {
		t.Fatal("SIDFromContext on plain ctx must be false")
	}
	if HasAnyPermissionFromContext(plain) {
		t.Fatal("HasAnyPermissionFromContext on plain ctx must be false")
	}

	falseMarker := WithSessionContext(context.Background(), testPayload())
	if HasAnyPermissionFromContext(falseMarker) {
		t.Fatal("HasAnyPermissionFromContext on false marker must be false")
	}
}

// ---- verify.go：§11.1 四步 ----

// TestVerifyStep1BadToken 步骤①：坏令牌（乱码 / 未知 kid / 跨 purpose）
// 一律 ErrNotAuthenticated，且不触碰 epoch 链。
func TestVerifyStep1BadToken(t *testing.T) {
	ctx := context.Background()
	epochs := &fakeEpochReader{values: map[int64]int64{42: 7}}
	v := newVerifierAt(NewTokens(newTestCodec(t)), epochs)

	for _, tok := range []string{"", "garbage"} {
		if _, err := v.Verify(ctx, tok); !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("Verify(%q) err = %v, want ErrNotAuthenticated", tok, err)
		}
	}
	foreign, err := NewTokens(otherKeyCodec(t)).Sign(testPayload())
	if err != nil {
		t.Fatalf("Sign foreign: %v", err)
	}
	if _, err := v.Verify(ctx, foreign); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Verify(unknown kid) err = %v, want ErrNotAuthenticated", err)
	}
	if epochs.callCount() != 0 {
		t.Fatalf("epoch calls = %d, want 0（步骤①失败即止，不查 epoch）", epochs.callCount())
	}
}

// TestVerifyStep2Expired 步骤②：exp 过期即未登录；未过期通过。
func TestVerifyStep2Expired(t *testing.T) {
	ctx := context.Background()
	tokens := NewTokens(newTestCodec(t))
	epochs := &fakeEpochReader{values: map[int64]int64{42: 7}}

	tok, err := tokens.Sign(testPayload()) // exp=2000
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	v := NewVerifier(tokens, epochs)
	v.now = func() time.Time { return time.Unix(2000, 0) } // now == exp：到点即过期
	if _, err := v.Verify(ctx, tok); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Verify at exp err = %v, want ErrNotAuthenticated", err)
	}

	v.now = func() time.Time { return time.Unix(1999, 0) }
	p, err := v.Verify(ctx, tok)
	if err != nil || p.GetId() != 42 {
		t.Fatalf("Verify before exp = (%v, %v), want pass", p, err)
	}
}

// TestVerifyStep3EpochMismatch 步骤③：token.epoch != 当前值即
// ErrSessionStale（改密后旧令牌失效）。
func TestVerifyStep3EpochMismatch(t *testing.T) {
	ctx := context.Background()
	tokens := NewTokens(newTestCodec(t))
	tok, err := tokens.Sign(testPayload()) // epoch=7
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	epochs := &fakeEpochReader{values: map[int64]int64{42: 8}} // 已改密 → 8
	v := newVerifierAt(tokens, epochs)

	if _, err := v.Verify(ctx, tok); !errors.Is(err, ErrSessionStale) {
		t.Fatalf("err = %v, want ErrSessionStale", err)
	}
	if epochs.callCount() != 1 {
		t.Fatalf("epoch calls = %d, want 1", epochs.callCount())
	}
}

// TestVerifyStep3Revoked 步骤③：逐出标记存在即 ErrSessionRevoked，且
// 优先于 epoch 比对（一致时同样拒绝）。
func TestVerifyStep3Revoked(t *testing.T) {
	ctx := context.Background()
	tokens := NewTokens(newTestCodec(t))
	tok, err := tokens.Sign(testPayload()) // epoch=7, sid=sid-0001
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	epochs := &fakeEpochReader{
		values:  map[int64]int64{42: 7}, // epoch 一致
		revoked: map[string]bool{"sid-0001": true},
	}
	v := newVerifierAt(tokens, epochs)

	_, err = v.Verify(ctx, tok)
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("err = %v, want ErrSessionRevoked", err)
	}
	if errors.Is(err, ErrSessionStale) || errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("revoked must not classify as stale/not-authenticated: %v", err)
	}
}

// TestVerifyStep3EpochReaderError 失效检查读取链故障 → 包装错误传播，
// 不与未登录 / 失效混同（基础设施错误语义）。
func TestVerifyStep3EpochReaderError(t *testing.T) {
	ctx := context.Background()
	tokens := NewTokens(newTestCodec(t))
	tok, err := tokens.Sign(testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	boom := errors.New("redis and db both down")
	v := newVerifierAt(tokens, &fakeEpochReader{err: boom})

	_, err = v.Verify(ctx, tok)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
	if errors.Is(err, ErrNotAuthenticated) || errors.Is(err, ErrSessionStale) || errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("infra failure must not classify as not-authenticated/stale/revoked: %v", err)
	}
}

// TestVerifyStep4Pass 步骤④：四步全过返回原载荷（uid/amr/sid 可用）。
func TestVerifyStep4Pass(t *testing.T) {
	ctx := context.Background()
	tokens := NewTokens(newTestCodec(t))
	want := testPayload()
	tok, err := tokens.Sign(want)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	v := newVerifierAt(tokens, &fakeEpochReader{values: map[int64]int64{42: 7}})

	got, err := v.Verify(ctx, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.GetId() != 42 || got.GetEpoch() != 7 || got.GetSid() != "sid-0001" {
		t.Fatalf("payload = %+v, want original", got)
	}
}

// TestVerifyEpochChainIntegration 双键一次读集成：Verifier 消费真实
// cache.EpochStore + fake redis——①缺失回源（MGET + SET、TTL 24h）
// ②Redis 命中不回源不写回（每请求固定 1 次 MGET，无本地缓存）。
func TestVerifyEpochChainIntegration(t *testing.T) {
	ctx := context.Background()
	tokens := NewTokens(newTestCodec(t))
	tok, err := tokens.Sign(testPayload()) // uid=42 epoch=7 sid=sid-0001
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cr := &countingRedis{}
	var srcCalls int
	src := func(ctx context.Context, uid int64) (int64, error) {
		srcCalls++
		return 7, nil
	}
	store := cache.NewEpochStore(cr, src)
	v := newVerifierAt(tokens, store)

	// ① 缺失 → 回源 + SET 新值（key=al:pwdep:42、TTL 24h）。
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("Verify #1: %v", err)
	}
	gets, mgets, sets := cr.counts()
	if gets != 0 || mgets != 1 || sets != 1 {
		t.Fatalf("redis gets=%d mgets=%d sets=%d, want 0/1/1（校验热路径只走 MGET）", gets, mgets, sets)
	}
	if len(cr.mgetKeys) != 1 || len(cr.mgetKeys[0]) != 2 ||
		cr.mgetKeys[0][0] != "al:pwdep:42" || cr.mgetKeys[0][1] != "al:sess:ev:sid-0001" {
		t.Fatalf("mget keys = %v, want [al:pwdep:42 al:sess:ev:sid-0001]", cr.mgetKeys)
	}
	if cr.setKeys[0] != "al:pwdep:42" {
		t.Fatalf("set key = %q, want al:pwdep:42", cr.setKeys[0])
	}
	if cr.setTTNs[0] != 24*time.Hour {
		t.Fatalf("set ttl = %v, want 24h", cr.setTTNs[0])
	}
	if srcCalls != 1 {
		t.Fatalf("source calls = %d, want 1", srcCalls)
	}

	// ② 第二次 Verify：无本地缓存，固定再走一次 MGET；Redis 命中（①已
	// 写回）→ 不回源、不写回。
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("Verify #2: %v", err)
	}
	gets, mgets, sets = cr.counts()
	if gets != 0 || mgets != 2 || sets != 1 {
		t.Fatalf("redis gets=%d mgets=%d sets=%d, want 0/2/1（热路径固定 1 次 MGET）", gets, mgets, sets)
	}
	if srcCalls != 1 {
		t.Fatalf("source calls = %d, want 1（MGET 命中不回源）", srcCalls)
	}
}

// TestVerifyFailOpenDegraded Command-level 故障 fail-open 集成：MGET
// 命令级故障（模拟 Redis down）→ 回源 DB 比对——DB 一致放行（revoked=
// false、不回写缓存）；DB 不一致 → ErrSessionStale。逐出状态无法判定，
// 按「未逐出」放行，不 500。
func TestVerifyFailOpenDegraded(t *testing.T) {
	ctx := context.Background()
	tokens := NewTokens(newTestCodec(t))
	tok, err := tokens.Sign(testPayload()) // uid=42 epoch=7
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// a) 回源一致 → 放行；故障路径不写回缓存。
	cr := &countingRedis{mgetErr: errors.New("redis down")}
	var srcCalls int
	src := func(ctx context.Context, uid int64) (int64, error) {
		srcCalls++
		return 7, nil
	}
	v := newVerifierAt(tokens, cache.NewEpochStore(cr, src))
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("Verify (fail-open, DB match): %v", err)
	}
	if srcCalls != 1 {
		t.Fatalf("source calls = %d, want 1（fail-open 回源）", srcCalls)
	}
	_, _, sets := cr.counts()
	if sets != 0 {
		t.Fatalf("sets = %d, want 0（故障路径不回写缓存）", sets)
	}

	// b) 回源不一致 → ErrSessionStale（fail-open 仍完成比对）。
	cr2 := &countingRedis{mgetErr: errors.New("redis down")}
	v2 := newVerifierAt(tokens, cache.NewEpochStore(cr2, func(ctx context.Context, uid int64) (int64, error) {
		return 8, nil
	}))
	if _, err := v2.Verify(ctx, tok); !errors.Is(err, ErrSessionStale) {
		t.Fatalf("err = %v, want ErrSessionStale（fail-open 回源比对生效）", err)
	}
}
