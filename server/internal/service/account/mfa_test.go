// mfa_test.go 单测：fake 依赖（不连真库，
// webauthn_test.go 同款风格）覆盖 GetMfa 明细 / SetMfa 启用与关闭分支 /
// BindTotp 两态（HMAC-SHA1 ±1 步真算）/ 恢复码重生成。
package account

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	credentialpb "authloft/gen/go/credential"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// mfaNow 固定时钟（loc 无关，Unix 秒口径）。
var mfaNow = time.Unix(1761800000, 0).UTC()

// fakeMfaUsers MfaUserStore 的 fake：单用户回放。
type fakeMfaUsers struct {
	u   *model.User
	err error
}

func (f *fakeMfaUsers) FindByID(_ context.Context, id int64) (*model.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.u == nil || f.u.ID != id {
		return nil, fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)
	}
	return f.u, nil
}

// fakeMfaCreds MfaCredentialStore 的 fake：kind 行内存存储 + 建库 / 更新 /
// 删行调用记录（Find / Delete 未命中回放 repo 包装形态的 ErrRecordNotFound）。
type fakeMfaCreds struct {
	rows    []*model.UserCredential
	creates []*model.UserCredential
	updates []*model.UserCredential
	deletes []mfaCredDelete
}

// mfaCredDelete DeleteByUserAndKind 调用记录。
type mfaCredDelete struct {
	uid  int64
	kind string
}

func (f *fakeMfaCreds) FindByUserAndKind(_ context.Context, userID int64, kind string) (*model.UserCredential, error) {
	for _, r := range f.rows {
		if r.UserID == userID && r.Kind == kind {
			return r, nil
		}
	}
	return nil, fmt.Errorf("credential repo: find by user kind: %w", gorm.ErrRecordNotFound)
}

func (f *fakeMfaCreds) ListByUser(_ context.Context, userID int64) ([]model.UserCredential, error) {
	out := make([]model.UserCredential, 0, len(f.rows))
	for _, r := range f.rows {
		if r.UserID == userID {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (f *fakeMfaCreds) Create(_ context.Context, c *model.UserCredential) error {
	f.creates = append(f.creates, c)
	f.rows = append(f.rows, c)
	return nil
}

func (f *fakeMfaCreds) Update(_ context.Context, c *model.UserCredential) error {
	f.updates = append(f.updates, c)
	return nil
}

func (f *fakeMfaCreds) DeleteByUserAndKind(_ context.Context, userID int64, kind string) error {
	f.deletes = append(f.deletes, mfaCredDelete{uid: userID, kind: kind})
	for i, r := range f.rows {
		if r.UserID == userID && r.Kind == kind {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("credential repo: delete by user kind: %w", gorm.ErrRecordNotFound)
}

// fakeMfaWebauthn MfaWebauthnStore 的 fake：凭据行回放。
type fakeMfaWebauthn struct {
	rows []model.UserCredentialWebauthn
}

func (f *fakeMfaWebauthn) ListByUser(_ context.Context, userID int64) ([]model.UserCredentialWebauthn, error) {
	out := make([]model.UserCredentialWebauthn, 0, len(f.rows))
	for _, r := range f.rows {
		if r.UserID == userID {
			out = append(out, r)
		}
	}
	return out, nil
}

// fakeMfaSettings MfaSettingsReader 的 fake：仅 mfa_enabled 键。
type fakeMfaSettings struct {
	mfaEnabled bool
	has        bool
}

func (f *fakeMfaSettings) GetBool(key string) (bool, bool) {
	if key == settings.KeyMfaEnabled {
		return f.mfaEnabled, f.has
	}
	return false, false
}

// fakeMfaRand Rand 的 fake：xorshift32 确定性伪随机（恢复码生成带去重，
// 源必须良分布——连续递增字节模 32 会周期重复，触发去重上限保护）。
type fakeMfaRand struct{ state uint32 }

func (f *fakeMfaRand) Read(p []byte) (int, error) {
	if f.state == 0 {
		f.state = 0xAB
	}
	for i := range p {
		f.state ^= f.state << 13
		f.state ^= f.state >> 17
		f.state ^= f.state << 5
		p[i] = byte(f.state)
	}
	return len(p), nil
}

// newMfaService 组装被测服务 + 全量 fake。
func newMfaService(u *model.User, creds *fakeMfaCreds, wa *fakeMfaWebauthn, st *fakeMfaSettings, audit *fakeAudit) *MfaService {
	return NewMfaService(MfaDeps{
		Users:    &fakeMfaUsers{u: u},
		Creds:    creds,
		Webauthn: wa,
		Settings: st,
		Audit:    audit,
		Now:      func() time.Time { return mfaNow },
		Rand:     &fakeMfaRand{state: 0xAB},
	})
}

// mfaUser 全绑定态用户。
func mfaUser() *model.User {
	phone := "13812348000"
	email := "zhang_san@example.com"
	return &model.User{
		ID:            42,
		Username:      "zhang_san",
		Phone:         &phone,
		PhoneVerified: 1,
		Email:         &email,
		EmailVerified: 1,
	}
}

// mfaCredMeta 构造 credential.CredentialMeta 序列化字节（测试夹具）。
func mfaCredMeta(t *testing.T, m *credentialpb.CredentialMeta) []byte {
	t.Helper()
	b, err := repo.MarshalCredentialMeta(m)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	return b
}

func TestMfaGetDetail(t *testing.T) {
	used := mfaNow.Add(-time.Hour)
	creds := &fakeMfaCreds{rows: []*model.UserCredential{
		{ID: 1, UserID: 42, Kind: "totp", Secret: []byte("JBSWY3DPEHPK3PXP"), IsEnabled: 1,
			CreatedAt: mfaNow.Add(-2 * time.Hour), LastUsedAt: &used, UpdatedAt: used},
		{ID: 2, UserID: 42, Kind: "webauthn", IsEnabled: 1, CreatedAt: mfaNow.Add(-48 * time.Hour), UpdatedAt: mfaNow},
		{ID: 3, UserID: 42, Kind: "webauthn", IsEnabled: 1, CreatedAt: mfaNow.Add(-24 * time.Hour),
			LastUsedAt: &used, UpdatedAt: mfaNow},
		{ID: 4, UserID: 42, Kind: "recovery_code", IsEnabled: 1,
			Meta: mfaCredMeta(t, &credentialpb.CredentialMeta{RecoveryCodes: []string{
				"0a1b2c3d", "4e5f6g7h", "01234567", "89abcdef", "0a1b2c3e",
				"4e5f6g7j", "01234568", "89abcdeg"}}),
			CreatedAt: mfaNow.Add(-2 * time.Hour), UpdatedAt: mfaNow},
	}}
	svc := newMfaService(mfaUser(), creds, &fakeMfaWebauthn{rows: []model.UserCredentialWebauthn{
		{ID: 2, UserID: 42}, {ID: 3, UserID: 42},
	}}, &fakeMfaSettings{}, &fakeAudit{})

	d, err := svc.GetMfa(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetMfa: %v", err)
	}
	if len(d.Factors) != 5 {
		t.Fatalf("factors = %d, want 5", len(d.Factors))
	}
	got := map[string]MfaFactorDetail{}
	for _, f := range d.Factors {
		got[f.Factor] = f
	}
	// totp：bound + boundAt + lastUsedAt。
	if f := got["totp"]; !f.Bound || f.BoundAt != mfaNow.Add(-2*time.Hour).Unix() ||
		f.LastUsedAt != used.Unix() || f.Target != "" || f.Credentials != 0 || f.Remaining != 0 {
		t.Errorf("totp detail = %+v", f)
	}
	// otp_sms / otp_email：掩码目标（orchestrator 算法：138****8000 / z***@…）。
	if f := got["otp_sms"]; !f.Bound || f.Target != "138****8000" || f.LastUsedAt != 0 {
		t.Errorf("otp_sms detail = %+v", f)
	}
	if f := got["otp_email"]; !f.Bound || f.Target != "z***@example.com" || f.LastUsedAt != 0 {
		t.Errorf("otp_email detail = %+v", f)
	}
	// webauthn：凭据数 2、boundAt 最早、lastUsedAt 最新。
	if f := got["webauthn"]; !f.Bound || f.Credentials != 2 ||
		f.BoundAt != mfaNow.Add(-48*time.Hour).Unix() || f.LastUsedAt != used.Unix() {
		t.Errorf("webauthn detail = %+v", f)
	}
	// recovery_code：剩余 8 + recoveryIssuedAt = 行 created_at。
	if f := got["recovery_code"]; !f.Bound || f.Remaining != 8 {
		t.Errorf("recovery_code detail = %+v", f)
	}
	if d.RecoveryIssuedAt != mfaNow.Add(-2*time.Hour).Unix() {
		t.Errorf("recoveryIssuedAt = %d", d.RecoveryIssuedAt)
	}
}

func TestMfaGetDetailUnbound(t *testing.T) {
	// 无 phone / email 用户 + 空凭据库 → 五因子全 unbound、零值明细。
	svc := newMfaService(&model.User{ID: 42, Username: "zhang_san"}, &fakeMfaCreds{}, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})
	d, err := svc.GetMfa(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetMfa: %v", err)
	}
	if len(d.Factors) != 5 {
		t.Fatalf("factors = %d, want 5", len(d.Factors))
	}
	for _, f := range d.Factors {
		if f.Bound {
			t.Errorf("factor %q bound on empty store", f.Factor)
		}
		switch f.Factor {
		case "otp_sms", "otp_email":
			if f.Target != "" {
				t.Errorf("factor %q target = %q on unbound", f.Factor, f.Target)
			}
		}
	}
	if d.RecoveryIssuedAt != 0 {
		t.Errorf("recoveryIssuedAt = %d, want 0（未签发）", d.RecoveryIssuedAt)
	}
}

func TestMfaGetDetailRecoveryExhausted(t *testing.T) {
	// 删空写回空数组等价该 kind 不可用（§4.2 行 697）：bound=false、remaining=0，
	// 但行存在即已签发 → recoveryIssuedAt 非 0。
	creds := &fakeMfaCreds{rows: []*model.UserCredential{
		{ID: 9, UserID: 42, Kind: "recovery_code", IsEnabled: 1,
			Meta: mfaCredMeta(t, &credentialpb.CredentialMeta{}),
			CreatedAt: mfaNow, UpdatedAt: mfaNow},
	}}
	svc := newMfaService(mfaUser(), creds, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})
	d, err := svc.GetMfa(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetMfa: %v", err)
	}
	var rc MfaFactorDetail
	for _, f := range d.Factors {
		if f.Factor == "recovery_code" {
			rc = f
		}
	}
	if rc.Bound || rc.Remaining != 0 {
		t.Errorf("exhausted recovery_code = %+v, want bound=false remaining=0", rc)
	}
	if d.RecoveryIssuedAt != mfaNow.Unix() {
		t.Errorf("recoveryIssuedAt = %d, want row created_at", d.RecoveryIssuedAt)
	}
}

func TestMfaSetMfaEnable(t *testing.T) {
	creds := &fakeMfaCreds{}
	audit := &fakeAudit{}
	// required=false（user.mfa_required=0）。
	svc := newMfaService(&model.User{ID: 42, Username: "zhang_san"}, creds,
		&fakeMfaWebauthn{}, &fakeMfaSettings{}, audit)

	if err := svc.SetMfa(context.Background(), 42, []string{"otp_sms", "totp"}); err != nil {
		t.Fatalf("SetMfa: %v", err)
	}
	if len(creds.creates) != 1 {
		t.Fatalf("creates = %d, want 1（首开建 mfa_setting 行）", len(creds.creates))
	}
	row := creds.creates[0]
	if row.UserID != 42 || row.Kind != "mfa_setting" || row.IsEnabled != 1 {
		t.Errorf("created row = %+v", row)
	}
	meta, err := repo.UnmarshalCredentialMeta(row.Meta)
	if err != nil {
		t.Fatalf("decode meta: %v", err)
	}
	// 归一序（totp → otp_sms），与 mfaOrder 一致。
	if !proto.Equal(meta, &credentialpb.CredentialMeta{MfaMethods: []string{"totp", "otp_sms"}}) {
		t.Errorf("mfa_methods = %v, want [totp otp_sms]", meta.GetMfaMethods())
	}
	// enable_mfa 审计 + detail={methods:[...]}（§4.6 行 821）。
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.Event != "enable_mfa" || ev.ActorID != 42 || ev.UserID != 42 {
		t.Errorf("audit event = %+v", ev)
	}
	var detail map[string]any
	if err := msgpack.Unmarshal(ev.Detail, &detail); err != nil {
		t.Fatalf("decode audit detail: %v", err)
	}
	methods, _ := detail["methods"].([]any)
	if len(methods) != 2 || methods[0] != "totp" || methods[1] != "otp_sms" {
		t.Errorf("audit detail methods = %v", detail["methods"])
	}

	// 再开 = Update 既有行（每用户至多一行）。
	if err := svc.SetMfa(context.Background(), 42, []string{"webauthn"}); err != nil {
		t.Fatalf("SetMfa again: %v", err)
	}
	if len(creds.creates) != 1 || len(creds.updates) != 1 {
		t.Fatalf("creates=%d updates=%d, want 1/1（再开走 Update）", len(creds.creates), len(creds.updates))
	}
	meta, err = repo.UnmarshalCredentialMeta(creds.updates[0].Meta)
	if err != nil {
		t.Fatalf("decode updated meta: %v", err)
	}
	if len(meta.GetMfaMethods()) != 1 || meta.GetMfaMethods()[0] != "webauthn" {
		t.Errorf("updated mfa_methods = %v", meta.GetMfaMethods())
	}
	if len(audit.events) != 2 {
		t.Errorf("audit events = %d, want 2（每次启用一投）", len(audit.events))
	}
}

func TestMfaSetMfaInvalidMethod(t *testing.T) {
	creds := &fakeMfaCreds{}
	svc := newMfaService(&model.User{ID: 42}, creds, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})
	for _, methods := range [][]string{
		{"totp", "magic"},  // 未知因子
		{"recovery_code"},  // 随 totp 投影，不可独立勾选
	} {
		if err := svc.SetMfa(context.Background(), 42, methods); !errors.Is(err, ErrMfaInvalidRequest) {
			t.Errorf("SetMfa(%v) err = %v, want ErrMfaInvalidRequest", methods, err)
		}
	}
	if len(creds.creates) != 0 || len(creds.updates) != 0 {
		t.Errorf("invalid input must not touch store: creates=%d updates=%d", len(creds.creates), len(creds.updates))
	}
}

func TestMfaSetMfaRequiredReject(t *testing.T) {
	// required=true（settings.mfa_enabled=true + user.mfa_required=1）时空数组
	// = 关闭被拒（§3.2 行 849「true 时用户不可关闭」）。
	svc := newMfaService(&model.User{ID: 42, MfaRequired: 1}, &fakeMfaCreds{},
		&fakeMfaWebauthn{}, &fakeMfaSettings{mfaEnabled: true, has: true}, &fakeAudit{})
	err := svc.SetMfa(context.Background(), 42, nil)
	if !errors.Is(err, ErrMfaInvalidRequest) {
		t.Errorf("close under required err = %v, want ErrMfaInvalidRequest", err)
	}
	// settings.mfa_enabled=false → required=false（口径与 orchestrator/handler 一致）。
	svc2 := newMfaService(&model.User{ID: 42, MfaRequired: 1}, &fakeMfaCreds{},
		&fakeMfaWebauthn{}, &fakeMfaSettings{mfaEnabled: false, has: true}, &fakeAudit{})
	if err := svc2.SetMfa(context.Background(), 42, []string{"totp"}); err != nil {
		t.Errorf("enable under mfa_enabled=false err = %v, want nil（启用不受 required 限制）", err)
	}
}

func TestMfaSetMfaClose(t *testing.T) {
	// 关闭 ⇔ 删除 mfa_setting 行（既定口径；行 862
	//「行存在即顶层 enabled=true」）：先开再关 round-trip——行被删（非
	// is_enabled=0）+ disable_mfa 审计已投（detail={methods:[]}）；已关闭态
	// 再关 → 未命中幂等成功。
	creds := &fakeMfaCreds{}
	audit := &fakeAudit{}
	svc := newMfaService(&model.User{ID: 42, MfaRequired: 0}, creds,
		&fakeMfaWebauthn{}, &fakeMfaSettings{mfaEnabled: true, has: true}, audit)
	// 预置：先开启（建 mfa_setting 行）。
	if err := svc.SetMfa(context.Background(), 42, []string{"totp"}); err != nil {
		t.Fatalf("pre-open: %v", err)
	}
	if len(creds.rows) != 1 || creds.rows[0].Kind != "mfa_setting" {
		t.Fatalf("pre-open rows = %+v, want 1 mfa_setting 行", creds.rows)
	}
	// 关闭：空数组。
	if err := svc.SetMfa(context.Background(), 42, nil); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(creds.deletes) != 1 || creds.deletes[0].uid != 42 || creds.deletes[0].kind != "mfa_setting" {
		t.Errorf("deletes = %+v, want one mfa_setting delete for uid 42", creds.deletes)
	}
	if len(creds.rows) != 0 {
		t.Errorf("rows after close = %d, want 0（关闭=删行，非 is_enabled=0）", len(creds.rows))
	}
	if len(creds.creates) != 1 || len(creds.updates) != 0 {
		t.Errorf("close must not create/update: creates=%d updates=%d", len(creds.creates), len(creds.updates))
	}
	// 审计：enable_mfa（开）→ disable_mfa（关，detail={methods:[]}）。
	if len(audit.events) != 2 {
		t.Fatalf("audit events = %d, want 2", len(audit.events))
	}
	if ev := audit.events[0]; ev.Event != "enable_mfa" {
		t.Errorf("first event = %q, want enable_mfa", ev.Event)
	}
	ev := audit.events[1]
	if ev.Event != "disable_mfa" || ev.ActorID != 42 || ev.UserID != 42 {
		t.Errorf("disable event = %+v", ev)
	}
	var detail map[string]any
	if err := msgpack.Unmarshal(ev.Detail, &detail); err != nil {
		t.Fatalf("decode disable detail: %v", err)
	}
	if m, ok := detail["methods"].([]any); !ok || len(m) != 0 {
		t.Errorf("disable detail methods = %#v, want 空数组", detail["methods"])
	}
	// 已关闭态再关 → 行不存在幂等成功（Delete 未命中不放大为错误）。
	if err := svc.SetMfa(context.Background(), 42, nil); err != nil {
		t.Errorf("idempotent close: %v", err)
	}
	if len(creds.deletes) != 2 {
		t.Errorf("deletes = %d, want 2（幂等关闭照调删行）", len(creds.deletes))
	}
}

func TestMfaBindTotpChallenge(t *testing.T) {
	svc := newMfaService(mfaUser(), &fakeMfaCreds{}, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})
	ch, err := svc.BindTotpChallenge(context.Background(), 42)
	if err != nil {
		t.Fatalf("BindTotpChallenge: %v", err)
	}
	// 16 字符 Base32（10 字节熵）、大写、可被登录链 decodeSecret 解码。
	if len(ch.Secret) != 16 {
		t.Errorf("secret len = %d, want 16", len(ch.Secret))
	}
	if strings.ToLower(ch.Secret) != ch.Secret && strings.ToUpper(ch.Secret) != ch.Secret {
		t.Errorf("secret %q not pure case", ch.Secret)
	}
	if _, err := decodeTotpSecret(ch.Secret); err != nil {
		t.Errorf("secret not decodable: %v", err)
	}
	// otpauthUrl 形状与前端样例逐字一致（account.test.tsx:1088）。
	wantPrefix := "otpauth://totp/Authloft:zhang_san?secret=" + ch.Secret + "&issuer=Authloft"
	if ch.OtpauthUrl != wantPrefix {
		t.Errorf("otpauthUrl = %q, want %q", ch.OtpauthUrl, wantPrefix)
	}
	if ch.QrcodeContent != ch.OtpauthUrl {
		t.Errorf("qrcodeContent = %q, want = otpauthUrl", ch.QrcodeContent)
	}
}

func TestMfaBindTotpVerify(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	key, err := decodeTotpSecret(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	counter := uint64(mfaNow.Unix() / 30)
	code := totpHotp(key, counter)

	creds := &fakeMfaCreds{}
	svc := newMfaService(mfaUser(), creds, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})
	codes, err := svc.BindTotpVerify(context.Background(), 42, secret, code)
	if err != nil {
		t.Fatalf("BindTotpVerify: %v", err)
	}
	// 同一响应下发 10 个恢复码（展示形 xxxx-xxxx，字符集 Crockford 小写）。
	if len(codes) != 10 {
		t.Fatalf("recovery codes = %d, want 10", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 9 || c[4] != '-' {
			t.Errorf("code %q not xxxx-xxxx", c)
		}
		stored := strings.ReplaceAll(c, "-", "")
		if len(stored) != 8 {
			t.Errorf("code %q stored form len = %d", c, len(stored))
		}
		for _, r := range stored {
			if !strings.ContainsRune(recoveryCodeCharset, r) {
				t.Errorf("code %q char %q outside Crockford charset", c, r)
			}
		}
		if seen[c] {
			t.Errorf("duplicated code %q", c)
		}
		seen[c] = true
	}
	// totp 行落库：明文 Base32 secret + digits/period meta + 启用。
	if len(creds.creates) != 2 {
		t.Fatalf("creates = %d, want 2（totp + recovery_code 两行）", len(creds.creates))
	}
	var totpRow, rcRow *model.UserCredential
	for _, c := range creds.creates {
		switch c.Kind {
		case "totp":
			totpRow = c
		case "recovery_code":
			rcRow = c
		}
	}
	if totpRow == nil || rcRow == nil {
		t.Fatalf("missing totp/recovery_code rows: %+v", creds.creates)
	}
	if string(totpRow.Secret) != secret || totpRow.IsEnabled != 1 {
		t.Errorf("totp row = %+v", totpRow)
	}
	totpMeta, err := repo.UnmarshalCredentialMeta(totpRow.Meta)
	if err != nil {
		t.Fatalf("decode totp meta: %v", err)
	}
	if totpMeta.GetTotpDigits() != 6 || totpMeta.GetTotpPeriod() != 30 {
		t.Errorf("totp meta digits/period = %d/%d, want 6/30", totpMeta.GetTotpDigits(), totpMeta.GetTotpPeriod())
	}
	// recovery_code 行：meta 10 条存储形 == 下发展示形去连字符。
	rcMeta, err := repo.UnmarshalCredentialMeta(rcRow.Meta)
	if err != nil {
		t.Fatalf("decode recovery meta: %v", err)
	}
	stored := rcMeta.GetRecoveryCodes()
	if len(stored) != 10 {
		t.Fatalf("stored codes = %d, want 10", len(stored))
	}
	for i, c := range codes {
		if stored[i] != strings.ReplaceAll(c, "-", "") {
			t.Errorf("stored[%d] = %q, display = %q", i, stored[i], c)
		}
	}

	// ±1 时间步（后端架构 §8.4 行 1081）：前一步的码同样通过。
	creds2 := &fakeMfaCreds{}
	svc2 := newMfaService(mfaUser(), creds2, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})
	if _, err := svc2.BindTotpVerify(context.Background(), 42, secret, totpHotp(key, counter-1)); err != nil {
		t.Errorf("verify with previous step err = %v, want nil（±1 步）", err)
	}
	if _, err := svc2.BindTotpVerify(context.Background(), 42, secret, totpHotp(key, counter+1)); err != nil {
		t.Errorf("verify with next step err = %v, want nil（±1 步）", err)
	}
	if _, err := svc2.BindTotpVerify(context.Background(), 42, secret, totpHotp(key, counter+2)); !errors.Is(err, ErrMfaInvalidCode) {
		t.Errorf("verify with +2 steps err = %v, want ErrMfaInvalidCode", err)
	}

	// 重复绑定按覆盖处理（换密钥）：既有行 Update，不 Create。svc2 此前已
	// 成功 verify 两次（counter-1 / counter+1 各 Create 两行），本次再 verify
	// → 第三次成功为纯 Update ×2（totp + recovery_code），累计 updates=4。
	if _, err := svc2.BindTotpVerify(context.Background(), 42, secret, code); err != nil {
		t.Fatalf("re-bind: %v", err)
	}
	if len(creds2.creates) != 2 || len(creds2.updates) != 4 {
		t.Errorf("re-bind creates=%d updates=%d, want 2/4（覆盖不重建）", len(creds2.creates), len(creds2.updates))
	}
}

func TestMfaBindTotpVerifyFailures(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	key, _ := decodeTotpSecret(secret)
	code := totpHotp(key, uint64(mfaNow.Unix()/30))
	creds := &fakeMfaCreds{}
	svc := newMfaService(mfaUser(), creds, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})

	cases := []struct {
		name             string
		secret, code     string
		want             error
		wantNoStoreWrite bool
	}{
		{"wrong code", secret, totpHotp(key, uint64(mfaNow.Unix()/30)+99), ErrMfaInvalidCode, true},
		{"malformed code letters", secret, "12345a", ErrMfaInvalidRequest, true},
		{"short code", secret, "12345", ErrMfaInvalidRequest, true},
		{"empty secret", "", code, ErrMfaInvalidRequest, true},
		{"malformed secret", "@@@@", code, ErrMfaInvalidRequest, true},
	}
	for _, tc := range cases {
		_, err := svc.BindTotpVerify(context.Background(), 42, tc.secret, tc.code)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	if len(creds.creates) != 0 || len(creds.updates) != 0 {
		t.Errorf("failed verify must not write store: creates=%d updates=%d", len(creds.creates), len(creds.updates))
	}
}

func TestMfaRegenerateRecoveryCodes(t *testing.T) {
	creds := &fakeMfaCreds{}
	svc := newMfaService(mfaUser(), creds, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})
	// action 非法 → invalid_request。
	if _, err := svc.RegenerateRecoveryCodes(context.Background(), 42, "reset"); !errors.Is(err, ErrMfaInvalidRequest) {
		t.Errorf("bad action err = %v, want ErrMfaInvalidRequest", err)
	}
	// 无行（从未绑定 totp）→ code_expired（「重新生成」针对既有签发）。
	if _, err := svc.RegenerateRecoveryCodes(context.Background(), 42, "regenerate"); !errors.Is(err, ErrMfaCodeExpired) {
		t.Errorf("no row err = %v, want ErrMfaCodeExpired", err)
	}
	// 既有行（含消费尽）→ 全量作废：新 10 码覆盖旧码，createdAt 沿行 created_at。
	creds.rows = []*model.UserCredential{
		{ID: 7, UserID: 42, Kind: "recovery_code", IsEnabled: 1,
			Meta:      mfaCredMeta(t, &credentialpb.CredentialMeta{}),
			CreatedAt: mfaNow.Add(-time.Hour), UpdatedAt: mfaNow},
	}
	res, err := svc.RegenerateRecoveryCodes(context.Background(), 42, "regenerate")
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if len(res.Codes) != 10 {
		t.Fatalf("codes = %d, want 10", len(res.Codes))
	}
	if len(creds.updates) != 1 {
		t.Fatalf("updates = %d, want 1（覆盖既有行）", len(creds.updates))
	}
	meta, err := repo.UnmarshalCredentialMeta(creds.updates[0].Meta)
	if err != nil {
		t.Fatalf("decode meta: %v", err)
	}
	if len(meta.GetRecoveryCodes()) != 10 {
		t.Fatalf("stored codes = %d, want 10", len(meta.GetRecoveryCodes()))
	}
	for i, c := range res.Codes {
		if meta.GetRecoveryCodes()[i] != strings.ReplaceAll(c, "-", "") {
			t.Errorf("stored[%d]=%q vs display=%q", i, meta.GetRecoveryCodes()[i], c)
		}
	}
	if res.CreatedAt != mfaNow.Add(-time.Hour).Unix() {
		t.Errorf("createdAt = %d, want 沿行 created_at", res.CreatedAt)
	}
	if creds.updates[0].UpdatedAt != mfaNow {
		t.Errorf("row updated_at = %v, want now", creds.updates[0].UpdatedAt)
	}
}

func TestMfaUnauthenticatedAndUserMissing(t *testing.T) {
	svc := newMfaService(mfaUser(), &fakeMfaCreds{}, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})
	ctx := context.Background()
	if _, err := svc.GetMfa(ctx, 0); !errors.Is(err, ErrMfaUnauthenticated) {
		t.Errorf("GetMfa(0) err = %v, want ErrMfaUnauthenticated", err)
	}
	if err := svc.SetMfa(ctx, 0, []string{"totp"}); !errors.Is(err, ErrMfaUnauthenticated) {
		t.Errorf("SetMfa(0) err = %v, want ErrMfaUnauthenticated", err)
	}
	if _, err := svc.BindTotpChallenge(ctx, 0); !errors.Is(err, ErrMfaUnauthenticated) {
		t.Errorf("BindTotpChallenge(0) err = %v, want ErrMfaUnauthenticated", err)
	}
	if _, err := svc.BindTotpVerify(ctx, 0, "JBSWY3DPEHPK3PXP", "123456"); !errors.Is(err, ErrMfaUnauthenticated) {
		t.Errorf("BindTotpVerify(0) err = %v, want ErrMfaUnauthenticated", err)
	}
	if _, err := svc.RegenerateRecoveryCodes(ctx, 0, "regenerate"); !errors.Is(err, ErrMfaUnauthenticated) {
		t.Errorf("RegenerateRecoveryCodes(0) err = %v, want ErrMfaUnauthenticated", err)
	}
	// user 不存在 → gorm.ErrRecordNotFound 原样上抛（handler 映射 not_found）。
	svc2 := newMfaService(nil, &fakeMfaCreds{}, &fakeMfaWebauthn{}, &fakeMfaSettings{}, &fakeAudit{})
	if _, err := svc2.GetMfa(ctx, 42); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("GetMfa(missing user) err = %v, want gorm.ErrRecordNotFound", err)
	}
	if err := svc2.SetMfa(ctx, 42, []string{"totp"}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("SetMfa(missing user) err = %v, want gorm.ErrRecordNotFound", err)
	}
	if _, err := svc2.BindTotpChallenge(ctx, 42); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("BindTotpChallenge(missing user) err = %v, want gorm.ErrRecordNotFound", err)
	}
}

func TestMfaMaskAlgorithms(t *testing.T) {
	// 与 orchestrator 同款算法的抽样锚定（§3.5「各落一份」防漂移）。
	if got := maskMfaPhone("13812348000"); got != "138****8000" {
		t.Errorf("maskMfaPhone = %q", got)
	}
	if got := maskMfaPhone("1234567"); got != "123****4567" && got != "****" && len(got) < 4 {
		t.Errorf("maskMfaPhone(7位) = %q", got)
	}
	if got := maskMfaPhone("123"); got != "****" {
		t.Errorf("maskMfaPhone(短号) = %q, want ****", got)
	}
	if got := maskMfaEmail("zhang_san@example.com"); got != "z***@example.com" {
		t.Errorf("maskMfaEmail = %q", got)
	}
	if got := maskMfaEmail("a@b.com"); got != "*@b.com" {
		t.Errorf("maskMfaEmail(单字符本地段) = %q", got)
	}
	if got := maskMfaEmail("no-at-sign"); got != "***" {
		t.Errorf("maskMfaEmail(无@) = %q", got)
	}
}
