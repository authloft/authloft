// mfa_test.go 单测：fake 依赖（不连真库，
// webauthn_test.go 同款风格）覆盖 GetMfa 明细 / SetMfa 启用与关闭分支 /
// BindTotp 两态（HMAC-SHA1 ±1 步真算）/ 恢复码重生成。
package account

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"gorm.io/gorm"

	credentialpb "authloft/gen/go/credential"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/verification"
	"authloft/internal/settings"
)

// mfaNow 固定时钟（loc 无关，Unix 秒口径）。
var mfaNow = time.Unix(1761800000, 0).UTC()

// fakeMfaUsers MfaUserStore 的 fake：单用户回放 + mfa_required 写入记录。
type fakeMfaUsers struct {
	u       *model.User
	err     error
	updates []int8 // UpdateMfaRequired 入参序列
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

func (f *fakeMfaUsers) UpdateMfaRequired(_ context.Context, id int64, v int8) error {
	if f.err != nil {
		return f.err
	}
	if f.u == nil || f.u.ID != id {
		return fmt.Errorf("user repo: update mfa required: %w", gorm.ErrRecordNotFound)
	}
	f.updates = append(f.updates, v)
	f.u.MfaRequired = v
	return nil
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

// fakeMfaSettings MfaSettingsReader 的 fake：mfa_enabled 与 mfa_methods 两键。
type fakeMfaSettings struct {
	mfaEnabled bool
	has        bool
	methods    []string
	methodsHas bool
}

func (f *fakeMfaSettings) GetBool(key string) (bool, bool) {
	if key == settings.KeyMfaEnabled {
		return f.mfaEnabled, f.has
	}
	return false, false
}

func (f *fakeMfaSettings) GetStringSlice(key string) ([]string, bool) {
	if key == settings.KeyMfaMethods {
		return f.methods, f.methodsHas
	}
	return nil, false
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
			Meta:      mfaCredMeta(t, &credentialpb.CredentialMeta{}),
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

// mfaSettingsOn mfa_enabled=true + 指定白名单的 settings fake。
func mfaSettingsOn(methods ...string) *fakeMfaSettings {
	return &fakeMfaSettings{mfaEnabled: true, has: true, methods: methods, methodsHas: true}
}

// newMfaServiceWithUsers 需要断言 mfa_required 写入时显式持有 fakeMfaUsers。
func newMfaServiceWithUsers(u *model.User, users *fakeMfaUsers, creds *fakeMfaCreds,
	st *fakeMfaSettings, audit *fakeAudit) *MfaService {
	return NewMfaService(MfaDeps{
		Users:    users,
		Creds:    creds,
		Webauthn: &fakeMfaWebauthn{},
		Settings: st,
		Audit:    audit,
		Now:      func() time.Time { return mfaNow },
		Rand:     &fakeMfaRand{state: 0xAB},
	})
}

func TestMfaSetMfaEnable(t *testing.T) {
	// 白名单 totp + 已绑定 totp 行 → 允许开启，只写 user.mfa_required=1。
	creds := &fakeMfaCreds{rows: []*model.UserCredential{
		{ID: 1, UserID: 42, Kind: kindTotp, IsEnabled: 1},
	}}
	users := &fakeMfaUsers{u: &model.User{ID: 42, Username: "zhang_san"}}
	audit := &fakeAudit{}
	svc := newMfaServiceWithUsers(users.u, users, creds, mfaSettingsOn("totp", "webauthn"), audit)

	if err := svc.SetMfa(context.Background(), 42, true); err != nil {
		t.Fatalf("SetMfa(true): %v", err)
	}
	if len(users.updates) != 1 || users.updates[0] != 1 {
		t.Fatalf("mfa_required updates = %v, want [1]", users.updates)
	}
	if len(creds.creates) != 0 || len(creds.updates) != 0 || len(creds.deletes) != 0 {
		t.Errorf("开关切换不得触碰凭证: creates=%d updates=%d deletes=%d",
			len(creds.creates), len(creds.updates), len(creds.deletes))
	}
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
	if v, ok := detail["enabled"].(bool); !ok || !v {
		t.Errorf("audit detail enabled = %#v, want true", detail["enabled"])
	}
}

func TestMfaSetMfaEnableRejected(t *testing.T) {
	cases := []struct {
		name     string
		settings *fakeMfaSettings
		creds    *fakeMfaCreds
	}{
		{"白名单为空", &fakeMfaSettings{mfaEnabled: true, has: true}, &fakeMfaCreds{rows: []*model.UserCredential{
			{UserID: 42, Kind: kindTotp, IsEnabled: 1},
		}}},
		{"白名单内因子未绑定", mfaSettingsOn("totp"), &fakeMfaCreds{}},
		{"系统总开关关闭", &fakeMfaSettings{mfaEnabled: false, has: true, methods: []string{"totp"}, methodsHas: true},
			&fakeMfaCreds{rows: []*model.UserCredential{{UserID: 42, Kind: kindTotp, IsEnabled: 1}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			users := &fakeMfaUsers{u: &model.User{ID: 42, Username: "zhang_san"}}
			svc := newMfaServiceWithUsers(users.u, users, tc.creds, tc.settings, &fakeAudit{})
			if err := svc.SetMfa(context.Background(), 42, true); !errors.Is(err, ErrMfaInvalidRequest) {
				t.Fatalf("SetMfa(true) err = %v, want ErrMfaInvalidRequest", err)
			}
			if len(users.updates) != 0 {
				t.Errorf("被拒不得写 mfa_required: %v", users.updates)
			}
		})
	}
}

func TestMfaSetMfaDisable(t *testing.T) {
	// 关闭不校验可用因子：即便白名单为空也直接写 0。
	creds := &fakeMfaCreds{}
	users := &fakeMfaUsers{u: &model.User{ID: 42, MfaRequired: 1}}
	audit := &fakeAudit{}
	svc := newMfaServiceWithUsers(users.u, users, creds, &fakeMfaSettings{}, audit)

	if err := svc.SetMfa(context.Background(), 42, false); err != nil {
		t.Fatalf("SetMfa(false): %v", err)
	}
	if len(users.updates) != 1 || users.updates[0] != 0 {
		t.Fatalf("mfa_required updates = %v, want [0]", users.updates)
	}
	if len(creds.deletes) != 0 {
		t.Errorf("关闭不得删除凭证行: %+v", creds.deletes)
	}
	if len(audit.events) != 1 || audit.events[0].Event != "disable_mfa" {
		t.Fatalf("audit events = %+v, want disable_mfa", audit.events)
	}
	var detail map[string]any
	if err := msgpack.Unmarshal(audit.events[0].Detail, &detail); err != nil {
		t.Fatalf("decode disable detail: %v", err)
	}
	if v, ok := detail["enabled"].(bool); !ok || v {
		t.Errorf("audit detail enabled = %#v, want false", detail["enabled"])
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
	if err := svc.SetMfa(ctx, 0, true); !errors.Is(err, ErrMfaUnauthenticated) {
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
	if err := svc2.SetMfa(ctx, 42, true); !errors.Is(err, gorm.ErrRecordNotFound) {
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

// fakeAssertions AssertionConsumer 的 fake：记录入参并回放结论。
type fakeAssertions struct {
	err   error
	token string
	want  verification.Want
	calls int
}

func (f *fakeAssertions) ConsumeAssertion(_ context.Context, token string, want verification.Want) (verification.Assertion, error) {
	f.calls++
	f.token = token
	f.want = want
	return verification.Assertion{}, f.err
}

// TestUnbindTotpConsumesAssertionAndDeletes 覆盖 §3.5 / §16 的解绑口径：
// 断言三重校验由消费出口负责，通过后删除 kind=totp 并作废恢复码；同一断言
// 二次提交因凭据已删返回 verification_invalid（低风险不加 al:once）。
func TestUnbindTotpConsumesAssertionAndDeletes(t *testing.T) {
	creds := &fakeMfaCreds{rows: []*model.UserCredential{
		{UserID: 42, Kind: kindTotp},
		{UserID: 42, Kind: kindRecoveryCode},
	}}
	assertions := &fakeAssertions{}
	svc := NewMfaService(MfaDeps{Creds: creds, Assertions: assertions})

	if err := svc.UnbindTotp(context.Background(), 42, "vt-1"); err != nil {
		t.Fatalf("UnbindTotp: %v", err)
	}
	if assertions.calls != 1 || assertions.token != "vt-1" {
		t.Fatalf("断言消费入参 = token %q calls %d", assertions.token, assertions.calls)
	}
	want := assertions.want
	if want.BizPurpose != verification.BizPurposeUnbindTOTP || want.Operation != "unbind_totp" ||
		want.Subject != (verification.Subject{Kind: verification.SubjectKindUID, ID: "42"}) {
		t.Fatalf("Want = %+v", want)
	}
	if len(creds.deletes) != 2 || creds.deletes[0] != (mfaCredDelete{uid: 42, kind: kindTotp}) ||
		creds.deletes[1] != (mfaCredDelete{uid: 42, kind: kindRecoveryCode}) {
		t.Fatalf("deletes = %+v", creds.deletes)
	}
	for _, r := range creds.rows {
		if r.Kind == kindTotp || r.Kind == kindRecoveryCode {
			t.Fatalf("凭据未删除: %+v", r)
		}
	}

	// 同一断言二次使用：totp 行已删 → verification_invalid（可证伪）。
	err := svc.UnbindTotp(context.Background(), 42, "vt-1")
	var ve *verification.Error
	if !errors.As(err, &ve) || ve.Code != "verification_invalid" {
		t.Fatalf("二次使用 err = %v, want verification_invalid", err)
	}
}

func TestUnbindTotpRejectsMissingAssertion(t *testing.T) {
	creds := &fakeMfaCreds{}
	svc := NewMfaService(MfaDeps{Creds: creds, Assertions: &fakeAssertions{}})
	if err := svc.UnbindTotp(context.Background(), 42, ""); !isVerificationCode(err, "verification_required") {
		t.Fatalf("缺断言 err = %v, want verification_required", err)
	}
	if err := svc.UnbindTotp(context.Background(), 0, "vt-1"); !errors.Is(err, ErrMfaUnauthenticated) {
		t.Fatalf("无 uid err = %v, want ErrMfaUnauthenticated", err)
	}
	svc = NewMfaService(MfaDeps{Creds: creds})
	if err := svc.UnbindTotp(context.Background(), 42, "vt-1"); !errors.Is(err, ErrMfaInternal) {
		t.Fatalf("未装配断言消费 err = %v, want ErrMfaInternal", err)
	}
}

func TestUnbindTotpPropagatesAssertionError(t *testing.T) {
	creds := &fakeMfaCreds{rows: []*model.UserCredential{{UserID: 42, Kind: kindTotp}}}
	assertions := &fakeAssertions{err: &verification.Error{Code: "verification_invalid"}}
	svc := NewMfaService(MfaDeps{Creds: creds, Assertions: assertions})
	err := svc.UnbindTotp(context.Background(), 42, "vt-1")
	if !isVerificationCode(err, "verification_invalid") {
		t.Fatalf("err = %v, want verification_invalid", err)
	}
	if len(creds.deletes) != 0 {
		t.Fatalf("断言未通过不得删除凭据: %+v", creds.deletes)
	}
}

// TestUnbindTotpResetsSwitchWhenLastFactorRemoved 解绑后无可用因子回落
// mfa_required=0；仍有其他可用因子（如手机号）时保持原开关（§3.5 运行期兜底）。
func TestUnbindTotpResetsSwitchWhenLastFactorRemoved(t *testing.T) {
	phone := "13812348000"
	cases := []struct {
		name        string
		methods     []string
		user        *model.User
		wantUpdates []int8
	}{
		{"无其他可用因子 → 回落", []string{"totp"}, &model.User{ID: 42, MfaRequired: 1}, []int8{0}},
		{"手机号仍可用 → 保持", []string{"totp", "otp_sms"}, &model.User{ID: 42, MfaRequired: 1, Phone: &phone}, nil},
		// 开关本来就是 0：删掉最后一个因子也不得回写（不刷 updated_at）。
		{"开关本为 0 → 不写回", []string{"totp"}, &model.User{ID: 42, MfaRequired: 0}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creds := &fakeMfaCreds{rows: []*model.UserCredential{
				{UserID: 42, Kind: kindTotp, IsEnabled: 1},
				{UserID: 42, Kind: kindRecoveryCode, IsEnabled: 1},
			}}
			users := &fakeMfaUsers{u: tc.user}
			svc := NewMfaService(MfaDeps{
				Users:      users,
				Creds:      creds,
				Settings:   mfaSettingsOn(tc.methods...),
				Assertions: &fakeAssertions{},
			})
			if err := svc.UnbindTotp(context.Background(), 42, "vt-1"); err != nil {
				t.Fatalf("UnbindTotp: %v", err)
			}
			if len(users.updates) != len(tc.wantUpdates) {
				t.Fatalf("mfa_required updates = %v, want %v", users.updates, tc.wantUpdates)
			}
			for i, w := range tc.wantUpdates {
				if users.updates[i] != w {
					t.Errorf("updates[%d] = %d, want %d", i, users.updates[i], w)
				}
			}
		})
	}
}

func isVerificationCode(err error, code string) bool {
	var ve *verification.Error
	return errors.As(err, &ve) && ve.Code == code
}

// TestUnbindTotpWithRealAssertionService 端到端：真 AssertionCodec 签发断言、
// 真 verification.Service 消费并做 biz_purpose/operation/subject 校验，再接
// MfaService 删除凭据；同一断言二次使用因凭据已删被拒（可证伪）。
func TestUnbindTotpWithRealAssertionService(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x3C
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	codec := verification.NewAssertionCodec(security.NewCodec(ks), security.NewCodec(ks))
	assertions := verification.NewService(verification.Deps{Codec: codec})

	issue := func(operation string) string {
		tok, err := codec.IssueAssertion(verification.Assertion{
			BizPurpose: verification.BizPurposeUnbindTOTP,
			Subject:    verification.Subject{Kind: verification.SubjectKindUID, ID: "42"},
			Nonce:      "nonce-e2e",
			AMR:        []string{"totp"},
			Operation:  operation,
		}, verification.AssertionTTL)
		if err != nil {
			t.Fatalf("IssueAssertion: %v", err)
		}
		return tok
	}

	// operation 不符：消费侧拒绝，凭据不得删除。
	creds := &fakeMfaCreds{rows: []*model.UserCredential{
		{UserID: 42, Kind: kindTotp},
		{UserID: 42, Kind: kindRecoveryCode},
	}}
	svc := NewMfaService(MfaDeps{Creds: creds, Assertions: assertions})
	if err := svc.UnbindTotp(context.Background(), 42, issue("other_operation")); !isVerificationCode(err, "verification_invalid") {
		t.Fatalf("operation 不符 err = %v, want verification_invalid", err)
	}
	if len(creds.deletes) != 0 {
		t.Fatalf("断言校验未过不得删除凭据: %+v", creds.deletes)
	}

	// 有效断言：解绑成功并删除 totp / recovery_code。
	tok := issue("unbind_totp")
	if err := svc.UnbindTotp(context.Background(), 42, tok); err != nil {
		t.Fatalf("有效断言解绑: %v", err)
	}
	if len(creds.deletes) != 2 {
		t.Fatalf("deletes = %+v, want totp + recovery_code", creds.deletes)
	}

	// 同一断言二次使用：凭据已删 → verification_invalid。
	if err := svc.UnbindTotp(context.Background(), 42, tok); !isVerificationCode(err, "verification_invalid") {
		t.Fatalf("二次使用 err = %v, want verification_invalid", err)
	}
}

// TestVerificationProductionConstructorUnique 生产构造点唯一性位置断言：
// step-up 服务的生产构造点只能有 buildVerification 一处，且必须注入
// Deps.Settings；否则新增构造点会静默回落注册默认 otp_ttl（§4.7、§20）。
// 本文件内的测试桩（_test.go）不属生产代码，扫描时排除。
func TestVerificationProductionConstructorUnique(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取当前文件路径失败")
	}
	root := filepath.Join(filepath.Dir(thisFile), "../../..")
	const ctor = "verification.NewService("
	total := 0
	var ctorFile string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case "gen", ".git", ".agent-temp":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if n := strings.Count(string(b), ctor); n > 0 {
			total += n
			ctorFile = path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描生产源码失败: %v", err)
	}
	if total != 1 {
		t.Fatalf("step-up 服务生产构造点应唯一，实测 %d 处", total)
	}
	// 唯一构造点必须注入 settings 快照源，否则 intSetting 静默回默认值。
	b, err := os.ReadFile(ctorFile)
	if err != nil {
		t.Fatalf("读构造点文件失败: %v", err)
	}
	block := string(b)
	if i := strings.Index(block, ctor); i >= 0 {
		block = block[i:]
		if j := strings.Index(block, "\n\t})"); j >= 0 {
			block = block[:j]
		}
	}
	if !strings.Contains(block, "Settings:") {
		t.Fatal("唯一生产构造点未注入 Deps.Settings（会静默回默认 otp_ttl）")
	}
}
