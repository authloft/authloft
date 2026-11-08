// settings.go 的 service 层测试：GetSettings 全键投影对 §5.6 /
// internal/settings 键表逐键、SetSettings 部分更新（PATCH：optional has
// 位 / 显式零值 / 未设置不修改 / repeated 伴生 has_* 标志与清空列表）
// + SetMany 落库 +
// settings_update 审计（detail 变更项解码断言）、ListEvents 透传、
// DecodeToken login/session 正例 + 非法 / 篡改 / 跨 purpose / cookie
// 载荷 schema 未落地失败例、GetStatus 三字段。真库 List 用例在
// internal/repo/eventlog_repo_test.go；settings watcher 热更传播的真连
// 用例在 internal/settings 既有测试（SetMany PUBLISH → reload 链），
// 本处以 fake 断言写入与审计，不重复造真库 watcher 测试（既定口径）。
package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "authloft/gen/go/api/admin/v1"
	"authloft/gen/go/token"
	"authloft/internal/dto"
	"authloft/internal/eventlog"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	adminsvc "authloft/internal/service/admin"
	"authloft/internal/settings"
)

// settingsTestCodec 构造 32B 单密钥 Codec（§1.4 封装；测试不读配置）。
func settingsTestCodec(t *testing.T) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x60 + i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

// —— fake 全家（窄接口逐一落档）——

// fakeSettingsStore SettingsStore 的 fake：Snapshot 返回预置快照；SetMany
// 留档 kv / updatedBy，错误可注入。
type fakeSettingsStore struct {
	snap    map[string]any
	setErr  error
	gotKV   map[string]any
	gotBy   int64
	setCall int
}

func (f *fakeSettingsStore) Snapshot() map[string]any { return f.snap }

func (f *fakeSettingsStore) SetMany(_ context.Context, kv map[string]any, updatedBy int64) error {
	f.setCall++
	f.gotKV = kv
	f.gotBy = updatedBy
	return f.setErr
}

// fakeSettingsEvents EventLister 的 fake：query 留档，返回可预置。
type fakeSettingsEvents struct {
	rows    []model.EventLog
	total   int64
	listErr error
	got     repo.EventAdminQuery
}

func (f *fakeSettingsEvents) List(_ context.Context, q repo.EventAdminQuery) ([]model.EventLog, int64, error) {
	f.got = q
	return f.rows, f.total, f.listErr
}

// settingsFakeAudit AuditSink 的 fake：events 落档断言。
type settingsFakeAudit struct{ events []model.EventLog }

func (f *settingsFakeAudit) PushEvent(ev model.EventLog) { f.events = append(f.events, ev) }

// fakeSettingsQueue QueueMonitor 的 fake：三指标预置。
type fakeSettingsQueue struct {
	length  int
	dropped uint64
	flushMs int64
}

func (f *fakeSettingsQueue) Len() int        { return f.length }
func (f *fakeSettingsQueue) Dropped() uint64 { return f.dropped }
func (f *fakeSettingsQueue) FlushMs() int64  { return f.flushMs }

// newSettingsService 组装被测 service（codecs 全用同一 codec——Encode/Decode
// 语义只由 purpose 决定）。
func newSettingsService(store adminsvc.SettingsStore, events adminsvc.EventLister,
	audit adminsvc.AuditSink, codec *security.Codec, queue adminsvc.QueueMonitor,
) *adminsvc.SettingsService {
	return adminsvc.NewSettingsService(store, events, audit, adminsvc.TokenCodecs{
		Session: codec, Login: codec, Cookie: codec,
	}, queue)
}

// TestSettingsServiceGetSettingsAllKeys 全键投影（OUTCOME ①）：真
// settings.Store 种子默认档（NewStore(nil,nil)）→ GetSettings →
// dto.AdminSettings → protojson（UseProtoNames + EmitUnpopulated，测试侧
// 回放）→ 36 键逐键对 settings.Defaults()——同时验证键名零自造、
// 键集完整（= §5.6 四张表之和）与值类型投影。
func TestSettingsServiceGetSettingsAllKeys(t *testing.T) {
	store := settings.NewStore(nil, nil)
	svc := newSettingsService(store, &fakeSettingsEvents{}, &settingsFakeAudit{}, nil, &fakeSettingsQueue{})

	snap := svc.GetSettings()
	resp := dto.AdminSettings(snap)
	b, err := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	want := settings.Defaults()
	if len(got) != len(want) {
		t.Fatalf("投影键数 = %d, want %d（36 键全键，§5.6 四张表之和）", len(got), len(want))
	}
	for k, v := range want {
		g, ok := got[k]
		if !ok {
			t.Fatalf("键 %q 缺失（键名应对 §5.6 四张表零自造）", k)
		}
		switch wv := v.(type) {
		case int64:
			gs, ok := g.(string)
			if !ok || gs != strconv.FormatInt(wv, 10) {
				t.Errorf("键 %q = %v, want %d", k, g, wv)
			}
		case bool, string:
			if g != any(wv) {
				t.Errorf("键 %q = %v, want %v", k, g, wv)
			}
		case []string:
			ga, ok := g.([]any)
			if !ok || len(ga) != len(wv) {
				t.Errorf("键 %q = %v, want %v", k, g, wv)
				continue
			}
			for i := range wv {
				if ga[i] != any(wv[i]) {
					t.Errorf("键 %q[%d] = %v, want %v", k, i, ga[i], wv[i])
				}
			}
		}
	}
}

// —— proto3 optional 指针构造（生成物标量字段为 *int64 / *bool / *string）——
// 指针非 nil = has 位置位（显式设值，含 0 / false / 空串）；nil = 未设置。
// 与 §3.2 行 837 UpdateProfile 的可选字段测试口径一致。
func i64Ptr(v int64) *int64   { return &v }
func boolPtr(v bool) *bool    { return &v }
func strPtr(v string) *string { return &v }

// defaultSetSettingsRequest 全默认请求（= settings.Defaults() 全字段显式
// 提交形态，即前端设置页以 GET 结果为底稿整体回写）。PATCH 语义下这是
// 「全部标量 has 位置位 + 四个 repeated 伴生标志置 true」的兼容基线：
// 与快照同值也照常写入；两个默认空列表同样在写入集里（显式清空）。
func defaultSetSettingsRequest() *adminv1.SetSettingsRequest {
	def := settings.Defaults()
	return &adminv1.SetSettingsRequest{
		PwdMinLength:          i64Ptr(8),
		PwdMaxLength:          i64Ptr(64),
		PwdRequireClasses:     i64Ptr(3),
		PwdDisallowUsername:   boolPtr(true),
		PwdDisallowCommon:     boolPtr(true),
		AllowPasswordReset:    boolPtr(true),
		OtpResendInterval:     i64Ptr(60),
		OtpTtl:                i64Ptr(300),
		OtpMaxAttempts:        i64Ptr(5),
		OtpDailyLimitTarget:   i64Ptr(10),
		OtpDailyLimitIp:       i64Ptr(50),
		HasLoginMethods:       boolPtr(true),
		LoginMethods:          def[settings.KeyLoginMethods].([]string),
		AllowRegistration:     boolPtr(true),
		AllowSignupPassword:   boolPtr(true),
		AllowSignupPhone:      boolPtr(true),
		AllowSignupEmail:      boolPtr(true),
		MfaEnabled:            boolPtr(true),
		HasMfaMethods:         boolPtr(true),
		MfaMethods:            def[settings.KeyMfaMethods].([]string),
		PwdFailCapture:        i64Ptr(3),
		PwdFailBan:            i64Ptr(6),
		PwdBanTtl:             i64Ptr(21600),
		SessionTtl:            i64Ptr(604800),
		CookieName:            strPtr("al_session"),
		HasSsoDomains:         boolPtr(true),
		SsoDomains:            []string{},
		QueueWorkers:          i64Ptr(4),
		QueueCapacity:         i64Ptr(8192),
		QueueBatch:            i64Ptr(200),
		QueueFlushMs:          i64Ptr(2000),
		CaptchaProviderKey:    strPtr(""),
		SmsProviderKey:        strPtr(""),
		EmailProviderKey:      strPtr(""),
		AvatarStorageProvider: strPtr(""),
		HasGatewayTokens:      boolPtr(true),
		GatewayTokens:         []string{},
		EventlogRetentionDays: i64Ptr(180),
		StaticBase:            strPtr("/assets"),
		HttpsDeployment:       strPtr(settings.HTTPSDeploymentAuto),
	}
}

// TestSettingsServiceSetSettingsPatchOnlyPresentKeys 部分更新主链路
// （OUTCOME ②）：只提交 4 个在场键 → SetMany 只落这 4 键（updatedBy=actor），
// 未提交键（含快照非默认现值的 pwd_max_length / https_deployment）既不进
// kv 也不进审计变更集；审计 settings_update（actor=admin、user_id=0），
// detail 的 keys / before / after 只含在场且实际变化的键。
func TestSettingsServiceSetSettingsPatchOnlyPresentKeys(t *testing.T) {
	ctx := context.Background()
	// 快照基线 = 默认档 + 两处非默认现值（证明「未提交 = 保留现值」）。
	snap := settings.Defaults()
	snap[settings.KeyPwdMaxLength] = int64(40)
	snap[settings.KeyHttpsDeployment] = settings.HTTPSDeploymentTrue
	store := &fakeSettingsStore{snap: snap}
	audit := &settingsFakeAudit{}
	svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})

	req := &adminv1.SetSettingsRequest{
		PwdMinLength:      i64Ptr(10),           // 默认 8 → 变更
		AllowRegistration: boolPtr(false),       // 默认 true → 变更
		HasMfaMethods:     boolPtr(true),        // 伴生标志置 true → 列表在场
		MfaMethods:        []string{"webauthn"}, // 整组替换
		HasSsoDomains:     boolPtr(true),        // 伴生标志置 true → 列表在场
		SsoDomains:        []string{"https://a.example.com", "https://b.example.com"},
	}
	if err := svc.SetSettings(ctx, 1, req); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}

	// 落库断言：只 4 键、updatedBy=actor、逐键值正确。
	if store.gotBy != 1 {
		t.Fatalf("updatedBy = %d, want 1", store.gotBy)
	}
	if len(store.gotKV) != 4 {
		t.Fatalf("SetMany 键数 = %d, want 4（PATCH：只写在场键）", len(store.gotKV))
	}
	if got, _ := store.gotKV[settings.KeyPwdMinLength].(int64); got != 10 {
		t.Errorf("pwd_min_length = %v, want 10", store.gotKV[settings.KeyPwdMinLength])
	}
	if got, _ := store.gotKV[settings.KeyAllowRegistration].(bool); got {
		t.Errorf("allow_registration = %v, want false", store.gotKV[settings.KeyAllowRegistration])
	}
	if got, _ := store.gotKV[settings.KeyMfaMethods].([]string); len(got) != 1 || got[0] != "webauthn" {
		t.Errorf("mfa_methods = %v, want [webauthn]（整组替换）", store.gotKV[settings.KeyMfaMethods])
	}
	if got, _ := store.gotKV[settings.KeySsoDomains].([]string); len(got) != 2 || got[0] != "https://a.example.com" {
		t.Errorf("sso_domains = %v", store.gotKV[settings.KeySsoDomains])
	}
	// 未在场键：不落库（旧全量替换会写零值），保留快照现值。
	for _, k := range []string{
		settings.KeyPwdMaxLength, settings.KeyCookieName,
		settings.KeyHttpsDeployment, settings.KeyLoginMethods,
	} {
		if _, ok := store.gotKV[k]; ok {
			t.Errorf("未设置键 %q 不应写入: %v", k, store.gotKV[k])
		}
	}

	// 审计断言：settings_update、actor=admin、actor_id=1、user_id=0。
	if len(audit.events) != 1 {
		t.Fatalf("审计事件数 = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.Event != eventlog.EventSettingsUpdate || ev.ActorType != eventlog.ActorTypeAdmin ||
		ev.ActorID != 1 || ev.UserID != 0 {
		t.Fatalf("审计事件头 = %+v", ev)
	}
	var detail struct {
		Keys   []string       `msgpack:"keys"`
		Before map[string]any `msgpack:"before"`
		After  map[string]any `msgpack:"after"`
	}
	if err := msgpack.Unmarshal(ev.Detail, &detail); err != nil {
		t.Fatalf("detail msgpack 解码: %v", err)
	}
	// 变更项 = pwd_min_length / allow_registration / mfa_methods / sso_domains，
	// 按 settings.Defs() 表序；未在场键一律不进变更集（diffSettings 的核心修正）。
	wantKeys := []string{
		settings.KeyPwdMinLength,
		settings.KeyAllowRegistration,
		settings.KeyMfaMethods,
		settings.KeySsoDomains,
	}
	if len(detail.Keys) != len(wantKeys) {
		t.Fatalf("变更 keys = %v, want %v", detail.Keys, wantKeys)
	}
	for i, k := range wantKeys {
		if detail.Keys[i] != k {
			t.Fatalf("变更 keys[%d] = %q, want %q（应按 defs 表序）", i, detail.Keys[i], k)
		}
		if _, ok := detail.Before[k]; !ok {
			t.Errorf("before 缺变更键 %q", k)
		}
		if _, ok := detail.After[k]; !ok {
			t.Errorf("after 缺变更键 %q", k)
		}
	}
	if b, _ := detail.Before[settings.KeyPwdMinLength].(int64); b != 8 {
		t.Errorf("before[pwd_min_length] = %v, want 8", detail.Before[settings.KeyPwdMinLength])
	}
	if a, _ := detail.After[settings.KeyPwdMinLength].(int64); a != 10 {
		t.Errorf("after[pwd_min_length] = %v, want 10", detail.After[settings.KeyPwdMinLength])
	}
	for _, k := range []string{settings.KeyPwdMaxLength, settings.KeyHttpsDeployment, settings.KeyCookieName} {
		if _, ok := detail.Before[k]; ok {
			t.Errorf("未设置键 %q 不得进 before: %v", k, detail.Before)
		}
		if _, ok := detail.After[k]; ok {
			t.Errorf("未设置键 %q 不得进 after: %v", k, detail.After)
		}
	}
}

// TestSettingsServiceSetSettingsFullRequestNoChangeStillAudits 全量提交
// 客户端兼容 + 幂等重放：32 个标量 has 位置位、四个 repeated 伴生标志
// 置 true，且所有值与快照同 → 36 键照常整批 SetMany（PATCH 不做
// 「同值跳过」），两个默认空列表也在写入集里（显式清空但不算变更）；
// detail 的 keys/before/after 空集，仍投审计（每次管理员动作留痕，
// 口径同 UserService.UpdateUserStatus）。
func TestSettingsServiceSetSettingsFullRequestNoChangeStillAudits(t *testing.T) {
	ctx := context.Background()
	store := &fakeSettingsStore{snap: settings.Defaults()}
	audit := &settingsFakeAudit{}
	svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})

	if err := svc.SetSettings(ctx, 7, defaultSetSettingsRequest()); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	if store.gotBy != 7 || len(store.gotKV) != 36 {
		t.Fatalf("落档 = by %d keys %d, want 7/36（32 标量 + 4 列表，含 2 个空列表）", store.gotBy, len(store.gotKV))
	}
	// 同值键仍显式写回（has 位生效，不因与快照同值而跳过）。
	if got, _ := store.gotKV[settings.KeyPwdMaxLength].(int64); got != 64 {
		t.Errorf("pwd_max_length 应原值写回, got %v", got)
	}
	if got, _ := store.gotKV[settings.KeyStaticBase].(string); got != "/assets" {
		t.Errorf("static_base 应原值写回, got %q", got)
	}
	// 伴生标志置 true 时，空列表也整组写入（非 nil 空切片 → 清空该列表）。
	for _, k := range []string{settings.KeySsoDomains, settings.KeyGatewayTokens} {
		got, ok := store.gotKV[k].([]string)
		if !ok || got == nil || len(got) != 0 {
			t.Errorf("空列表 %q 应写入非 nil 空切片, got %#v", k, store.gotKV[k])
		}
	}
	if len(audit.events) != 1 {
		t.Fatalf("同值重放也应投审计, got %d 条", len(audit.events))
	}
	var detail struct {
		Keys   []string       `msgpack:"keys"`
		Before map[string]any `msgpack:"before"`
		After  map[string]any `msgpack:"after"`
	}
	if err := msgpack.Unmarshal(audit.events[0].Detail, &detail); err != nil {
		t.Fatalf("detail: %v", err)
	}
	if len(detail.Keys) != 0 || len(detail.Before) != 0 || len(detail.After) != 0 {
		t.Errorf("同值重放 detail 应空集, got %v/%v/%v", detail.Keys, detail.Before, detail.After)
	}
}

// TestSettingsServiceSetSettingsHTTPSDeploymentValidation：三态
// 值域 true/false/auto 原样落库（fake 断言传值，值域白名单在 settings 包
// TestValidate 已覆盖）；三态之外（含显式空串 / 大写）整批拒绝、不产生半截
// 写入，且真 Store 链路错误经本层转译可判别——errors.Is 命中
// ErrInvalidRequest（§5.6 行 1361：SetSettings 非法值 → invalid_request；
// handler mapWriteError 按本哨兵映射 400，此前裸错误不命中误落
// 500）。负例用真 Store（nil repo）——Validate 先于落库（store.go
// SetMany），非法值在触达存储前返回，不会 panic。PATCH 下正负例均只提交
// https_deployment 单键：其余键缺省不影响校验链，也不会被误写零值。
func TestSettingsServiceSetSettingsHTTPSDeploymentValidation(t *testing.T) {
	ctx := context.Background()
	for _, ok := range []string{settings.HTTPSDeploymentTrue, settings.HTTPSDeploymentFalse, settings.HTTPSDeploymentAuto} {
		store := &fakeSettingsStore{snap: settings.Defaults()}
		svc := newSettingsService(store, &fakeSettingsEvents{}, &settingsFakeAudit{}, nil, &fakeSettingsQueue{})
		req := &adminv1.SetSettingsRequest{HttpsDeployment: strPtr(ok)}
		if err := svc.SetSettings(ctx, 1, req); err != nil {
			t.Errorf("https_deployment=%q 三态内应通过: %v", ok, err)
		}
		if len(store.gotKV) != 1 {
			t.Errorf("https_deployment=%q PATCH 只应写 1 键, got %d", ok, len(store.gotKV))
		}
		if got, _ := store.gotKV[settings.KeyHttpsDeployment].(string); got != ok {
			t.Errorf("https_deployment=%q 应原样落库, got %v", ok, got)
		}
	}
	for _, bad := range []string{"yes", "", "TRUE", "Auto", "1", "maybe"} {
		store := settings.NewStore(nil, nil)
		audit := &settingsFakeAudit{}
		svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})
		req := &adminv1.SetSettingsRequest{HttpsDeployment: strPtr(bad)}
		err := svc.SetSettings(ctx, 1, req)
		if err == nil {
			t.Errorf("https_deployment=%q 三态外应拒绝", bad)
			continue
		}
		if !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Errorf("https_deployment=%q 拒绝应转译 ErrInvalidRequest（handler 400 判据）, got %v", bad, err)
		}
		if !strings.Contains(err.Error(), settings.KeyHttpsDeployment) {
			t.Errorf("https_deployment=%q 拒绝错误应可判别（含键名）, got %v", bad, err)
		}
		if len(audit.events) != 0 {
			t.Errorf("https_deployment=%q 校验失败不应投审计, got %d 条", bad, len(audit.events))
		}
	}
}

// TestSettingsServiceSetSettingsExplicitZeroValues proto3 optional 三态回归
// （§3.2 行 837 口径）：显式 0 / false / 空串覆盖现值（旧「零值 = 未传」
// 实现会漏写），未设置字段不写入；显式同值键（captcha_provider_key="" /
// https_deployment="auto"）照常写入但不进变更集。fake 不过 Validate，
// 三态值域拒绝另见 TestSettingsServiceSetSettingsHTTPSDeploymentValidation。
func TestSettingsServiceSetSettingsExplicitZeroValues(t *testing.T) {
	ctx := context.Background()
	store := &fakeSettingsStore{snap: settings.Defaults()}
	audit := &settingsFakeAudit{}
	svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})

	req := &adminv1.SetSettingsRequest{
		AllowRegistration:  boolPtr(false),
		PwdBanTtl:          i64Ptr(0),
		CookieName:         strPtr(""),
		CaptchaProviderKey: strPtr(""),                           // 显式空串，与默认同值
		HttpsDeployment:    strPtr(settings.HTTPSDeploymentAuto), // 显式同值
	}
	if err := svc.SetSettings(ctx, 1, req); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	if len(store.gotKV) != 5 {
		t.Fatalf("SetMany 键数 = %d, want 5（只写在场键）", len(store.gotKV))
	}
	if got, _ := store.gotKV[settings.KeyPwdBanTtl].(int64); got != 0 {
		t.Errorf("pwd_ban_ttl 显式 0 应写回, got %v", store.gotKV[settings.KeyPwdBanTtl])
	}
	if got, _ := store.gotKV[settings.KeyAllowRegistration].(bool); got {
		t.Errorf("allow_registration 显式 false 应写回, got %v", store.gotKV[settings.KeyAllowRegistration])
	}
	if got, _ := store.gotKV[settings.KeyCookieName].(string); got != "" {
		t.Errorf("cookie_name 显式空串应清空, got %q", got)
	}
	if _, ok := store.gotKV[settings.KeyPwdMaxLength]; ok {
		t.Error("pwd_max_length 未设置不应写入（更不应零值写回）")
	}
	if _, ok := store.gotKV[settings.KeySessionTtl]; ok {
		t.Error("session_ttl 未设置不应写入")
	}

	// 变更集只含 3 个真正变值的键（按 defs 表序）；显式同值键不进变更集。
	if len(audit.events) != 1 {
		t.Fatalf("审计 = %d, want 1", len(audit.events))
	}
	var detail struct {
		Keys   []string       `msgpack:"keys"`
		Before map[string]any `msgpack:"before"`
		After  map[string]any `msgpack:"after"`
	}
	if err := msgpack.Unmarshal(audit.events[0].Detail, &detail); err != nil {
		t.Fatalf("detail: %v", err)
	}
	wantKeys := []string{settings.KeyAllowRegistration, settings.KeyPwdBanTtl, settings.KeyCookieName}
	if len(detail.Keys) != len(wantKeys) {
		t.Fatalf("变更 keys = %v, want %v", detail.Keys, wantKeys)
	}
	for i, k := range wantKeys {
		if detail.Keys[i] != k {
			t.Fatalf("变更 keys[%d] = %q, want %q", i, detail.Keys[i], k)
		}
	}
	if b, _ := detail.Before[settings.KeyPwdBanTtl].(int64); b != 21600 {
		t.Errorf("before[pwd_ban_ttl] = %v, want 21600", detail.Before[settings.KeyPwdBanTtl])
	}
	if a, _ := detail.After[settings.KeyPwdBanTtl].(int64); a != 0 {
		t.Errorf("after[pwd_ban_ttl] = %v, want 0", detail.After[settings.KeyPwdBanTtl])
	}
	for _, k := range []string{settings.KeyCaptchaProviderKey, settings.KeyHttpsDeployment, settings.KeyPwdMaxLength} {
		if _, ok := detail.After[k]; ok {
			t.Errorf("键 %q 不应进 after: %v", k, detail.After)
		}
	}
}

// TestSettingsServiceSetSettingsEmptyRequestNoop 空请求 / nil 请求：无任何
// has 位 → 零写入（SetMany 收到空 map，真 Store 内部直接返回）、零变更，
// 仍投一条审计（每次管理员动作留痕）；不会像旧全量替换那样把 36 键清零。
func TestSettingsServiceSetSettingsEmptyRequestNoop(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		req  *adminv1.SetSettingsRequest
	}{
		{"空请求", &adminv1.SetSettingsRequest{}},
		{"nil 请求", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeSettingsStore{snap: settings.Defaults()}
			audit := &settingsFakeAudit{}
			svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})

			if err := svc.SetSettings(ctx, 1, tc.req); err != nil {
				t.Fatalf("SetSettings: %v", err)
			}
			if len(store.gotKV) != 0 {
				t.Fatalf("空请求写入键 = %v, want 空集", store.gotKV)
			}
			if store.setCall != 1 {
				t.Errorf("SetMany 调用数 = %d, want 1（空 map 在 Store 内即 no-op）", store.setCall)
			}
			if len(audit.events) != 1 {
				t.Fatalf("空请求也应投审计, got %d 条", len(audit.events))
			}
			var detail struct {
				Keys   []string       `msgpack:"keys"`
				Before map[string]any `msgpack:"before"`
				After  map[string]any `msgpack:"after"`
			}
			if err := msgpack.Unmarshal(audit.events[0].Detail, &detail); err != nil {
				t.Fatalf("detail: %v", err)
			}
			if len(detail.Keys) != 0 || len(detail.Before) != 0 || len(detail.After) != 0 {
				t.Errorf("空请求 detail 应空集, got %v/%v/%v", detail.Keys, detail.Before, detail.After)
			}
		})
	}
}

// TestSettingsServiceSetSettingsRepeatedListSemantics has_* 伴生标志口径：
// 标志取 true = 列表在场（非空数组整组替换 / 空数组或缺省数组清空该列表）；
// 标志缺省 / 显式 false = 不写入，即便带了非空数组也不「按数组推测在场」。
// protojson 把 `[]` 解成 nil，故客户端清空必须显式带 hasXxx=true——用例把
// 这条 wire 契约（含仅带标志不带数组的清空形态）钉死。
func TestSettingsServiceSetSettingsRepeatedListSemantics(t *testing.T) {
	ctx := context.Background()
	// 快照里 sso_domains 非默认现值，清空动作才可在 kv / 审计中被观测。
	run := func(t *testing.T, req *adminv1.SetSettingsRequest) (*fakeSettingsStore, *settingsFakeAudit) {
		t.Helper()
		snap := settings.Defaults()
		snap[settings.KeySsoDomains] = []string{"https://old.example.com"}
		store := &fakeSettingsStore{snap: snap}
		audit := &settingsFakeAudit{}
		svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})
		if err := svc.SetSettings(ctx, 1, req); err != nil {
			t.Fatalf("SetSettings: %v", err)
		}
		return store, audit
	}
	assertCleared := func(t *testing.T, store *fakeSettingsStore) {
		t.Helper()
		if len(store.gotKV) != 1 {
			t.Fatalf("清空应只写 1 键, got %v", store.gotKV)
		}
		got, ok := store.gotKV[settings.KeySsoDomains].([]string)
		if !ok || got == nil || len(got) != 0 {
			t.Fatalf("sso_domains 应写入非 nil 空切片, got %#v", store.gotKV[settings.KeySsoDomains])
		}
	}

	t.Run("has=true + 非空数组整组替换", func(t *testing.T) {
		store, _ := run(t, &adminv1.SetSettingsRequest{
			HasSsoDomains: boolPtr(true), SsoDomains: []string{"https://a.example.com"},
		})
		if len(store.gotKV) != 1 {
			t.Fatalf("写入键 = %v, want 1 键", store.gotKV)
		}
		if got, _ := store.gotKV[settings.KeySsoDomains].([]string); len(got) != 1 || got[0] != "https://a.example.com" {
			t.Errorf("sso_domains = %v", store.gotKV[settings.KeySsoDomains])
		}
	})

	t.Run("has=true + 空数组清空（含审计变更项）", func(t *testing.T) {
		store, audit := run(t, &adminv1.SetSettingsRequest{
			HasSsoDomains: boolPtr(true), SsoDomains: []string{},
		})
		assertCleared(t, store)
		var detail struct {
			Keys  []string       `msgpack:"keys"`
			After map[string]any `msgpack:"after"`
		}
		if err := msgpack.Unmarshal(audit.events[0].Detail, &detail); err != nil {
			t.Fatalf("detail: %v", err)
		}
		if len(detail.Keys) != 1 || detail.Keys[0] != settings.KeySsoDomains {
			t.Errorf("清空应进变更集, got keys = %v", detail.Keys)
		}
		if _, ok := detail.After[settings.KeySsoDomains]; !ok {
			t.Errorf("after 应含清空的 sso_domains: %v", detail.After)
		}
	})

	t.Run("has=true 不带数组也清空", func(t *testing.T) {
		store, _ := run(t, &adminv1.SetSettingsRequest{HasSsoDomains: boolPtr(true)})
		assertCleared(t, store)
	})

	for _, body := range []string{
		`{"hasSsoDomains":true,"ssoDomains":[]}`,
		`{"hasSsoDomains":true}`,
	} {
		t.Run("wire "+body+" 清空", func(t *testing.T) {
			req := &adminv1.SetSettingsRequest{}
			if err := protojson.Unmarshal([]byte(body), req); err != nil {
				t.Fatalf("protojson: %v", err)
			}
			if !req.GetHasSsoDomains() {
				t.Fatalf("wire %s 的 has 标志应为 true", body)
			}
			if req.GetSsoDomains() != nil {
				t.Fatalf("wire %s 的 [] / 缺省数组应解码为 nil, got %#v", body, req.GetSsoDomains())
			}
			store, _ := run(t, req)
			assertCleared(t, store)
		})
	}

	t.Run("标志缺省或显式 false 不写入（标志是唯一在场判据）", func(t *testing.T) {
		wireEmptyList := &adminv1.SetSettingsRequest{}
		if err := protojson.Unmarshal([]byte(`{"ssoDomains":[]}`), wireEmptyList); err != nil {
			t.Fatalf("protojson: %v", err)
		}
		for _, tc := range []struct {
			name string
			req  *adminv1.SetSettingsRequest
		}{
			{"缺省 + 非空数组", &adminv1.SetSettingsRequest{SsoDomains: []string{"https://a.example.com"}}},
			{"缺省 + 空数组", &adminv1.SetSettingsRequest{SsoDomains: []string{}}},
			{"显式 false + 非空数组", &adminv1.SetSettingsRequest{
				HasSsoDomains: boolPtr(false), SsoDomains: []string{"https://a.example.com"},
			}},
			{"wire 无标志 + []", wireEmptyList},
		} {
			t.Run(tc.name, func(t *testing.T) {
				store, _ := run(t, tc.req)
				if len(store.gotKV) != 0 {
					t.Errorf("标志未置 true 不应写入, got %v", store.gotKV)
				}
			})
		}
	})

	t.Run("四个列表的 has 标志各自独立", func(t *testing.T) {
		store, _ := run(t, &adminv1.SetSettingsRequest{
			HasLoginMethods:  boolPtr(true),
			LoginMethods:     []string{"password"},
			HasMfaMethods:    boolPtr(true),
			MfaMethods:       []string{"totp"},
			HasSsoDomains:    boolPtr(true),
			SsoDomains:       []string{"https://a.example.com"},
			HasGatewayTokens: boolPtr(true),
			GatewayTokens:    []string{"gw-1"},
		})
		if len(store.gotKV) != 4 {
			t.Fatalf("四标志全置位应写 4 键, got %v", store.gotKV)
		}
		for _, k := range []string{
			settings.KeyLoginMethods, settings.KeyMfaMethods,
			settings.KeySsoDomains, settings.KeyGatewayTokens,
		} {
			if _, ok := store.gotKV[k]; !ok {
				t.Errorf("缺键 %q: %v", k, store.gotKV)
			}
		}
	})
}

// TestSettingsServiceSetSettingsStoreError SetMany 失败 → 原样上抛、零审计
// （主链路失败不留痕——audit 只对已落库动作）。
func TestSettingsServiceSetSettingsStoreError(t *testing.T) {
	ctx := context.Background()
	store := &fakeSettingsStore{snap: settings.Defaults(), setErr: errors.New("boom")}
	audit := &settingsFakeAudit{}
	svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})

	if err := svc.SetSettings(ctx, 1, &adminv1.SetSettingsRequest{PwdMinLength: i64Ptr(10)}); err == nil {
		t.Fatal("SetMany 错误应上抛")
	}
	if len(audit.events) != 0 {
		t.Fatalf("落库失败不应审计, got %d", len(audit.events))
	}
}

// TestSettingsServiceListEvents 统一事件视图透传（OUTCOME ③）：六筛选指针
// 原样、分页、sort/order 一并透传；返回行 / total 原样带回。
func TestSettingsServiceListEvents(t *testing.T) {
	ctx := context.Background()
	events := &fakeSettingsEvents{
		rows:  []model.EventLog{{ID: 1, Event: "login_success"}},
		total: 5,
	}
	svc := newSettingsService(&fakeSettingsStore{snap: settings.Defaults()}, events,
		&settingsFakeAudit{}, nil, &fakeSettingsQueue{})

	actorID := int64(9)
	from, to := int64(1700000000), int64(1700003600)
	rows, total, err := svc.ListEvents(ctx, adminsvc.EventListFilter{
		Event: "login_success", ActorType: "admin", ActorID: &actorID,
		From: &from, To: &to, Page: 2, PageSize: 50, Sort: "created_at", Order: "asc",
	})
	if err != nil || total != 5 || len(rows) != 1 {
		t.Fatalf("ListEvents = (%d, %d, %v)", len(rows), total, err)
	}
	q := events.got
	if q.Event != "login_success" || q.ActorType != "admin" ||
		q.ActorID == nil || *q.ActorID != 9 ||
		q.From == nil || *q.From != from || q.To == nil || *q.To != to ||
		q.Page != 2 || q.PageSize != 50 || q.Sort != "created_at" || q.Order != "asc" {
		t.Errorf("透传 query = %+v", q)
	}
}

// TestSettingsServiceDecodeToken 三 purpose 解码（OUTCOME ④）：login /
// session 正例（载荷字段逐项断言），非法 purpose、篡改、跨 purpose、
// cookie（载荷 schema 未落地口径）失败例 → ErrInvalidRequest。
func TestSettingsServiceDecodeToken(t *testing.T) {
	ctx := context.Background()
	codec := settingsTestCodec(t)
	svc := newSettingsService(&fakeSettingsStore{snap: settings.Defaults()},
		&fakeSettingsEvents{}, &settingsFakeAudit{}, codec, &fakeSettingsQueue{})
	_ = ctx

	t.Run("login 正例", func(t *testing.T) {
		src := &token.LoginTokenPayload{
			Tid: "tid-1", Flow: "login", Factor: "password",
			Passed: []string{"password"}, Uid: 42,
			Ch:   &token.Challenge{Purpose: "mfa", Target: "u@x.com", Nonce: "n1"},
			Tp:   &token.ThirdParty{ProviderKey: "wechat_mp", OpenId: "o1"},
			Oidc: &token.Oidc{ClientId: "cid", Scope: "openid"},
			Amr:  []string{"pwd"}, Iat: 100, Exp: 160,
		}
		tokStr, err := codec.Seal(security.PurposeLogin, src)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		msg, err := svc.DecodeToken("login", tokStr)
		if err != nil {
			t.Fatalf("DecodeToken: %v", err)
		}
		got, ok := msg.(*token.LoginTokenPayload)
		if !ok || got.Tid != "tid-1" || got.Flow != "login" || got.Uid != 42 ||
			got.Ch.GetPurpose() != "mfa" || got.Ch.GetTarget() != "u@x.com" ||
			got.Tp.GetProviderKey() != "wechat_mp" || got.Oidc.GetClientId() != "cid" ||
			len(got.Amr) != 1 || got.Amr[0] != "pwd" || got.Iat != 100 || got.Exp != 160 {
			t.Fatalf("login 载荷解码 = %+v", got)
		}
		// Struct 投影：protojson camelCase 口径（ch / tp / oidc 嵌套对象；
		// int64 → 十进制字符串，§1.12）。
		payload, err := dto.AdminDecodePayload(msg)
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		m := payload.AsMap()
		if m["tid"] != "tid-1" || m["flow"] != "login" || m["uid"] != "42" {
			t.Errorf("payload 顶层 = %v", m)
		}
		ch, ok := m["ch"].(map[string]any)
		if !ok || ch["purpose"] != "mfa" || ch["target"] != "u@x.com" || ch["nonce"] != "n1" {
			t.Errorf("ch 投影 = %v", m["ch"])
		}
		if tp, ok := m["tp"].(map[string]any); !ok || tp["providerKey"] != "wechat_mp" {
			t.Errorf("tp 投影 = %v", m["tp"])
		}
	})

	t.Run("session 正例", func(t *testing.T) {
		tokStr, err := codec.Seal(security.PurposeSession, &token.SessionTokenPayload{
			Id: 7, Epoch: 3, Amr: []string{"pwd", "otp"}, Sid: "sid-x", Iat: 1, Exp: 2,
		})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		msg, err := svc.DecodeToken("session", tokStr)
		if err != nil {
			t.Fatalf("DecodeToken: %v", err)
		}
		got, ok := msg.(*token.SessionTokenPayload)
		if !ok || got.Id != 7 || got.Epoch != 3 || got.Sid != "sid-x" || len(got.Amr) != 2 {
			t.Fatalf("session 载荷解码 = %+v", got)
		}
	})

	t.Run("篡改失败", func(t *testing.T) {
		tokStr, err := codec.Seal(security.PurposeSession, &token.SessionTokenPayload{Id: 7})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		// base64url 尾部替换一个字符（GCM 认证必失败）。
		tampered := tokStr[:len(tokStr)-2] + "AA"
		if _, err := svc.DecodeToken("session", tampered); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("篡改令牌应 ErrInvalidRequest, got %v", err)
		}
	})

	t.Run("跨 purpose 失败", func(t *testing.T) {
		tokStr, err := codec.Seal(security.PurposeLogin, &token.LoginTokenPayload{Tid: "t"})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if _, err := svc.DecodeToken("session", tokStr); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("跨 purpose 应 ErrInvalidRequest（AAD 含 purpose）, got %v", err)
		}
	})

	t.Run("非法 purpose", func(t *testing.T) {
		for _, p := range []string{"", "bind", "ticket", "sync_payload", "oidc_code", "LOGIN"} {
			if _, err := svc.DecodeToken(p, "whatever"); !errors.Is(err, adminsvc.ErrInvalidRequest) {
				t.Errorf("purpose %q 应 ErrInvalidRequest, got %v", p, err)
			}
		}
	})

	t.Run("cookie 具名投影三态", func(t *testing.T) {
		// al_login_state 载荷 = token.LoginStatePayload（后端架构 §12.4
		// 行 1485；生成链产物）：正例解出具名字段、篡改失败、跨
		// purpose 失败。
		tokStr, err := codec.Seal(security.PurposeCookie, &token.LoginStatePayload{
			State: "l" + "abc123", Uid: 42, Iat: 1_700_000_000, Exp: 1_700_000_600,
		})
		if err != nil {
			t.Fatalf("Seal(cookie): %v", err)
		}
		msg, err := svc.DecodeToken("cookie", tokStr)
		if err != nil {
			t.Fatalf("DecodeToken(cookie): %v", err)
		}
		lp, ok := msg.(*token.LoginStatePayload)
		if !ok || lp.GetState() != "labc123" || lp.GetUid() != 42 ||
			lp.GetIat() != 1_700_000_000 || lp.GetExp() != 1_700_000_600 {
			t.Fatalf("cookie 载荷解码 = %+v", msg)
		}

		// 篡改失败：尾部替换（GCM 认证必失败）→ ErrInvalidRequest。
		tampered := tokStr[:len(tokStr)-2] + "AA"
		if _, err := svc.DecodeToken("cookie", tampered); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("篡改 cookie 应 ErrInvalidRequest, got %v", err)
		}

		// 跨 purpose 失败：login 令牌按 cookie purpose 解（AAD 含 purpose）。
		loginTok, err := codec.Seal(security.PurposeLogin, &token.LoginTokenPayload{Tid: "t"})
		if err != nil {
			t.Fatalf("Seal(login): %v", err)
		}
		if _, err := svc.DecodeToken("cookie", loginTok); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("跨 purpose 应 ErrInvalidRequest, got %v", err)
		}
	})
}

// TestSettingsServiceGetStatus 三字段只读透传（OUTCOME ⑤）。
func TestSettingsServiceGetStatus(t *testing.T) {
	svc := newSettingsService(&fakeSettingsStore{snap: settings.Defaults()},
		&fakeSettingsEvents{}, &settingsFakeAudit{}, nil,
		&fakeSettingsQueue{length: 7, dropped: 3, flushMs: 25})

	st := svc.GetStatus()
	if st.QueueLength != 7 || st.Dropped != 3 || st.FlushMs != 25 {
		t.Fatalf("GetStatus = %+v, want {7, 3, 25}", st)
	}
}

// TestSettingsServiceNowInjected 审计 CreatedAt 取注入时钟（可测性口径
// 同 UserService）。
func TestSettingsServiceNowInjected(t *testing.T) {
	// now 注入口经包内私有字段，外部测试仅能验证行为：审计事件 CreatedAt
	// 非零即可（构造器默认 time.Now）。
	ctx := context.Background()
	store := &fakeSettingsStore{snap: settings.Defaults()}
	audit := &settingsFakeAudit{}
	svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})
	if err := svc.SetSettings(ctx, 1, &adminv1.SetSettingsRequest{PwdMinLength: i64Ptr(9)}); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	if audit.events[0].CreatedAt.IsZero() {
		t.Fatal("审计 CreatedAt 应为当前时刻")
	}
	if audit.events[0].CreatedAt.After(time.Now().Add(time.Minute)) {
		t.Fatal("审计 CreatedAt 异常偏未来")
	}
}
