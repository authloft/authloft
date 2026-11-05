// settings.go 的 service 层测试：GetSettings 全键投影对 §5.6 /
// internal/settings 键表逐键、SetSettings 全量替换 + SetMany 落库 +
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

// defaultSetSettingsRequest 全默认请求（= settings.Defaults() 的全量提交
// 形态——前端设置页以 GET 结果为底稿整表单回写；全量替换语义的测试基线）。
func defaultSetSettingsRequest() *adminv1.SetSettingsRequest {
	def := settings.Defaults()
	return &adminv1.SetSettingsRequest{
		PwdMinLength:          8,
		PwdMaxLength:          64,
		PwdRequireClasses:     3,
		PwdDisallowUsername:   true,
		PwdDisallowCommon:     true,
		AllowPasswordReset:    true,
		OtpResendInterval:     60,
		OtpTtl:                300,
		OtpMaxAttempts:        5,
		OtpDailyLimitTarget:   10,
		OtpDailyLimitIp:       50,
		LoginMethods:          def[settings.KeyLoginMethods].([]string),
		AllowRegistration:     true,
		AllowSignupPassword:   true,
		AllowSignupPhone:      true,
		AllowSignupEmail:      true,
		MfaEnabled:            true,
		MfaMethods:            def[settings.KeyMfaMethods].([]string),
		PwdFailCapture:        3,
		PwdFailBan:            6,
		PwdBanTtl:             21600,
		SessionTtl:            604800,
		CookieName:            "al_session",
		SsoDomains:            []string{},
		QueueWorkers:          4,
		QueueCapacity:         8192,
		QueueBatch:            200,
		QueueFlushMs:          2000,
		CaptchaProviderKey:    "",
		SmsProviderKey:        "",
		EmailProviderKey:      "",
		AvatarStorageProvider: "",
		GatewayTokens:         []string{},
		EventlogRetentionDays: 180,
		StaticBase:            "/assets",
		HttpsDeployment:       settings.HTTPSDeploymentAuto,
	}
}

// TestSettingsServiceSetSettingsFullReplace 全量替换 + 落库 + 审计
// （OUTCOME ②）：36 键整批 SetMany（请求 = 全默认底稿 + 4 处显式变更——
// 全量提交语义下「没改的键」按表单原值写回，缺省字段才是零值写回），
// updatedBy=actor；审计 settings_update（actor=admin、user_id=0），detail
// 解码后 keys / before / after 只含实际变更的 4 键。
func TestSettingsServiceSetSettingsFullReplace(t *testing.T) {
	ctx := context.Background()
	// 快照基线 = 默认档（真 NewStore 种子，非手工拼——diff 断言才真实）。
	store := &fakeSettingsStore{snap: settings.Defaults()}
	audit := &settingsFakeAudit{}
	svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})

	req := defaultSetSettingsRequest()
	req.PwdMinLength = 10         // 默认 8 → 变更
	req.AllowRegistration = false // 默认 true → 变更
	req.MfaMethods = nil          // 清空（proto 空 repeated = nil → 写回空列表）
	req.SsoDomains = []string{"https://a.example.com", "https://b.example.com"}
	if err := svc.SetSettings(ctx, 1, req); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}

	// 落库断言：36 键整批、updatedBy=actor、逐键值正确（抽代表键）。
	if store.gotBy != 1 {
		t.Fatalf("updatedBy = %d, want 1", store.gotBy)
	}
	if len(store.gotKV) != len(settings.Defaults()) {
		t.Fatalf("SetMany 键数 = %d, want %d（全量替换：每字段即键）", len(store.gotKV), len(settings.Defaults()))
	}
	if got, _ := store.gotKV[settings.KeyPwdMinLength].(int64); got != 10 {
		t.Errorf("pwd_min_length = %v, want 10", store.gotKV[settings.KeyPwdMinLength])
	}
	if got, _ := store.gotKV[settings.KeyMfaMethods].([]string); len(got) != 0 {
		t.Errorf("mfa_methods = %v, want 空列表（清空）", store.gotKV[settings.KeyMfaMethods])
	}
	if got, _ := store.gotKV[settings.KeyAllowRegistration].(bool); got {
		t.Errorf("allow_registration = %v, want false", store.gotKV[settings.KeyAllowRegistration])
	}
	if got, _ := store.gotKV[settings.KeySsoDomains].([]string); len(got) != 2 || got[0] != "https://a.example.com" {
		t.Errorf("sso_domains = %v", store.gotKV[settings.KeySsoDomains])
	}
	// 未变更键按表单原值写回（全量替换核心：与快照同值也整批落库）：
	if got, _ := store.gotKV[settings.KeyPwdMaxLength].(int64); got != 64 {
		t.Errorf("pwd_max_length 应表单原值写回, got %v", got)
	}
	if got, _ := store.gotKV[settings.KeyStaticBase].(string); got != "/assets" {
		t.Errorf("static_base 应表单原值写回, got %q", got)
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
	// 按 settings.Defs() 表序。
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
	if _, ok := detail.Before[settings.KeyCookieName]; ok {
		t.Errorf("未变更键不得进 before: %v", detail.Before)
	}
}

// TestSettingsServiceSetSettingsNoChangeStillAudits 幂等重放：全部键与
// 快照同值 → keys/before/after 空集，仍投审计 + 仍整批落库（每次管理员
// 动作留痕，口径同 UserService.UpdateUserStatus）。
func TestSettingsServiceSetSettingsNoChangeStillAudits(t *testing.T) {
	ctx := context.Background()
	store := &fakeSettingsStore{snap: settings.Defaults()}
	audit := &settingsFakeAudit{}
	svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})

	if err := svc.SetSettings(ctx, 7, defaultSetSettingsRequest()); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	if store.gotBy != 7 || len(store.gotKV) != len(settings.Defaults()) {
		t.Fatalf("落档 = by %d keys %d, want 7/%d（全量写库不跳过）", store.gotBy, len(store.gotKV), len(settings.Defaults()))
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
// TestValidate 已覆盖）；三态之外（含空串 / 大写）整批拒绝、不产生半截
// 写入，且真 Store 链路错误经本层转译可判别——errors.Is 命中
// ErrInvalidRequest（§5.6 行 1361：SetSettings 非法值 → invalid_request；
// handler mapWriteError 按本哨兵映射 400，此前裸错误不命中误落
// 500）。负例用真 Store（nil repo）——Validate 先于落库（store.go
// SetMany），非法值在触达存储前返回，不会 panic。
func TestSettingsServiceSetSettingsHTTPSDeploymentValidation(t *testing.T) {
	ctx := context.Background()
	for _, ok := range []string{settings.HTTPSDeploymentTrue, settings.HTTPSDeploymentFalse, settings.HTTPSDeploymentAuto} {
		store := &fakeSettingsStore{snap: settings.Defaults()}
		svc := newSettingsService(store, &fakeSettingsEvents{}, &settingsFakeAudit{}, nil, &fakeSettingsQueue{})
		req := defaultSetSettingsRequest()
		req.HttpsDeployment = ok
		if err := svc.SetSettings(ctx, 1, req); err != nil {
			t.Errorf("https_deployment=%q 三态内应通过: %v", ok, err)
		}
		if got, _ := store.gotKV[settings.KeyHttpsDeployment].(string); got != ok {
			t.Errorf("https_deployment=%q 应原样落库, got %v", ok, got)
		}
	}
	for _, bad := range []string{"yes", "", "TRUE", "Auto", "1", "maybe"} {
		store := settings.NewStore(nil, nil)
		svc := newSettingsService(store, &fakeSettingsEvents{}, &settingsFakeAudit{}, nil, &fakeSettingsQueue{})
		req := defaultSetSettingsRequest()
		req.HttpsDeployment = bad
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
	}
}

// TestSettingsServiceSetSettingsZeroValuesWrittenBack protojson 零值省略的
// 补集语义（settings.proto SetSettingsRequest 注释）：空请求（全字段缺省）
// 即 36 键全零值写回——缺省视为零值，不作「缺省保留原值」的 PATCH 解读。
// https_deployment 的零值空串在真 Store 会被三态校验拒绝（§5.6 行 1361
// 全量替换语义内非三态 → invalid_request）；本测试用 fake（不过 Validate）
// 只断言补集语义，三态拒绝在 TestSettingsServiceSetSettingsHTTPSDeploymentValidation。
func TestSettingsServiceSetSettingsZeroValuesWrittenBack(t *testing.T) {
	ctx := context.Background()
	store := &fakeSettingsStore{snap: settings.Defaults()}
	audit := &settingsFakeAudit{}
	svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})

	if err := svc.SetSettings(ctx, 1, &adminv1.SetSettingsRequest{}); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	if len(store.gotKV) != 36 {
		t.Fatalf("SetMany 键数 = %d, want 36", len(store.gotKV))
	}
	if got, _ := store.gotKV[settings.KeyPwdMaxLength].(int64); got != 0 {
		t.Errorf("pwd_max_length 缺省应零值写回, got %v", got)
	}
	if got, _ := store.gotKV[settings.KeyCookieName].(string); got != "" {
		t.Errorf("cookie_name 缺省应零值写回, got %q", got)
	}
	if got, _ := store.gotKV[settings.KeyAllowRegistration].(bool); got {
		t.Errorf("allow_registration 缺省应 false 写回, got %v", got)
	}
	if got, _ := store.gotKV[settings.KeyLoginMethods].([]string); len(got) != 0 {
		t.Errorf("login_methods 缺省应空列表写回, got %v", got)
	}
	// detail 全键变更（默认快照 → 全零）。
	if len(audit.events) != 1 {
		t.Fatalf("审计 = %d, want 1", len(audit.events))
	}
	var detail struct {
		Keys []string `msgpack:"keys"`
	}
	if err := msgpack.Unmarshal(audit.events[0].Detail, &detail); err != nil {
		t.Fatalf("detail: %v", err)
	}
	if len(detail.Keys) != 30 {
		// 36 − 6：默认档本就是零值的 6 键（sso_domains / gateway_tokens /
		// captcha_provider_key / sms_provider_key / email_provider_key /
		// avatar_storage_provider）零值写回后同值、不进变更集；
		// https_deployment 默认 auto 非零 → 全零提交算变更（fake 不过
		// Validate；真 Store 该提交会被三态校验整批拒绝，见
		// TestSettingsServiceSetSettingsHTTPSDeploymentValidation）。
		t.Errorf("全零提交变更 keys = %d, want 30（36 − 6 个默认零值键）", len(detail.Keys))
	}
}

// TestSettingsServiceSetSettingsStoreError SetMany 失败 → 原样上抛、零审计
// （主链路失败不留痕——audit 只对已落库动作）。
func TestSettingsServiceSetSettingsStoreError(t *testing.T) {
	ctx := context.Background()
	store := &fakeSettingsStore{snap: settings.Defaults(), setErr: errors.New("boom")}
	audit := &settingsFakeAudit{}
	svc := newSettingsService(store, &fakeSettingsEvents{}, audit, nil, &fakeSettingsQueue{})

	if err := svc.SetSettings(ctx, 1, &adminv1.SetSettingsRequest{}); err == nil {
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
	if err := svc.SetSettings(ctx, 1, &adminv1.SetSettingsRequest{}); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	if audit.events[0].CreatedAt.IsZero() {
		t.Fatal("审计 CreatedAt 应为当前时刻")
	}
	if audit.events[0].CreatedAt.After(time.Now().Add(time.Minute)) {
		t.Fatal("审计 CreatedAt 异常偏未来")
	}
}
