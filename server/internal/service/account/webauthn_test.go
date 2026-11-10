// webauthn_test.go account 域通行密钥族 service 层单测（不连 DB，
// WebauthnStore / WebauthnCredentialStore / WebauthnFactor / AuditSink 全部
// fake 注入；因子内核的四项固定校验与 token 状态机由 factor/webauthn
// factor_test.go 覆盖，此处只测编排：fail-closed、投影、串号防御、查重、
// 写库形态、审计投递、Rename 归属与校验）。
package account

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

	"authloft/gen/go/credential"
	"authloft/internal/factor/webauthn"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// fakeWebauthnFactor WebauthnFactor 的 fake：预置结果回放 + 入参记录。
type fakeWebauthnFactor struct {
	begin         *webauthn.RegistrationChallenge
	beginErr      error
	beginUID      int64
	beginUsername string

	finish    *webauthn.RegistrationVerify
	finishTok string
	finishIn  *structpb.Struct
}

func (f *fakeWebauthnFactor) BeginRegistration(uid int64, username string) (*webauthn.RegistrationChallenge, error) {
	f.beginUID, f.beginUsername = uid, username
	return f.begin, f.beginErr
}

func (f *fakeWebauthnFactor) FinishRegistration(tok string, credential *structpb.Struct) *webauthn.RegistrationVerify {
	f.finishTok, f.finishIn = tok, credential
	return f.finish
}

// fakeWebauthnRows WebauthnStore 的 fake：内存行集 + 建库记录。
type fakeWebauthnRows struct {
	list    []model.UserCredentialWebauthn
	listErr error

	byCredID     map[string]*model.UserCredentialWebauthn
	lookupErr    map[string]error // 指定 credential_id 的查重错误（缺省 ErrRecordNotFound）
	lookupAlways error

	created   []*model.UserCredential
	createdW  []*model.UserCredentialWebauthn
	createErr error

	// Delete 回放入参 / 错误（deleteErrAsNotFound = true 时回放包装 not found，
	// 模拟 TOCTOU 并发删除）。
	deleteErr           error
	deleteErrAsNotFound bool
	deletedID           int64
	deletedUID          int64
}

func (f *fakeWebauthnRows) ListByUser(_ context.Context, _ int64) ([]model.UserCredentialWebauthn, error) {
	return f.list, f.listErr
}

func (f *fakeWebauthnRows) FindByCredentialID(_ context.Context, credentialID string) (*model.UserCredentialWebauthn, error) {
	if f.lookupAlways != nil {
		return nil, f.lookupAlways
	}
	if err, ok := f.lookupErr[credentialID]; ok {
		return nil, err
	}
	if row, ok := f.byCredID[credentialID]; ok {
		return row, nil
	}
	return nil, fmtNotFound()
}

func (f *fakeWebauthnRows) Create(_ context.Context, c *model.UserCredential, w *model.UserCredentialWebauthn) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, c)
	f.createdW = append(f.createdW, w)
	return nil
}

func (f *fakeWebauthnRows) Delete(_ context.Context, id, userID int64) error {
	if f.deleteErrAsNotFound {
		return fmt.Errorf("webauthn repo: delete: %w", gorm.ErrRecordNotFound)
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletedID, f.deletedUID = id, userID
	return nil
}

// fakeWebauthnCredRows WebauthnCredentialStore 的 fake。
type fakeWebauthnCredRows struct {
	list      []model.UserCredential
	listErr   error
	updated   []*model.UserCredential
	updateErr error
}

func (f *fakeWebauthnCredRows) ListByUser(_ context.Context, _ int64) ([]model.UserCredential, error) {
	return f.list, f.listErr
}

func (f *fakeWebauthnCredRows) Update(_ context.Context, c *model.UserCredential) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.updated = append(f.updated, c)
	return nil
}

// fmtNotFound 与 repo 包装形态一致的 ErrRecordNotFound（%w 包装可 errors.Is）。
func fmtNotFound() error {
	return fmt.Errorf("webauthn repo: find by credential id: %w", gorm.ErrRecordNotFound)
}

// fakeUserStore WebauthnUserStore 的 fake：缺省回放 username=alice，可指定
// 用户行 / 错误以覆盖空值、用户不存在与 DB 故障。
type fakeUserStore struct {
	user  *model.User
	err   error
	calls []int64
}

func (s *fakeUserStore) FindByID(_ context.Context, id int64) (*model.User, error) {
	s.calls = append(s.calls, id)
	if s.err != nil {
		return nil, s.err
	}
	if s.user != nil {
		return s.user, nil
	}
	return &model.User{ID: id, Username: "alice"}, nil
}

// newWebauthnService 构造被测 service（factor 非 nil 正常态）。
func newWebauthnService(factor WebauthnFactor, rows *fakeWebauthnRows, credRows *fakeWebauthnCredRows, audit *fakeAudit) *WebauthnService {
	return NewWebauthnService(WebauthnDeps{
		Factor:   factor,
		Webauthn: rows,
		Creds:    credRows,
		Users:    &fakeUserStore{},
		Audit:    audit,
		Now:      func() time.Time { return time.Unix(1764000000, 0).UTC() },
	})
}

// TestWebauthnFailClosed 降级窗口 fail-closed（§8.3 行 1071-1075、
// OUTCOME ②）：Factor=nil（启动初始化失败降级）时四方法一律
// ErrWebauthnDegraded（handler 映射 method_disabled + 固定文案），含只读
// 列表；未启用账号与无关功能不受影响（本用例即「行为边界」反向证明：
// 降级只经 Factor 判定，不触 DB）。
func TestWebauthnFailClosed(t *testing.T) {
	rows := &fakeWebauthnRows{}
	credRows := &fakeWebauthnCredRows{}
	s := newWebauthnService(nil, rows, credRows, &fakeAudit{})
	ctx := context.Background()

	if _, err := s.ListCredentials(ctx, 42); !errors.Is(err, ErrWebauthnDegraded) {
		t.Errorf("ListCredentials err = %v, want ErrWebauthnDegraded", err)
	}
	if _, err := s.BeginRegister(ctx, 42); !errors.Is(err, ErrWebauthnDegraded) {
		t.Errorf("BeginRegister err = %v, want ErrWebauthnDegraded", err)
	}
	if err := s.FinishRegister(ctx, 42, "tok", &structpb.Struct{}, ""); !errors.Is(err, ErrWebauthnDegraded) {
		t.Errorf("FinishRegister err = %v, want ErrWebauthnDegraded", err)
	}
	if err := s.RenameCredential(ctx, 42, 1, "new"); !errors.Is(err, ErrWebauthnDegraded) {
		t.Errorf("RenameCredential err = %v, want ErrWebauthnDegraded", err)
	}
	if err := s.DeleteCredential(ctx, 42, 1); !errors.Is(err, ErrWebauthnDegraded) {
		t.Errorf("DeleteCredential err = %v, want ErrWebauthnDegraded", err)
	}
	// 无会话（uid=0）优先 401，且先于 fail-closed 判定。
	if _, err := s.ListCredentials(ctx, 0); !errors.Is(err, ErrWebauthnUnauthenticated) {
		t.Errorf("ListCredentials uid=0 err = %v, want ErrWebauthnUnauthenticated", err)
	}
	if err := s.DeleteCredential(ctx, 0, 1); !errors.Is(err, ErrWebauthnUnauthenticated) {
		t.Errorf("DeleteCredential uid=0 err = %v, want ErrWebauthnUnauthenticated", err)
	}
	// 降级路径零 DB 触达。
	if len(rows.created) != 0 || len(credRows.updated) != 0 || rows.deletedID != 0 {
		t.Errorf("degraded path touched storage: created=%d updated=%d deleted=%d",
			len(rows.created), len(credRows.updated), rows.deletedID)
	}
}

// TestWebauthnListCredentials 列表投影（§3.6 行 931，OUTCOME ①）：label /
// createdAt / lastUsedAt 取 user_credential 行，transports / aaguid 解
// meta；脏数据行（user_credential 行缺失）零值投影不报错。
func TestWebauthnListCredentials(t *testing.T) {
	meta, err := repo.MarshalCredentialMeta(&credential.CredentialMeta{
		Transports: []string{"internal", "hybrid"},
		Aaguid:     "adce0002-35bc-c60a-648b-0b25f1f05503",
	})
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	lastUsed := time.Unix(1764100000, 0).UTC()
	rows := &fakeWebauthnRows{list: []model.UserCredentialWebauthn{
		{ID: 11, UserID: 42, Kind: "webauthn", CredentialID: "cred-a"},
		{ID: 7, UserID: 42, Kind: "webauthn", CredentialID: "cred-b"}, // 无对应 user_credential 行（脏数据）
	}}
	credRows := &fakeWebauthnCredRows{list: []model.UserCredential{
		{ID: 11, UserID: 42, Kind: "webauthn", Label: "MacBook Touch ID", Meta: meta,
			LastUsedAt: &lastUsed, CreatedAt: time.Unix(1764000100, 0).UTC()},
		{ID: 12, UserID: 42, Kind: "password"}, // 非 webauthn 行不参与投影
	}}
	s := newWebauthnService(&fakeWebauthnFactor{}, rows, credRows, &fakeAudit{})

	items, err := s.ListCredentials(context.Background(), 42)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2: %+v", len(items), items)
	}
	// 顺序保持 repo 返回序（id 倒序口径归 repo）。
	a := items[0]
	if a.ID != 11 || a.Label != "MacBook Touch ID" || a.CreatedAt != 1764000100 ||
		a.LastUsedAt != 1764100000 || a.AAGUID != "adce0002-35bc-c60a-648b-0b25f1f05503" {
		t.Errorf("item[0] = %+v", a)
	}
	if len(a.Transports) != 2 || a.Transports[0] != "internal" || a.Transports[1] != "hybrid" {
		t.Errorf("item[0].Transports = %v", a.Transports)
	}
	// 脏数据行：零值投影。
	b := items[1]
	if b.ID != 7 || b.Label != "" || b.CreatedAt != 0 || b.LastUsedAt != 0 || b.AAGUID != "" || len(b.Transports) != 0 {
		t.Errorf("item[1] (orphan) = %+v, want zero-value projection", b)
	}
}

// TestWebauthnBeginRegister challenge 透传（OUTCOME ①）。
func TestWebauthnBeginRegister(t *testing.T) {
	want := &webauthn.RegistrationChallenge{Token: "t", ExpiresIn: 120}
	f := &fakeWebauthnFactor{begin: want}
	s := newWebauthnService(f, &fakeWebauthnRows{}, &fakeWebauthnCredRows{}, &fakeAudit{})

	got, err := s.BeginRegister(context.Background(), 42)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	if got != want {
		t.Errorf("BeginRegister = %+v, want same pointer as factor output", got)
	}
	if f.beginUID != 42 {
		t.Errorf("factor uid = %d, want 42", f.beginUID)
	}
	if f.beginUsername != "alice" {
		t.Errorf("factor username = %q, want alice (server-side user table)", f.beginUsername)
	}
	if _, err := s.BeginRegister(context.Background(), 0); !errors.Is(err, ErrWebauthnUnauthenticated) {
		t.Errorf("uid=0 err = %v, want ErrWebauthnUnauthenticated", err)
	}
}

// TestWebauthnBeginRegisterUsername 注册 options 的用户信息来源：只取服务端
// 用户表的 username（name / displayName 同值），并覆盖空值回落、用户不存在、
// DB 故障与装配遗漏四种边界。username 不经请求参数传递，无法被伪造。
func TestWebauthnBeginRegisterUsername(t *testing.T) {
	ch := &webauthn.RegistrationChallenge{Token: "t", ExpiresIn: 120}
	cases := []struct {
		name     string
		users    WebauthnUserStore
		wantName string
		wantErr  error
	}{
		{"username verbatim", &fakeUserStore{user: &model.User{ID: 42, Username: "zhang_san"}}, "zhang_san", nil},
		{"username trimmed", &fakeUserStore{user: &model.User{ID: 42, Username: "  alice  "}}, "alice", nil},
		{"blank falls back to uid", &fakeUserStore{user: &model.User{ID: 42, Username: "   "}}, "42", nil},
		{"user missing", &fakeUserStore{err: fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)}, "", ErrWebauthnUnauthenticated},
		{"db failure", &fakeUserStore{err: errors.New("db down")}, "", ErrWebauthnInternal},
		{"store not wired", nil, "", ErrWebauthnInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWebauthnFactor{begin: ch}
			s := newWebauthnService(f, &fakeWebauthnRows{}, &fakeWebauthnCredRows{}, &fakeAudit{})
			s.deps.Users = tc.users
			got, err := s.BeginRegister(context.Background(), 42)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("BeginRegister: %v", err)
			}
			if got != ch {
				t.Errorf("challenge = %+v, want factor output", got)
			}
			if f.beginUsername != tc.wantName {
				t.Errorf("factor username = %q, want %q", f.beginUsername, tc.wantName)
			}
		})
	}
}

// TestWebauthnFinishRegister verify 编排（§3.6 行 933/947，OUTCOME ①）：
// 状态映射、uid 串号防御、凭据查重、写库两行形态、审计投递。
func TestWebauthnFinishRegister(t *testing.T) {
	cred := &structpb.Struct{}
	okVerify := &webauthn.RegistrationVerify{
		UID: 42, CredentialID: "cred-new", PublicKey: []byte{1, 2}, SignCount: 3,
		Transports: []string{"internal"}, AAGUID: "aa-00",
	}

	t.Run("token invalid", func(t *testing.T) {
		f := &fakeWebauthnFactor{finish: &webauthn.RegistrationVerify{Status: webauthn.StatusInvalidRequest}}
		s := newWebauthnService(f, &fakeWebauthnRows{}, &fakeWebauthnCredRows{}, &fakeAudit{})
		if err := s.FinishRegister(context.Background(), 42, "bad", cred, ""); !errors.Is(err, ErrWebauthnInvalidRequest) {
			t.Errorf("err = %v, want ErrWebauthnInvalidRequest", err)
		}
	})
	t.Run("token expired", func(t *testing.T) {
		f := &fakeWebauthnFactor{finish: &webauthn.RegistrationVerify{Status: webauthn.StatusCodeExpired}}
		s := newWebauthnService(f, &fakeWebauthnRows{}, &fakeWebauthnCredRows{}, &fakeAudit{})
		if err := s.FinishRegister(context.Background(), 42, "old", cred, ""); !errors.Is(err, ErrWebauthnCodeExpired) {
			t.Errorf("err = %v, want ErrWebauthnCodeExpired", err)
		}
	})
	t.Run("empty token or credential", func(t *testing.T) {
		s := newWebauthnService(&fakeWebauthnFactor{}, &fakeWebauthnRows{}, &fakeWebauthnCredRows{}, &fakeAudit{})
		if err := s.FinishRegister(context.Background(), 42, "", cred, ""); !errors.Is(err, ErrWebauthnInvalidRequest) {
			t.Errorf("empty token err = %v, want ErrWebauthnInvalidRequest", err)
		}
		if err := s.FinishRegister(context.Background(), 42, "tok", nil, ""); !errors.Is(err, ErrWebauthnInvalidRequest) {
			t.Errorf("nil credential err = %v, want ErrWebauthnInvalidRequest", err)
		}
	})
	t.Run("label too long", func(t *testing.T) {
		s := newWebauthnService(&fakeWebauthnFactor{}, &fakeWebauthnRows{}, &fakeWebauthnCredRows{}, &fakeAudit{})
		long := string(make([]byte, 129))
		if err := s.FinishRegister(context.Background(), 42, "tok", cred, long); !errors.Is(err, ErrWebauthnInvalidRequest) {
			t.Errorf("err = %v, want ErrWebauthnInvalidRequest", err)
		}
	})
	t.Run("uid mismatch", func(t *testing.T) {
		f := &fakeWebauthnFactor{finish: okVerify} // token uid=42
		s := newWebauthnService(f, &fakeWebauthnRows{}, &fakeWebauthnCredRows{}, &fakeAudit{})
		if err := s.FinishRegister(context.Background(), 43, "tok", cred, ""); !errors.Is(err, ErrWebauthnInvalidRequest) {
			t.Errorf("err = %v, want ErrWebauthnInvalidRequest (uid mismatch)", err)
		}
	})
	t.Run("duplicate credential id", func(t *testing.T) {
		f := &fakeWebauthnFactor{finish: okVerify}
		rows := &fakeWebauthnRows{byCredID: map[string]*model.UserCredentialWebauthn{
			"cred-new": {ID: 9, UserID: 42, CredentialID: "cred-new"},
		}}
		s := newWebauthnService(f, rows, &fakeWebauthnCredRows{}, &fakeAudit{})
		if err := s.FinishRegister(context.Background(), 42, "tok", cred, ""); !errors.Is(err, ErrWebauthnDuplicate) {
			t.Errorf("err = %v, want ErrWebauthnDuplicate", err)
		}
	})
	t.Run("create duplicate race", func(t *testing.T) {
		f := &fakeWebauthnFactor{finish: okVerify}
		rows := &fakeWebauthnRows{createErr: fmt.Errorf("webauthn repo: create: %w: dup", repo.ErrWebauthnDuplicate)}
		s := newWebauthnService(f, rows, &fakeWebauthnCredRows{}, &fakeAudit{})
		if err := s.FinishRegister(context.Background(), 42, "tok", cred, ""); !errors.Is(err, ErrWebauthnDuplicate) {
			t.Errorf("err = %v, want ErrWebauthnDuplicate (race)", err)
		}
	})
	t.Run("success", func(t *testing.T) {
		f := &fakeWebauthnFactor{finish: okVerify}
		rows := &fakeWebauthnRows{}
		audit := &fakeAudit{}
		s := newWebauthnService(f, rows, &fakeWebauthnCredRows{}, audit)

		if err := s.FinishRegister(context.Background(), 42, "tok", cred, "YubiKey 5"); err != nil {
			t.Fatalf("FinishRegister: %v", err)
		}
		if f.finishTok != "tok" || f.finishIn != cred {
			t.Errorf("factor input = (%q, %v), want passthrough", f.finishTok, f.finishIn)
		}
		// 同事务两行形态。
		if len(rows.created) != 1 || len(rows.createdW) != 1 {
			t.Fatalf("created = %d/%d rows, want 1/1", len(rows.created), len(rows.createdW))
		}
		c, w := rows.created[0], rows.createdW[0]
		if c.UserID != 42 || c.Kind != "webauthn" || c.Label != "YubiKey 5" || c.IsEnabled != 1 {
			t.Errorf("user_credential row = %+v", c)
		}
		if len(c.Secret) != 0 {
			t.Errorf("secret = %v, want empty (公钥在 webauthn 行)", c.Secret)
		}
		meta, err := repo.UnmarshalCredentialMeta(c.Meta)
		if err != nil {
			t.Fatalf("unmarshal meta: %v", err)
		}
		if len(meta.GetTransports()) != 1 || meta.GetTransports()[0] != "internal" || meta.GetAaguid() != "aa-00" {
			t.Errorf("meta = %+v", meta)
		}
		if w.UserID != 42 || w.CredentialID != "cred-new" || w.SignCount != 3 ||
			string(w.PublicKey) != string([]byte{1, 2}) {
			t.Errorf("webauthn row = %+v", w)
		}
		// 审计投递（webauthn_register，§4.6）。
		if len(audit.events) != 1 {
			t.Fatalf("audit events = %d, want 1", len(audit.events))
		}
		ev := audit.events[0]
		if ev.Event != "webauthn_register" || ev.ActorID != 42 || ev.UserID != 42 || ev.Target != "cred-new" {
			t.Errorf("audit event = %+v", ev)
		}
	})
}

// TestWebauthnRenameCredential 重命名（§3.6 行 934，OUTCOME ①）：仅本人
// （id+uid+kind 定位）、label 校验、不存在 → not_found。
func TestWebauthnRenameCredential(t *testing.T) {
	credRows := &fakeWebauthnCredRows{list: []model.UserCredential{
		{ID: 11, UserID: 42, Kind: "webauthn", Label: "old", Secret: []byte("s")},
		{ID: 12, UserID: 42, Kind: "password"},
	}}
	s := newWebauthnService(&fakeWebauthnFactor{}, &fakeWebauthnRows{}, credRows, &fakeAudit{})
	ctx := context.Background()

	if err := s.RenameCredential(ctx, 42, 11, "new name"); err != nil {
		t.Fatalf("RenameCredential: %v", err)
	}
	if len(credRows.updated) != 1 || credRows.updated[0].ID != 11 || credRows.updated[0].Label != "new name" {
		t.Errorf("updated = %+v", credRows.updated)
	}
	// secret 原样保留（Update 整行可变列回写不丢字段）。
	if string(credRows.updated[0].Secret) != "s" {
		t.Errorf("secret lost on rename: %q", credRows.updated[0].Secret)
	}

	if err := s.RenameCredential(ctx, 42, 11, ""); !errors.Is(err, ErrWebauthnInvalidRequest) {
		t.Errorf("empty label err = %v, want ErrWebauthnInvalidRequest", err)
	}
	if err := s.RenameCredential(ctx, 42, 11, string(make([]byte, 129))); !errors.Is(err, ErrWebauthnInvalidRequest) {
		t.Errorf("long label err = %v, want ErrWebauthnInvalidRequest", err)
	}
	// 目标不存在（含「属于他人」——ListByUser 只返回本人行，他人 id 永不命中）。
	if err := s.RenameCredential(ctx, 42, 999, "x"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("missing id err = %v, want gorm.ErrRecordNotFound", err)
	}
	// 非 webauthn kind 行不可作为目标。
	if err := s.RenameCredential(ctx, 42, 12, "x"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("password row err = %v, want gorm.ErrRecordNotFound", err)
	}
}

// TestWebauthnDeleteCredential 删除（§3.6 行 935）：仅本人（预查
// ListByUser 不命中 → not_found，属他人同一结论不泄露存在性）、TOCTOU
// （预查命中后 Delete 返回 not_found → 同一结论）、成功路径（Delete 入参
// 透传 + webauthn_delete 审计 detail）、id<=0 → invalid_request。
func TestWebauthnDeleteCredential(t *testing.T) {
	rows := &fakeWebauthnRows{list: []model.UserCredentialWebauthn{
		{ID: 11, UserID: 42, Kind: "webauthn", CredentialID: "cred-a"},
	}}
	audit := &fakeAudit{}
	s := newWebauthnService(&fakeWebauthnFactor{}, rows, &fakeWebauthnCredRows{}, audit)
	ctx := context.Background()

	// 成功：预查命中 → Delete(id, uid) → webauthn_delete 审计。
	if err := s.DeleteCredential(ctx, 42, 11); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if rows.deletedID != 11 || rows.deletedUID != 42 {
		t.Errorf("Delete 入参 = (%d, %d), want (11, 42)", rows.deletedID, rows.deletedUID)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.Event != "webauthn_delete" || ev.ActorID != 42 || ev.UserID != 42 || ev.Target != "cred-a" {
		t.Errorf("audit event = %+v, want (webauthn_delete, 42, 42, cred-a)", ev)
	}

	// 目标不存在（含「属于他人」——ListByUser 只返回本人行）→ not_found，
	// 不触碰删除路径。
	rows2 := &fakeWebauthnRows{list: []model.UserCredentialWebauthn{
		{ID: 11, UserID: 42, Kind: "webauthn", CredentialID: "cred-a"},
	}}
	s2 := newWebauthnService(&fakeWebauthnFactor{}, rows2, &fakeWebauthnCredRows{}, audit)
	if err := s2.DeleteCredential(ctx, 42, 999); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("missing id err = %v, want gorm.ErrRecordNotFound", err)
	}
	if rows2.deletedID != 0 {
		t.Errorf("not_found 路径不应触达 Delete: deleted=%d", rows2.deletedID)
	}

	// TOCTOU：预查命中、Delete 返回 not found（并发已删）→ 同一结论，
	// 不投审计。
	rows3 := &fakeWebauthnRows{
		list:                []model.UserCredentialWebauthn{{ID: 11, UserID: 42, Kind: "webauthn", CredentialID: "cred-a"}},
		deleteErrAsNotFound: true,
	}
	before := len(audit.events)
	s3 := newWebauthnService(&fakeWebauthnFactor{}, rows3, &fakeWebauthnCredRows{}, audit)
	if err := s3.DeleteCredential(ctx, 42, 11); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("TOCTOU err = %v, want gorm.ErrRecordNotFound", err)
	}
	if len(audit.events) != before {
		t.Errorf("TOCTOU 不应投审计: before=%d after=%d", before, len(audit.events))
	}

	// id<=0 → invalid_request。
	if err := s.DeleteCredential(ctx, 42, 0); !errors.Is(err, ErrWebauthnInvalidRequest) {
		t.Errorf("id=0 err = %v, want ErrWebauthnInvalidRequest", err)
	}
}
