// client_test.go 覆盖 ClientService 全链业务规则：
// 双类型 CRUD 全链（Create 生成 secret 非空 / Get 明文 / Update 缺省保留 /
// client_id 不可改 / Delete 后 Get 404）、redirect_uris `*` 与 ^https?://
// 校验、uk 冲突 already_exists 转译（repo.ErrClientDuplicate → ErrDuplicateKey）、
// OIDC scopes 逗号串与 TTL 值域、分页透传。store 用内存 fake（*repo.ClientRepo
// 的真库用例在 repo/client_repo_test.go，本文件不重复建库）。
package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// fakeClientStore ClientStore 的内存 fake：模拟 *repo.ClientRepo 的关键
// 行为——uk_client_id 冲突返回包装的 repo.ErrClientDuplicate（errors.Is 可
// 判别）、未命中返回包装的 gorm.ErrRecordNotFound、Create 回填 id/时间戳
// （模拟 gorm default tag 回填语义）。
type fakeClientStore struct {
	sso    map[int64]*model.SsoClient
	oidc   map[int64]*model.OidcClient
	nextID int64

	gotList repo.ClientListQuery
}

func newFakeClientStore() *fakeClientStore {
	return &fakeClientStore{sso: map[int64]*model.SsoClient{}, oidc: map[int64]*model.OidcClient{}, nextID: 1}
}

func (f *fakeClientStore) FindSsoClientByID(_ context.Context, id int64) (*model.SsoClient, error) {
	row, ok := f.sso[id]
	if !ok {
		return nil, fmt.Errorf("fake: find sso client by id: %w", gorm.ErrRecordNotFound)
	}
	cp := *row
	return &cp, nil
}

func (f *fakeClientStore) FindOidcClientByID(_ context.Context, id int64) (*model.OidcClient, error) {
	row, ok := f.oidc[id]
	if !ok {
		return nil, fmt.Errorf("fake: find oidc client by id: %w", gorm.ErrRecordNotFound)
	}
	cp := *row
	return &cp, nil
}

func (f *fakeClientStore) ListSsoClients(_ context.Context, q repo.ClientListQuery) ([]model.SsoClient, int64, error) {
	f.gotList = q
	out := make([]model.SsoClient, 0, len(f.sso))
	for id := int64(1); id < f.nextID; id++ {
		if row, ok := f.sso[id]; ok {
			out = append(out, *row)
		}
	}
	return out, int64(len(out)), nil
}

func (f *fakeClientStore) ListOidcClients(_ context.Context, q repo.ClientListQuery) ([]model.OidcClient, int64, error) {
	f.gotList = q
	out := make([]model.OidcClient, 0, len(f.oidc))
	for id := int64(1); id < f.nextID; id++ {
		if row, ok := f.oidc[id]; ok {
			out = append(out, *row)
		}
	}
	return out, int64(len(out)), nil
}

func (f *fakeClientStore) CreateSsoClient(_ context.Context, c *model.SsoClient) error {
	for _, row := range f.sso {
		if row.ClientID == c.ClientID {
			return fmt.Errorf("fake: create sso client: %w: 1062", repo.ErrClientDuplicate)
		}
	}
	c.ID = f.nextID
	f.nextID++
	c.CreatedAt = time.Unix(1761700000, 0).UTC()
	c.UpdatedAt = c.CreatedAt
	f.sso[c.ID] = c
	return nil
}

func (f *fakeClientStore) CreateOidcClient(_ context.Context, c *model.OidcClient) error {
	for _, row := range f.oidc {
		if row.ClientID == c.ClientID {
			return fmt.Errorf("fake: create oidc client: %w: 1062", repo.ErrClientDuplicate)
		}
	}
	c.ID = f.nextID
	f.nextID++
	c.CreatedAt = time.Unix(1761700000, 0).UTC()
	c.UpdatedAt = c.CreatedAt
	f.oidc[c.ID] = c
	return nil
}

func (f *fakeClientStore) UpdateSsoClient(_ context.Context, c *model.SsoClient) error {
	if _, ok := f.sso[c.ID]; !ok {
		return fmt.Errorf("fake: update sso client: %w", gorm.ErrRecordNotFound)
	}
	f.sso[c.ID] = c
	return nil
}

func (f *fakeClientStore) UpdateOidcClient(_ context.Context, c *model.OidcClient) error {
	if _, ok := f.oidc[c.ID]; !ok {
		return fmt.Errorf("fake: update oidc client: %w", gorm.ErrRecordNotFound)
	}
	f.oidc[c.ID] = c
	return nil
}

func (f *fakeClientStore) DeleteSsoClient(_ context.Context, id int64) error {
	if _, ok := f.sso[id]; !ok {
		return fmt.Errorf("fake: delete sso client: %w", gorm.ErrRecordNotFound)
	}
	delete(f.sso, id)
	return nil
}

func (f *fakeClientStore) DeleteOidcClient(_ context.Context, id int64) error {
	if _, ok := f.oidc[id]; !ok {
		return fmt.Errorf("fake: delete oidc client: %w", gorm.ErrRecordNotFound)
	}
	delete(f.oidc, id)
	return nil
}

// TestClientServiceCreateSso SSO 新建：secret 服务端生成（非空 64 字符）、
// client_id 空 → 生成 / 非空用提交值、uk 冲突 → ErrDuplicateKey、
// redirect_uris 条目校验（`*` / ^https?:// / 非法形态）、uris round-trip。
func TestClientServiceCreateSso(t *testing.T) {
	ctx := context.Background()

	t.Run("生成与指定 client_id", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store)
		if err := svc.CreateSsoClient(ctx, SsoClientInput{Name: "门户"}); err != nil {
			t.Fatalf("Create（生成 client_id）: %v", err)
		}
		row := store.sso[1]
		if row.ClientID == "" {
			t.Error("client_id 应服务端生成非空")
		}
		if row.ClientSecret == "" || len(row.ClientSecret) != clientSecretLen {
			t.Errorf("client_secret 应生成非空 %d 字符, got %q", clientSecretLen, row.ClientSecret)
		}
		if row.Name != "门户" {
			t.Errorf("name = %q, want 门户", row.Name)
		}
	})
	t.Run("提交 client_id 用提交值", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store)
		if err := svc.CreateSsoClient(ctx, SsoClientInput{ClientID: "portal-main", Name: "门户"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if got := store.sso[1].ClientID; got != "portal-main" {
			t.Errorf("client_id = %q, want portal-main", got)
		}
	})
	t.Run("uk 冲突转译 already_exists 哨兵", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store)
		if err := svc.CreateSsoClient(ctx, SsoClientInput{ClientID: "dup-key"}); err != nil {
			t.Fatalf("首次 Create: %v", err)
		}
		err := svc.CreateSsoClient(ctx, SsoClientInput{ClientID: "dup-key"})
		if !errors.Is(err, ErrDuplicateKey) {
			t.Fatalf("重复 Create err = %v, want ErrDuplicateKey", err)
		}
	})
	t.Run("redirect_uris 校验", func(t *testing.T) {
		cases := []struct {
			uris []string
			want bool
			desc string
		}{
			{[]string{"*"}, true, "整段通配"},
			{[]string{"https://app.example.com/callback"}, true, "https"},
			{[]string{"http://localhost:3000/cb"}, true, "http"},
			{[]string{"https://a.example.com/cb", "*"}, true, "混合"},
			{[]string{"ftp://x.example.com/cb"}, false, "非 http(s) scheme"},
			{[]string{"https:/a.example.com"}, false, "缺斜杠"},
			{[]string{"example.com/cb"}, false, "无 scheme"},
			{[]string{""}, false, "空条目"},
			{[]string{"https://a.example.com/cb", ""}, false, "部分空条目"},
		}
		for _, tc := range cases {
			store := newFakeClientStore()
			svc := NewClientService(store)
			err := svc.CreateSsoClient(ctx, SsoClientInput{RedirectURIs: tc.uris})
			if tc.want && err != nil {
				t.Errorf("%s: 不应拒绝, got %v", tc.desc, err)
			}
			if !tc.want && !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("%s: err = %v, want ErrInvalidRequest", tc.desc, err)
			}
		}
	})
	t.Run("redirect_uris round-trip", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store)
		want := []string{"https://app.example.com/cb", "*"}
		if err := svc.CreateSsoClient(ctx, SsoClientInput{RedirectURIs: want}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		d, err := svc.GetSsoClient(ctx, 1)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if strings.Join(d.RedirectURIs, "|") != strings.Join(want, "|") {
			t.Errorf("redirect_uris round-trip = %v, want %v", d.RedirectURIs, want)
		}
	})
	t.Run("空 uris 允许（先建后补）", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store)
		if err := svc.CreateSsoClient(ctx, SsoClientInput{Name: "占位"}); err != nil {
			t.Fatalf("Create 无 uris: %v", err)
		}
		d, err := svc.GetSsoClient(ctx, 1)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(d.RedirectURIs) != 0 {
			t.Errorf("空 uris 应回空, got %v", d.RedirectURIs)
		}
	})
}

// TestClientServiceCreateOidc OIDC 新建：SSO 基线 + scopes 逗号串、TTL 0 落
// DDL 默认（store 收到零值）、TTL 值域、scope 条目校验。
func TestClientServiceCreateOidc(t *testing.T) {
	ctx := context.Background()

	t.Run("scopes 逗号串与拆分", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store)
		if err := svc.CreateOidcClient(ctx, OidcClientInput{
			Scopes: []string{"openid", "profile", "email"},
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if got := store.oidc[1].Scopes; got != "openid,profile,email" {
			t.Errorf("scopes 列 = %q, want 逗号串", got)
		}
		d, err := svc.GetOidcClient(ctx, 1)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if strings.Join(d.Scopes, ",") != "openid,profile,email" {
			t.Errorf("Get scopes = %v", d.Scopes)
		}
	})
	t.Run("TTL 零值原样传库（落 DDL 默认由真库用例覆盖）", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store)
		if err := svc.CreateOidcClient(ctx, OidcClientInput{}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		row := store.oidc[1]
		if row.AccessTokenTTL != 0 || row.RefreshTokenTTL != 0 {
			t.Errorf("TTL 零值应原样传库落 DDL 默认, got (%d, %d)", row.AccessTokenTTL, row.RefreshTokenTTL)
		}
		if row.Scopes != "" {
			t.Errorf("空 scopes 应原样传库落 DDL 默认, got %q", row.Scopes)
		}
	})
	t.Run("TTL 值域", func(t *testing.T) {
		for _, tc := range []struct {
			access, refresh int64
			want            bool
		}{
			{3600, 2592000, true},
			{86400, 2592000, true}, // 上限含端点
			{86401, 2592000, false},
			{3600, 2592001, false},
			{-1, 2592000, false},
			{3600, -1, false},
		} {
			store := newFakeClientStore()
			svc := NewClientService(store)
			err := svc.CreateOidcClient(ctx, OidcClientInput{AccessTokenTTL: tc.access, RefreshTokenTTL: tc.refresh})
			if tc.want && err != nil {
				t.Errorf("TTL(%d,%d): 不应拒绝, got %v", tc.access, tc.refresh, err)
			}
			if !tc.want && !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("TTL(%d,%d): err = %v, want ErrInvalidRequest", tc.access, tc.refresh, err)
			}
		}
	})
	t.Run("scope 条目校验", func(t *testing.T) {
		for _, scopes := range [][]string{{"openid", ""}, {"open,id"}} {
			store := newFakeClientStore()
			svc := NewClientService(store)
			err := svc.CreateOidcClient(ctx, OidcClientInput{Scopes: scopes})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("scopes %v: err = %v, want ErrInvalidRequest", scopes, err)
			}
		}
	})
	t.Run("uk 冲突转译", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store)
		if err := svc.CreateOidcClient(ctx, OidcClientInput{ClientID: "oidc-dup"}); err != nil {
			t.Fatalf("首次 Create: %v", err)
		}
		if err := svc.CreateOidcClient(ctx, OidcClientInput{ClientID: "oidc-dup"}); !errors.Is(err, ErrDuplicateKey) {
			t.Fatalf("重复 Create err = %v, want ErrDuplicateKey", err)
		}
	})
}

// TestClientServiceSsoLifecycle SSO CRUD 全链：Get 明文 secret、Update 缺省
// 保留原值、client_id 不可改（同值放行 / 异值拒绝）、Delete 后 Get 404、
// id<=0 防御。
func TestClientServiceSsoLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newFakeClientStore()
	svc := NewClientService(store)

	if err := svc.CreateSsoClient(ctx, SsoClientInput{
		ClientID:     "portal-main",
		Name:         "门户",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret := store.sso[1].ClientSecret

	d, err := svc.GetSsoClient(ctx, 1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if d.Row.ClientSecret != secret || secret == "" {
		t.Errorf("Get 应返回明文 secret, got %q (want %q)", d.Row.ClientSecret, secret)
	}
	if d.Row.ClientID != "portal-main" {
		t.Errorf("client_id = %q", d.Row.ClientID)
	}

	t.Run("Update 缺省键保留原值", func(t *testing.T) {
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{Name: "新门户"}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		row := store.sso[1]
		if row.Name != "新门户" {
			t.Errorf("name = %q, want 新门户", row.Name)
		}
		if row.ClientID != "portal-main" {
			t.Errorf("未提交的 client_id 应保留, got %q", row.ClientID)
		}
		if row.ClientSecret != secret {
			t.Error("未提交的 secret 应保留原值")
		}
		uris, err := repo.ParseClientRedirectUris(row.RedirectURIs)
		if err != nil || len(uris.Uris) != 1 || uris.Uris[0] != "https://app.example.com/cb" {
			t.Errorf("未提交的 redirect_uris 应保留, got %v (%v)", uris.Uris, err)
		}
	})
	t.Run("client_id 不可改", func(t *testing.T) {
		err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{ClientID: "hijack-id"})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("改 client_id err = %v, want ErrInvalidRequest", err)
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{ClientID: "portal-main"}); err != nil {
			t.Errorf("同值 client_id 幂等放行, got %v", err)
		}
	})
	t.Run("Update secret 非空覆盖", func(t *testing.T) {
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{ClientSecret: "rotated-64"}); err != nil {
			t.Fatalf("Update secret: %v", err)
		}
		if got := store.sso[1].ClientSecret; got != "rotated-64" {
			t.Errorf("secret = %q, want rotated-64", got)
		}
	})
	t.Run("Delete 后 Get 404", func(t *testing.T) {
		if err := svc.DeleteSsoClient(ctx, 1); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err := svc.GetSsoClient(ctx, 1)
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("Delete 后 Get err = %v, want gorm.ErrRecordNotFound", err)
		}
		if err := svc.DeleteSsoClient(ctx, 1); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("重复 Delete err = %v, want gorm.ErrRecordNotFound", err)
		}
	})
	t.Run("id<=0 防御", func(t *testing.T) {
		for _, err := range []error{
			func() error { _, err := svc.GetSsoClient(ctx, 0); return err }(),
			svc.UpdateSsoClient(ctx, -1, SsoClientPatch{Name: "x"}),
			svc.DeleteSsoClient(ctx, 0),
		} {
			if !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("id<=0 err = %v, want ErrInvalidRequest", err)
			}
		}
	})
}

// TestClientServiceOidcLifecycle OIDC CRUD 全链：SSO 基线同构 + scopes/TTL
// 的 PATCH 保留与覆盖。
func TestClientServiceOidcLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newFakeClientStore()
	svc := NewClientService(store)

	if err := svc.CreateOidcClient(ctx, OidcClientInput{
		ClientID:        "oidc-app",
		Scopes:          []string{"openid", "profile"},
		AccessTokenTTL:  1800,
		RefreshTokenTTL: 864000,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret := store.oidc[1].ClientSecret

	d, err := svc.GetOidcClient(ctx, 1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if d.Row.ClientSecret != secret || secret == "" {
		t.Errorf("Get 应返回明文 secret, got %q", d.Row.ClientSecret)
	}
	if strings.Join(d.Scopes, ",") != "openid,profile" {
		t.Errorf("Get scopes = %v", d.Scopes)
	}

	t.Run("TTL/scopes 缺省保留", func(t *testing.T) {
		if err := svc.UpdateOidcClient(ctx, 1, OidcClientPatch{Name: "改名"}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		row := store.oidc[1]
		if row.AccessTokenTTL != 1800 || row.RefreshTokenTTL != 864000 {
			t.Errorf("未提交 TTL 应保留, got (%d, %d)", row.AccessTokenTTL, row.RefreshTokenTTL)
		}
		if row.Scopes != "openid,profile" {
			t.Errorf("未提交 scopes 应保留, got %q", row.Scopes)
		}
	})
	t.Run("TTL/scopes 覆盖与值域", func(t *testing.T) {
		if err := svc.UpdateOidcClient(ctx, 1, OidcClientPatch{AccessTokenTTL: 7200, Scopes: []string{"openid"}}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		row := store.oidc[1]
		if row.AccessTokenTTL != 7200 {
			t.Errorf("access TTL = %d, want 7200", row.AccessTokenTTL)
		}
		if row.Scopes != "openid" {
			t.Errorf("scopes = %q, want openid", row.Scopes)
		}
		if err := svc.UpdateOidcClient(ctx, 1, OidcClientPatch{AccessTokenTTL: 86401}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("TTL 越界 err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("client_id 不可改与 Delete 后 404", func(t *testing.T) {
		if err := svc.UpdateOidcClient(ctx, 1, OidcClientPatch{ClientID: "hijack"}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("改 client_id err = %v, want ErrInvalidRequest", err)
		}
		if err := svc.DeleteOidcClient(ctx, 1); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := svc.GetOidcClient(ctx, 1); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("Delete 后 Get err = %v, want gorm.ErrRecordNotFound", err)
		}
	})
}

// TestClientServiceList 分页透传与 detail 解析（uris / scopes）。
func TestClientServiceList(t *testing.T) {
	ctx := context.Background()
	store := newFakeClientStore()
	svc := NewClientService(store)

	if err := svc.CreateSsoClient(ctx, SsoClientInput{ClientID: "c1", RedirectURIs: []string{"*"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.CreateOidcClient(ctx, OidcClientInput{ClientID: "o1", Scopes: []string{"openid"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rows, total, err := svc.ListSsoClients(ctx, 2, 50, "", "")
	if err != nil {
		t.Fatalf("ListSsoClients: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("total=%d rows=%d, want 1/1", total, len(rows))
	}
	if store.gotList.Page != 2 || store.gotList.PageSize != 50 {
		t.Errorf("分页透传 = %+v, want (2, 50)", store.gotList)
	}
	if len(rows[0].RedirectURIs) != 1 || rows[0].RedirectURIs[0] != "*" {
		t.Errorf("List detail uris = %v", rows[0].RedirectURIs)
	}

	orows, _, err := svc.ListOidcClients(ctx, 1, 20, "", "")
	if err != nil {
		t.Fatalf("ListOidcClients: %v", err)
	}
	if len(orows) != 1 || strings.Join(orows[0].Scopes, ",") != "openid" {
		t.Fatalf("List oidc detail = %+v", orows)
	}
}
