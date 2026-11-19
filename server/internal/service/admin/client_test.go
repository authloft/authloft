// client_test.go 覆盖 ClientService 全链业务规则：
// 双类型 CRUD 全链（Create 生成 secret 非空 / Get 明文 / Update 缺省保留 /
// client_id 不可改 / Delete 后 Get 404）、redirect_uris `*` 与 ^https?://
// 校验、uk 冲突 already_exists 转译（repo.ErrClientDuplicate → ErrDuplicateKey）、
// OIDC scopes 逗号串与 TTL 值域、分页透传、应用级登录配置三校验与 has 位
// PATCH 语义。store 用内存 fake（*repo.ClientRepo
// 的真库用例在 repo/client_repo_test.go，本文件不重复建库）。
package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"database/sql"

	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// fakeClientStore ClientStore 的内存 fake：模拟 *repo.ClientRepo 的关键
// 行为——uk_client_id 冲突返回包装的 repo.ErrClientDuplicate（errors.Is 可
// 判别）、未命中返回包装的 sql.ErrNoRows、Create 回填 id/时间戳
// （模拟真库自增主键与时间列回填语义）。
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
		return nil, fmt.Errorf("fake: find sso client by id: %w", sql.ErrNoRows)
	}
	cp := *row
	return &cp, nil
}

func (f *fakeClientStore) FindOidcClientByID(_ context.Context, id int64) (*model.OidcClient, error) {
	row, ok := f.oidc[id]
	if !ok {
		return nil, fmt.Errorf("fake: find oidc client by id: %w", sql.ErrNoRows)
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
		return fmt.Errorf("fake: update sso client: %w", sql.ErrNoRows)
	}
	f.sso[c.ID] = c
	return nil
}

func (f *fakeClientStore) UpdateOidcClient(_ context.Context, c *model.OidcClient) error {
	if _, ok := f.oidc[c.ID]; !ok {
		return fmt.Errorf("fake: update oidc client: %w", sql.ErrNoRows)
	}
	f.oidc[c.ID] = c
	return nil
}

func (f *fakeClientStore) DeleteSsoClient(_ context.Context, id int64) error {
	if _, ok := f.sso[id]; !ok {
		return fmt.Errorf("fake: delete sso client: %w", sql.ErrNoRows)
	}
	delete(f.sso, id)
	return nil
}

func (f *fakeClientStore) DeleteOidcClient(_ context.Context, id int64) error {
	if _, ok := f.oidc[id]; !ok {
		return fmt.Errorf("fake: delete oidc client: %w", sql.ErrNoRows)
	}
	delete(f.oidc, id)
	return nil
}

// fakeProviderKeys ProviderKeyFinder 的内存 fake：existing 为存在的 provider
// key 集合（nil map = 无 provider），未命中返回包装的 sql.ErrNoRows，
// 语义镜像 *repo.ProviderRepo.FindByKey；lookupKeys 记录查询轨迹供断言。
type fakeProviderKeys struct {
	existing   map[string]bool
	lookupKeys []string
}

func (f *fakeProviderKeys) FindByKey(_ context.Context, providerKey string) (*model.Provider, error) {
	f.lookupKeys = append(f.lookupKeys, providerKey)
	if f.existing[providerKey] {
		return &model.Provider{ProviderKey: providerKey}, nil
	}
	return nil, fmt.Errorf("fake: find provider by key: %w", sql.ErrNoRows)
}

// existingProviderKeys 多数用例共用的存在 key 集（不提交 oauth_providers 的
// 用例不触达存在性查询）。
var existingProviderKeys = map[string]bool{"wx_mp": true, "github": true}

// TestClientServiceCreateSso SSO 新建：secret 服务端生成（非空 64 字符）、
// client_id 空 → 生成 / 非空用提交值、uk 冲突 → ErrDuplicateKey、
// redirect_uris 条目校验（`*` / ^https?:// / 非法形态）、uris round-trip。
func TestClientServiceCreateSso(t *testing.T) {
	ctx := context.Background()

	t.Run("生成与指定 client_id", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
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
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
		if err := svc.CreateSsoClient(ctx, SsoClientInput{ClientID: "portal-main", Name: "门户"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if got := store.sso[1].ClientID; got != "portal-main" {
			t.Errorf("client_id = %q, want portal-main", got)
		}
	})
	t.Run("uk 冲突转译 already_exists 哨兵", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
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
			svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
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
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
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
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
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
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
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
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
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
			svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
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
			svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
			err := svc.CreateOidcClient(ctx, OidcClientInput{Scopes: scopes})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("scopes %v: err = %v, want ErrInvalidRequest", scopes, err)
			}
		}
	})
	t.Run("scopes 必含 openid", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
		err := svc.CreateOidcClient(ctx, OidcClientInput{Scopes: []string{"profile", "email"}})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("缺 openid err = %v, want ErrInvalidRequest", err)
		}
		if len(store.oidc) != 0 {
			t.Errorf("被拒请求不应落库, got %d 行", len(store.oidc))
		}
	})
	t.Run("uk 冲突转译", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
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
	svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})

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
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("Delete 后 Get err = %v, want sql.ErrNoRows", err)
		}
		if err := svc.DeleteSsoClient(ctx, 1); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("重复 Delete err = %v, want sql.ErrNoRows", err)
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
	svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})

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
	t.Run("scopes 覆盖必含 openid", func(t *testing.T) {
		if err := svc.UpdateOidcClient(ctx, 1, OidcClientPatch{Scopes: []string{"profile"}}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("缺 openid 覆盖 err = %v, want ErrInvalidRequest", err)
		}
		if store.oidc[1].Scopes != "openid" {
			t.Errorf("被拒 PATCH 不应改动 scopes, got %q", store.oidc[1].Scopes)
		}
	})
	t.Run("client_id 不可改与 Delete 后 404", func(t *testing.T) {
		if err := svc.UpdateOidcClient(ctx, 1, OidcClientPatch{ClientID: "hijack"}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("改 client_id err = %v, want ErrInvalidRequest", err)
		}
		if err := svc.DeleteOidcClient(ctx, 1); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := svc.GetOidcClient(ctx, 1); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("Delete 后 Get err = %v, want sql.ErrNoRows", err)
		}
	})
}

// TestClientServiceList 分页透传与 detail 解析（uris / scopes）。
func TestClientServiceList(t *testing.T) {
	ctx := context.Background()
	store := newFakeClientStore()
	svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})

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

// TestClientServiceSsoLoginOptions 应用级登录配置（§5.5）：login_methods
// 封闭集、oauth_providers key 存在性、default_redirect_uri 白名单命中与
// 列宽防御、has 位整组替换 / 空数组跟随全局、optional 清空、无 has 位回归、
// default 对合并后白名单校验。
func TestClientServiceSsoLoginOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("Create login_methods 封闭集", func(t *testing.T) {
		for _, tc := range []struct {
			methods []string
			want    bool
			desc    string
		}{
			{nil, true, "未配置跟随全局"},
			{[]string{"password"}, true, "单因子"},
			{[]string{"password", "otp_sms", "otp_email", "webauthn", "thirdparty"}, true, "全封闭集含 thirdparty"},
			{[]string{"totp"}, false, "totp 不在集合域"},
			{[]string{"recovery_code"}, false, "recovery_code 不在集合域"},
			{[]string{"password", "bogus"}, false, "越界取值"},
			{[]string{""}, false, "空条目"},
		} {
			store := newFakeClientStore()
			svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
			err := svc.CreateSsoClient(ctx, SsoClientInput{LoginMethods: tc.methods})
			if tc.want && err != nil {
				t.Errorf("%s: 不应拒绝, got %v", tc.desc, err)
			}
			if !tc.want && !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("%s: err = %v, want ErrInvalidRequest", tc.desc, err)
			}
		}
	})

	t.Run("Create oauth_providers key 存在性", func(t *testing.T) {
		store := newFakeClientStore()
		keys := &fakeProviderKeys{existing: existingProviderKeys}
		svc := NewClientService(store, keys)
		if err := svc.CreateSsoClient(ctx, SsoClientInput{OauthProviders: []string{"wx_mp", "github"}}); err != nil {
			t.Fatalf("存在的 key 不应拒绝: %v", err)
		}
		if len(keys.lookupKeys) != 2 {
			t.Errorf("应逐 key 查询存在性, got %v", keys.lookupKeys)
		}
		err := svc.CreateSsoClient(ctx, SsoClientInput{OauthProviders: []string{"wx_mp", "ghost"}})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("不存在的 key err = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("Create default_redirect_uri 白名单与列宽", func(t *testing.T) {
		for _, tc := range []struct {
			uris []string
			def  string
			want bool
			desc string
		}{
			{[]string{"https://app.example.com/cb"}, "https://app.example.com/cb", true, "字面命中"},
			{[]string{"*"}, "https://anything.example.org/x", true, "整段通配命中"},
			{[]string{"https://*.example.com/cb"}, "https://a.example.com/cb", true, "段通配命中"},
			{[]string{"https://app.example.com/cb"}, "https://other.example.com/cb", false, "不命中"},
			{nil, "https://app.example.com/cb", false, "白名单为空不命中"},
			{[]string{"https://app.example.com/cb"}, "https://" + strings.Repeat("a", 1100), false, "超 VARCHAR(1024) 列宽"},
			{[]string{"https://app.example.com/cb"}, "", true, "空 = 未配置"},
		} {
			store := newFakeClientStore()
			svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
			err := svc.CreateSsoClient(ctx, SsoClientInput{RedirectURIs: tc.uris, DefaultRedirectURI: tc.def})
			if tc.want && err != nil {
				t.Errorf("%s: 不应拒绝, got %v", tc.desc, err)
			}
			if !tc.want && !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("%s: err = %v, want ErrInvalidRequest", tc.desc, err)
			}
		}
	})

	t.Run("Create 三字段 round-trip", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
		in := SsoClientInput{
			RedirectURIs:       []string{"https://*.example.com/cb"},
			LoginMethods:       []string{"password", "thirdparty"},
			OauthProviders:     []string{"wx_mp"},
			DefaultRedirectURI: "https://app.example.com/cb",
		}
		if err := svc.CreateSsoClient(ctx, in); err != nil {
			t.Fatalf("Create: %v", err)
		}
		d, err := svc.GetSsoClient(ctx, 1)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if strings.Join(d.LoginMethods, "|") != "password|thirdparty" {
			t.Errorf("login_methods round-trip = %v", d.LoginMethods)
		}
		if strings.Join(d.OauthProviders, "|") != "wx_mp" {
			t.Errorf("oauth_providers round-trip = %v", d.OauthProviders)
		}
		if d.Row.DefaultRedirectURI != "https://app.example.com/cb" {
			t.Errorf("default_redirect_uri = %q", d.Row.DefaultRedirectURI)
		}
	})

	t.Run("Update has 位整组替换与空数组跟随全局", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
		if err := svc.CreateSsoClient(ctx, SsoClientInput{
			ClientID:       "portal",
			RedirectURIs:   []string{"https://*.example.com/cb"},
			LoginMethods:   []string{"password"},
			OauthProviders: []string{"wx_mp"},
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{HasLoginMethods: true, LoginMethods: []string{"otp_sms", "thirdparty"}}); err != nil {
			t.Fatalf("Update login_methods: %v", err)
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{HasOauthProviders: true, OauthProviders: []string{"github"}}); err != nil {
			t.Fatalf("Update oauth_providers: %v", err)
		}
		d, err := svc.GetSsoClient(ctx, 1)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if strings.Join(d.LoginMethods, "|") != "otp_sms|thirdparty" {
			t.Errorf("has=true 应整组替换, got %v", d.LoginMethods)
		}
		if strings.Join(d.OauthProviders, "|") != "github" {
			t.Errorf("has=true 应整组替换, got %v", d.OauthProviders)
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{HasLoginMethods: true, LoginMethods: nil}); err != nil {
			t.Fatalf("Update 空数组: %v", err)
		}
		d, err = svc.GetSsoClient(ctx, 1)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(d.LoginMethods) != 0 {
			t.Errorf("has=true 空数组应清空为跟随全局, got %v", d.LoginMethods)
		}
		if len(d.OauthProviders) != 1 || d.OauthProviders[0] != "github" {
			t.Errorf("未提交的 oauth_providers 应保留, got %v", d.OauthProviders)
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{HasOauthProviders: true, OauthProviders: []string{"ghost"}}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("不存在的 key err = %v, want ErrInvalidRequest", err)
		}
		d, _ = svc.GetSsoClient(ctx, 1)
		if len(d.OauthProviders) != 1 || d.OauthProviders[0] != "github" {
			t.Errorf("校验失败不应改库, got %v", d.OauthProviders)
		}
	})

	t.Run("Update 无 has 位回归", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
		if err := svc.CreateSsoClient(ctx, SsoClientInput{
			ClientID:     "portal",
			RedirectURIs: []string{"https://app.example.com/cb"},
			LoginMethods: []string{"password"},
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{
			Name:           "改名",
			LoginMethods:   []string{"webauthn"},
			OauthProviders: []string{"wx_mp"},
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		d, err := svc.GetSsoClient(ctx, 1)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if strings.Join(d.LoginMethods, "|") != "password" {
			t.Errorf("无 has 位应保留原值, got %v", d.LoginMethods)
		}
		if len(d.OauthProviders) != 0 {
			t.Errorf("无 has 位应保留原值, got %v", d.OauthProviders)
		}
		if d.Row.DefaultRedirectURI != "" {
			t.Errorf("default 未提交应保留原值, got %q", d.Row.DefaultRedirectURI)
		}
	})

	t.Run("Update default_redirect_uri 清空与合并白名单", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
		if err := svc.CreateSsoClient(ctx, SsoClientInput{
			ClientID:           "portal",
			RedirectURIs:       []string{"https://app.example.com/cb"},
			DefaultRedirectURI: "https://app.example.com/cb",
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{DefaultRedirectURI: strPtr("")}); err != nil {
			t.Fatalf("Update 清空: %v", err)
		}
		d, err := svc.GetSsoClient(ctx, 1)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if d.Row.DefaultRedirectURI != "" {
			t.Errorf("非 nil 空串应清空, got %q", d.Row.DefaultRedirectURI)
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{
			RedirectURIs:       []string{"https://new.example.com/cb"},
			DefaultRedirectURI: strPtr("https://app.example.com/cb"),
		}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("对合并后白名单不命中 err = %v, want ErrInvalidRequest", err)
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{
			RedirectURIs:       []string{"https://new.example.com/cb"},
			DefaultRedirectURI: strPtr("https://new.example.com/cb"),
		}); err != nil {
			t.Fatalf("命中合并后白名单不应拒绝: %v", err)
		}
		d, _ = svc.GetSsoClient(ctx, 1)
		if d.Row.DefaultRedirectURI != "https://new.example.com/cb" {
			t.Errorf("default_redirect_uri = %q", d.Row.DefaultRedirectURI)
		}
	})

	t.Run("Update 列宽防御", func(t *testing.T) {
		store := newFakeClientStore()
		svc := NewClientService(store, &fakeProviderKeys{existing: existingProviderKeys})
		if err := svc.CreateSsoClient(ctx, SsoClientInput{ClientID: "portal"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		big := make([]string, 90)
		for i := range big {
			big[i] = "thirdparty"
		}
		if err := svc.UpdateSsoClient(ctx, 1, SsoClientPatch{HasLoginMethods: true, LoginMethods: big}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("超 VARBINARY(1024) err = %v, want ErrInvalidRequest", err)
		}
	})
}

// strPtr 测试辅助：构造 optional string 的指针入参（nil = 不动 / 非 nil =
// 提交，空串 = 清空）。
func strPtr(s string) *string { return &s }
