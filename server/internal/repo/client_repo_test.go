// sso_client / oidc_client 表 repo 层测试：真实 MariaDB 测试
// 实例经 UC_TEST_MYSQL_DSN env 注入，无 env 时集成用例 skip（redirect_uris
// 编解码纯函数用例始终本地可跑）。表结构由 migrate.Up 建（§3.16 DDL 唯一
// 来源）；用例开始 drop 全表、结束 drop 全表 + assertNoTables 自证零残留
// （同既有 repo 测试口径）。跨二进制互斥由
// settings_repo_test.go 的 TestMain（GET_LOCK uc_test_db_slot）保证；共享
// 辅助 dropAllTables / assertNoTables / dbTestConfig 在彼处与 db_test.go。
// 连接串只经环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	"authloft/gen/go/client"
	"authloft/internal/migrate"
	"authloft/internal/repo/model"
)

// clientTestSetup 清库 + 建表 + 注册测后零残留清理，返回就绪的 ClientRepo。
func clientTestSetup(t *testing.T) *ClientRepo {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 client repo 集成用例")
	}
	ctx := context.Background()
	raw, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := raw.Ping(); err != nil {
		t.Fatalf("连接 MariaDB 测试实例失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := dropAllTables(raw); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	if err := migrate.Up(ctx, dsn); err != nil {
		t.Fatalf("migrate up 失败: %v", err)
	}
	t.Cleanup(func() {
		if err := dropAllTables(raw); err != nil {
			t.Errorf("测后清空测试库失败: %v", err)
		}
		if err := assertNoTables(raw); err != nil {
			t.Errorf("零残留自证失败: %v", err)
		}
	})
	db, err := Open(dbTestConfig(dsn, 10, 5, time.Minute))
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return NewClientRepo(db)
}

// clientTestUris 构造覆盖 §12.3 的样例回调白名单（含 `*` 通配）。
func clientTestUris() *client.ClientRedirectUris {
	return &client.ClientRedirectUris{
		Uris: []string{
			"https://app.example.com/callback",
			"https://*.example.com/*",
		},
	}
}

// TestClientRepoRedirectUrisRoundTrip（纯函数，无 env 本地可跑）：
// Marshal 与 Parse 互逆（proto.Equal 逐字段）；nil / 空输入边界；坏字节
// 解析报错。
func TestClientRepoRedirectUrisRoundTrip(t *testing.T) {
	// nil → 非 nil 零长字节（redirect_uris NOT NULL，不能写 NULL）→ Parse
	// 回非 nil 空消息。
	data, err := MarshalClientRedirectUris(nil)
	if err != nil || data == nil || len(data) != 0 {
		t.Fatalf("Marshal(nil) = %v(len %d), %v; want 非 nil 零长字节, nil", data, len(data), err)
	}
	got, err := ParseClientRedirectUris(data)
	if err != nil || got == nil || len(got.Uris) != 0 {
		t.Fatalf("Parse(Marshal(nil)) = %v, %v; want 非 nil 空消息, nil", got, err)
	}

	// 空消息 → 零长字节（非 nil）→ 解析回非 nil 空消息。
	data, err = MarshalClientRedirectUris(&client.ClientRedirectUris{})
	if err != nil {
		t.Fatalf("Marshal(空消息) 失败: %v", err)
	}
	if data == nil || len(data) != 0 {
		t.Errorf("空消息序列化应为非 nil 零长字节, got %v(len %d)", data, len(data))
	}
	got, err = ParseClientRedirectUris(nil)
	if err != nil || got == nil || len(got.Uris) != 0 {
		t.Fatalf("Parse(nil) = %v, %v; want 非 nil 空消息, nil", got, err)
	}

	// 样例 round-trip：proto.Equal 逐字段比较。
	src := clientTestUris()
	data, err = MarshalClientRedirectUris(src)
	if err != nil {
		t.Fatalf("Marshal 样例失败: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("样例序列化不应为零长度")
	}
	got, err = ParseClientRedirectUris(data)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if !proto.Equal(src, got) {
		t.Errorf("round-trip 后消息不一致:\nsrc = %v\ngot = %v", src, got)
	}

	// 坏字节解析报错（非 Protobuf 线格式）。
	if _, err := ParseClientRedirectUris([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Error("坏字节解析应报错, got nil error")
	}
}

// TestClientRepoSsoClientCRUD（env-skip）：Create 默认值回填 → 按
// client_id 命中与字段一致（redirect_uris 落库读回 round-trip）→
// uk_client_id 冲突判别与不入库 → Update 覆盖、同值幂等、不存在报
// not found → Delete 与重复 Delete。
func TestClientRepoSsoClientCRUD(t *testing.T) {
	rp := clientTestSetup(t)
	ctx := context.Background()

	urisData, err := MarshalClientRedirectUris(clientTestUris())
	if err != nil {
		t.Fatalf("MarshalClientRedirectUris 失败: %v", err)
	}
	c := &model.SsoClient{
		ClientID:     "sso_app",
		ClientSecret: strings.Repeat("s", 64),
		Name:         "SSO 应用",
		RedirectURIs: urisData,
	}
	if err := rp.CreateSsoClient(ctx, c); err != nil {
		t.Fatalf("CreateSsoClient 失败: %v", err)
	}
	if c.ID == 0 {
		t.Fatal("Create 后 ID 应非零（自增回填）")
	}
	if c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() {
		t.Error("Create 应自动填充 created_at / updated_at")
	}
	// default tag 值回填（§4.4 DDL 默认：name '' / is_enabled 1）。
	if c.IsEnabled != 1 {
		t.Errorf("Create 后 is_enabled 默认值回填 = %d, want 1", c.IsEnabled)
	}

	got, err := rp.FindSsoClientByClientID(ctx, "sso_app")
	if err != nil {
		t.Fatalf("FindSsoClientByClientID 失败: %v", err)
	}
	if got.ID != c.ID || got.Name != "SSO 应用" ||
		got.ClientSecret != strings.Repeat("s", 64) || got.IsEnabled != 1 {
		t.Errorf("FindSsoClientByClientID 字段不一致: %+v", got)
	}
	// redirect_uris 落库读回：字节一致 → Parse 后 proto 相等。
	if string(got.RedirectURIs) != string(urisData) {
		t.Errorf("redirect_uris 落库读回字节不一致: %d vs %d bytes", len(got.RedirectURIs), len(urisData))
	}
	urisParsed, err := ParseClientRedirectUris(got.RedirectURIs)
	if err != nil {
		t.Fatalf("ParseClientRedirectUris(落库值) 失败: %v", err)
	}
	if !proto.Equal(clientTestUris(), urisParsed) {
		t.Error("redirect_uris 落库读回 round-trip 不一致")
	}

	// 未命中。
	if _, err := rp.FindSsoClientByClientID(ctx, "nope"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("未命中应 ErrRecordNotFound, got %v", err)
	}

	// uk_client_id 冲突：同 client_id 再建 → ErrClientDuplicate，不入库。
	if err := rp.CreateSsoClient(ctx, &model.SsoClient{
		ClientID: "sso_app", ClientSecret: strings.Repeat("x", 64),
		RedirectURIs: urisData,
	}); !errors.Is(err, ErrClientDuplicate) {
		t.Errorf("同 client_id 冲突应 ErrClientDuplicate, got %v", err)
	}
	if _, total, err := rp.ListSsoClients(ctx, ClientListQuery{}); err != nil || total != 1 {
		t.Errorf("冲突不应入库: total=%d err=%v; want 1/nil", total, err)
	}

	// Update：改 name / 置 is_enabled=0（列级 UPDATE 落 0，default tag 只
	// 影响 Create）/ 换 redirect_uris。
	got.Name = "SSO 应用改名"
	got.IsEnabled = 0
	newUris, err := MarshalClientRedirectUris(&client.ClientRedirectUris{Uris: []string{"https://new.example.com/cb"}})
	if err != nil {
		t.Fatalf("MarshalClientRedirectUris 二次失败: %v", err)
	}
	got.RedirectURIs = newUris
	if err := rp.UpdateSsoClient(ctx, got); err != nil {
		t.Fatalf("UpdateSsoClient 失败: %v", err)
	}
	after, err := rp.FindSsoClientByClientID(ctx, "sso_app")
	if err != nil {
		t.Fatalf("Update 后 Find 失败: %v", err)
	}
	if after.Name != "SSO 应用改名" || after.IsEnabled != 0 {
		t.Errorf("Update 后字段不一致: %+v", after)
	}
	urisAfter, err := ParseClientRedirectUris(after.RedirectURIs)
	if err != nil || len(urisAfter.Uris) != 1 || urisAfter.Uris[0] != "https://new.example.com/cb" {
		t.Errorf("Update 后 redirect_uris 不一致: %v, %v", urisAfter, err)
	}
	// 同值二次 Update：changed-rows 语义 rows=0 但行存在 → 幂等成功。
	if err := rp.UpdateSsoClient(ctx, after); err != nil {
		t.Errorf("同值二次 Update 应幂等成功: %v", err)
	}

	// Update 不存在的行（带合法时间避免零值 DATETIME 先报错）。
	ghostAt := time.Now().Truncate(time.Second)
	ghost := &model.SsoClient{
		ID: 404, ClientID: "ghost", ClientSecret: strings.Repeat("g", 64),
		RedirectURIs: urisData, CreatedAt: ghostAt, UpdatedAt: ghostAt,
	}
	if err := rp.UpdateSsoClient(ctx, ghost); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Update 不存在的行应 ErrRecordNotFound, got %v", err)
	}

	// Delete：删后查无此行；重复删可判别 not found。
	if err := rp.DeleteSsoClient(ctx, c.ID); err != nil {
		t.Fatalf("DeleteSsoClient 失败: %v", err)
	}
	if _, err := rp.FindSsoClientByClientID(ctx, "sso_app"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Delete 后 Find 应 ErrRecordNotFound, got %v", err)
	}
	if err := rp.DeleteSsoClient(ctx, c.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("重复 Delete 应 ErrRecordNotFound, got %v", err)
	}

	// redirect_uris 列 NOT NULL：nil 入参编码为非 nil 零长字节，可直接
	// Create 落库（证明不触发 MySQL 1048）；读回 Parse 为空消息。
	emptyData, err := MarshalClientRedirectUris(nil)
	if err != nil {
		t.Fatalf("MarshalClientRedirectUris(nil) 失败: %v", err)
	}
	empty := &model.SsoClient{
		ClientID: "sso_empty_uris", ClientSecret: strings.Repeat("e", 64), RedirectURIs: emptyData,
	}
	if err := rp.CreateSsoClient(ctx, empty); err != nil {
		t.Fatalf("redirect_uris 空值 Create 应成功（NOT NULL 不得写 NULL）, got %v", err)
	}
	gotEmpty, err := rp.FindSsoClientByClientID(ctx, "sso_empty_uris")
	if err != nil {
		t.Fatalf("空 redirect_uris 行 Find 失败: %v", err)
	}
	emptyParsed, err := ParseClientRedirectUris(gotEmpty.RedirectURIs)
	if err != nil || len(emptyParsed.Uris) != 0 {
		t.Errorf("空 redirect_uris 读回 = %v, %v; want 空消息, nil", emptyParsed, err)
	}
}

// TestClientRepoOidcClientCRUD（env-skip）：Create 默认值回填（scopes /
// 两个 TTL / is_enabled）→ 按 client_id 命中 → uk_client_id 冲突判别 →
// Update（含 TTL / scopes / is_enabled=0）→ Delete 与重复 Delete。
func TestClientRepoOidcClientCRUD(t *testing.T) {
	rp := clientTestSetup(t)
	ctx := context.Background()

	urisData, err := MarshalClientRedirectUris(clientTestUris())
	if err != nil {
		t.Fatalf("MarshalClientRedirectUris 失败: %v", err)
	}
	c := &model.OidcClient{
		ClientID:     "oidc_app",
		ClientSecret: strings.Repeat("o", 64),
		Name:         "OIDC 应用",
		RedirectURIs: urisData,
	}
	if err := rp.CreateOidcClient(ctx, c); err != nil {
		t.Fatalf("CreateOidcClient 失败: %v", err)
	}
	if c.ID == 0 {
		t.Fatal("Create 后 ID 应非零（自增回填）")
	}
	// default tag 值回填（§4.5 DDL 默认：scopes 'openid,profile,email' /
	// access_token_ttl 3600 / refresh_token_ttl 2592000 / is_enabled 1）。
	if c.Scopes != "openid,profile,email" || c.AccessTokenTTL != 3600 ||
		c.RefreshTokenTTL != 2592000 || c.IsEnabled != 1 {
		t.Errorf("Create 后默认值回填不一致: %+v", c)
	}

	got, err := rp.FindOidcClientByClientID(ctx, "oidc_app")
	if err != nil {
		t.Fatalf("FindOidcClientByClientID 失败: %v", err)
	}
	if got.Name != "OIDC 应用" || got.Scopes != "openid,profile,email" ||
		got.AccessTokenTTL != 3600 || got.RefreshTokenTTL != 2592000 {
		t.Errorf("FindOidcClientByClientID 字段不一致: %+v", got)
	}
	if string(got.RedirectURIs) != string(urisData) {
		t.Errorf("oidc redirect_uris 落库读回字节不一致: %d vs %d bytes", len(got.RedirectURIs), len(urisData))
	}

	// 未命中。
	if _, err := rp.FindOidcClientByClientID(ctx, "nope"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("未命中应 ErrRecordNotFound, got %v", err)
	}

	// uk_client_id 冲突。
	if err := rp.CreateOidcClient(ctx, &model.OidcClient{
		ClientID: "oidc_app", ClientSecret: strings.Repeat("z", 64),
		RedirectURIs: urisData,
	}); !errors.Is(err, ErrClientDuplicate) {
		t.Errorf("同 client_id 冲突应 ErrClientDuplicate, got %v", err)
	}
	if _, total, err := rp.ListOidcClients(ctx, ClientListQuery{}); err != nil || total != 1 {
		t.Errorf("冲突不应入库: total=%d err=%v; want 1/nil", total, err)
	}

	// Update：改 scopes / 两个 TTL / is_enabled=0 / redirect_uris。
	got.Scopes = "openid,email,offline_access"
	got.AccessTokenTTL = 1800
	got.RefreshTokenTTL = 86400
	got.IsEnabled = 0
	newUris, err := MarshalClientRedirectUris(&client.ClientRedirectUris{Uris: []string{"https://oidc.example.com/cb"}})
	if err != nil {
		t.Fatalf("MarshalClientRedirectUris 二次失败: %v", err)
	}
	got.RedirectURIs = newUris
	if err := rp.UpdateOidcClient(ctx, got); err != nil {
		t.Fatalf("UpdateOidcClient 失败: %v", err)
	}
	after, err := rp.FindOidcClientByClientID(ctx, "oidc_app")
	if err != nil {
		t.Fatalf("Update 后 Find 失败: %v", err)
	}
	if after.Scopes != "openid,email,offline_access" || after.AccessTokenTTL != 1800 ||
		after.RefreshTokenTTL != 86400 || after.IsEnabled != 0 {
		t.Errorf("Update 后字段不一致: %+v", after)
	}
	urisAfter, err := ParseClientRedirectUris(after.RedirectURIs)
	if err != nil || len(urisAfter.Uris) != 1 || urisAfter.Uris[0] != "https://oidc.example.com/cb" {
		t.Errorf("Update 后 redirect_uris 不一致: %v, %v", urisAfter, err)
	}
	// 同值二次 Update 幂等成功。
	if err := rp.UpdateOidcClient(ctx, after); err != nil {
		t.Errorf("同值二次 Update 应幂等成功: %v", err)
	}

	// Update 不存在的行。
	ghostAt := time.Now().Truncate(time.Second)
	ghost := &model.OidcClient{
		ID: 404, ClientID: "ghost", ClientSecret: strings.Repeat("g", 64),
		Scopes: "openid", AccessTokenTTL: 3600, RefreshTokenTTL: 2592000,
		RedirectURIs: urisData, CreatedAt: ghostAt, UpdatedAt: ghostAt,
	}
	if err := rp.UpdateOidcClient(ctx, ghost); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Update 不存在的行应 ErrRecordNotFound, got %v", err)
	}

	// Delete 与重复 Delete。
	if err := rp.DeleteOidcClient(ctx, c.ID); err != nil {
		t.Fatalf("DeleteOidcClient 失败: %v", err)
	}
	if _, err := rp.FindOidcClientByClientID(ctx, "oidc_app"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Delete 后 Find 应 ErrRecordNotFound, got %v", err)
	}
	if err := rp.DeleteOidcClient(ctx, c.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("重复 Delete 应 ErrRecordNotFound, got %v", err)
	}
}

// TestClientRepoList（env-skip）：两表分页列表 + §1.7 分页参数归一 + 表间
// 互不串扰。缺省排序 id DESC（orderClause：order 非 asc 一律
// desc，口径同 user_repo）；排序应用 / 回落专项见 TestClientRepoListSort。
func TestClientRepoList(t *testing.T) {
	rp := clientTestSetup(t)
	ctx := context.Background()

	urisData, err := MarshalClientRedirectUris(clientTestUris())
	if err != nil {
		t.Fatalf("MarshalClientRedirectUris 失败: %v", err)
	}
	for _, id := range []string{"sso_1", "sso_2", "sso_3"} {
		if err := rp.CreateSsoClient(ctx, &model.SsoClient{
			ClientID: id, ClientSecret: strings.Repeat("s", 64), RedirectURIs: urisData,
		}); err != nil {
			t.Fatalf("CreateSsoClient %s 失败: %v", id, err)
		}
	}
	for _, id := range []string{"oidc_1", "oidc_2"} {
		if err := rp.CreateOidcClient(ctx, &model.OidcClient{
			ClientID: id, ClientSecret: strings.Repeat("o", 64), RedirectURIs: urisData,
		}); err != nil {
			t.Fatalf("CreateOidcClient %s 失败: %v", id, err)
		}
	}

	// 无分页参数：默认 page1 size20；sort / order 缺省 → id DESC。
	ssoRows, ssoTotal, err := rp.ListSsoClients(ctx, ClientListQuery{})
	if err != nil || ssoTotal != 3 || len(ssoRows) != 3 {
		t.Fatalf("SSO 全量 = %d 行 total=%d err=%v; want 3/3/nil", len(ssoRows), ssoTotal, err)
	}
	for i, want := range []string{"sso_3", "sso_2", "sso_1"} {
		if ssoRows[i].ClientID != want {
			t.Errorf("SSO 顺序[%d] = %s, want %s（id DESC）", i, ssoRows[i].ClientID, want)
		}
	}
	// 分页：page2 size2 → 只剩 sso_1，total 仍为 3。
	if rows, total, err := rp.ListSsoClients(ctx, ClientListQuery{Page: 2, PageSize: 2}); err != nil ||
		total != 3 || len(rows) != 1 || rows[0].ClientID != "sso_1" {
		t.Errorf("SSO page2 = %+v total=%d err=%v; want sso_1/3", rows, total, err)
	}
	// 分页参数归一：Page=0 归 1；PageSize<1 默认 20；PageSize>100 clamp。
	if rows, _, err := rp.ListSsoClients(ctx, ClientListQuery{Page: 0, PageSize: 2}); err != nil ||
		len(rows) != 2 || rows[0].ClientID != "sso_3" {
		t.Errorf("Page=0 应归 1: %+v err=%v", rows, err)
	}
	if _, _, err := rp.ListSsoClients(ctx, ClientListQuery{Page: 1, PageSize: 150}); err != nil {
		t.Errorf("PageSize=150 应 clamp 100 不报错: %v", err)
	}

	// OIDC 列表：2 行，表间互不串扰。
	oidcRows, oidcTotal, err := rp.ListOidcClients(ctx, ClientListQuery{})
	if err != nil || oidcTotal != 2 || len(oidcRows) != 2 {
		t.Fatalf("OIDC 全量 = %d 行 total=%d err=%v; want 2/2/nil", len(oidcRows), oidcTotal, err)
	}
	for i, want := range []string{"oidc_2", "oidc_1"} {
		if oidcRows[i].ClientID != want {
			t.Errorf("OIDC 顺序[%d] = %s, want %s（id DESC）", i, oidcRows[i].ClientID, want)
		}
	}
}

// TestClientRepoListSort（env-skip）：ClientListQuery 的 sort /
// order 应用与防御——合法列名排序生效（asc / desc / 大小写不敏感）、sort
// 缺省 / 字符集外（含注入尝试）静默回落 id、order 缺省 / 非 asc 一律 desc、
// 非 id 主序下同值行按 id DESC 次序不漂移（口径同 user_repo.ListUsers）。
func TestClientRepoListSort(t *testing.T) {
	rp := clientTestSetup(t)
	ctx := context.Background()

	urisData, err := MarshalClientRedirectUris(clientTestUris())
	if err != nil {
		t.Fatalf("MarshalClientRedirectUris 失败: %v", err)
	}
	// 4 行 SSO：name 与 id 序错开（id 1=beta / 2=alpha / 3=gamma），使 name
	// 排序与 id 排序可判别；行 4 与行 1 同 name（beta），验证非 id 主序下
	// 同值行按 id DESC 次序（4 在 1 前）分页不漂移。
	for _, tc := range []struct{ id, name string }{
		{"sso_1", "beta"}, {"sso_2", "alpha"}, {"sso_3", "gamma"}, {"sso_4", "beta"},
	} {
		if err := rp.CreateSsoClient(ctx, &model.SsoClient{
			ClientID: tc.id, ClientSecret: strings.Repeat("s", 64),
			Name: tc.name, RedirectURIs: urisData,
		}); err != nil {
			t.Fatalf("CreateSsoClient %s 失败: %v", tc.id, err)
		}
	}
	// 2 行 OIDC：name 与 id 序错开。
	for _, tc := range []struct{ id, name string }{
		{"oidc_1", "delta"}, {"oidc_2", "charlie"},
	} {
		if err := rp.CreateOidcClient(ctx, &model.OidcClient{
			ClientID: tc.id, ClientSecret: strings.Repeat("o", 64),
			Name: tc.name, RedirectURIs: urisData,
		}); err != nil {
			t.Fatalf("CreateOidcClient %s 失败: %v", tc.id, err)
		}
	}

	// sort=name, order=asc 生效；同值行（beta × 2）按 id DESC 次序。
	if rows, total, err := rp.ListSsoClients(ctx, ClientListQuery{Sort: "name", Order: "asc"}); err != nil || total != 4 {
		t.Fatalf("sort=name asc = %d 行 total=%d err=%v", len(rows), total, err)
	} else {
		for i, want := range []string{"sso_2", "sso_4", "sso_1", "sso_3"} {
			if rows[i].ClientID != want {
				t.Errorf("sort=name asc 顺序[%d] = %s, want %s", i, rows[i].ClientID, want)
			}
		}
	}
	// sort=name, order=desc 生效（大小写不敏感：DESC）；同值行次序不变。
	if rows, _, err := rp.ListSsoClients(ctx, ClientListQuery{Sort: "name", Order: "DESC"}); err != nil {
		t.Fatalf("sort=name DESC: %v", err)
	} else {
		for i, want := range []string{"sso_3", "sso_4", "sso_1", "sso_2"} {
			if rows[i].ClientID != want {
				t.Errorf("sort=name DESC 顺序[%d] = %s, want %s", i, rows[i].ClientID, want)
			}
		}
	}
	// sort=id, order=asc：主序即 id 时不追加次序，id ASC 形态可达。
	if rows, _, err := rp.ListSsoClients(ctx, ClientListQuery{Sort: "id", Order: "asc"}); err != nil {
		t.Fatalf("sort=id asc: %v", err)
	} else {
		for i, want := range []string{"sso_1", "sso_2", "sso_3", "sso_4"} {
			if rows[i].ClientID != want {
				t.Errorf("sort=id asc 顺序[%d] = %s, want %s", i, rows[i].ClientID, want)
			}
		}
	}
	// 非法 sort（字符集外 / 注入尝试）静默回落 id；order 缺省 → desc。
	for _, bad := range []string{"Name", "id; DROP TABLE sso_client", "id desc"} {
		if rows, _, err := rp.ListSsoClients(ctx, ClientListQuery{Sort: bad}); err != nil {
			t.Fatalf("非法 sort %q 应静默回落不报错: %v", bad, err)
		} else if rows[0].ClientID != "sso_4" {
			t.Errorf("非法 sort %q 应回落 id DESC（首行 sso_4）, got %s", bad, rows[0].ClientID)
		}
	}
	// order 非 asc（含乱值）一律 desc：首行应为最大 id。
	if rows, _, err := rp.ListSsoClients(ctx, ClientListQuery{Order: "bogus"}); err != nil || rows[0].ClientID != "sso_4" {
		t.Errorf("order 非法应一律 desc: %+v err=%v", rows, err)
	}
	// OIDC 表排序同样生效。
	if rows, _, err := rp.ListOidcClients(ctx, ClientListQuery{Sort: "name", Order: "desc"}); err != nil {
		t.Fatalf("OIDC sort=name desc: %v", err)
	} else {
		for i, want := range []string{"oidc_1", "oidc_2"} {
			if rows[i].ClientID != want {
				t.Errorf("OIDC sort=name desc 顺序[%d] = %s, want %s", i, rows[i].ClientID, want)
			}
		}
	}
}

// TestClientRepoFindByID（补齐 Find 操作主键形态的真库用例）：
// Create 回填 id → FindSsoClientByID / FindOidcClientByID 命中行与列值
// 一致；表间互不串扰；Delete 后再查 → gorm.ErrRecordNotFound。
func TestClientRepoFindByID(t *testing.T) {
	rp := clientTestSetup(t)
	ctx := context.Background()

	urisData, err := MarshalClientRedirectUris(clientTestUris())
	if err != nil {
		t.Fatalf("MarshalClientRedirectUris 失败: %v", err)
	}
	sso := &model.SsoClient{ClientID: "by_id_sso", ClientSecret: strings.Repeat("s", 64), Name: "SSO", RedirectURIs: urisData}
	if err := rp.CreateSsoClient(ctx, sso); err != nil {
		t.Fatalf("CreateSsoClient 失败: %v", err)
	}
	oidc := &model.OidcClient{ClientID: "by_id_oidc", ClientSecret: strings.Repeat("o", 64), Name: "OIDC", RedirectURIs: urisData}
	if err := rp.CreateOidcClient(ctx, oidc); err != nil {
		t.Fatalf("CreateOidcClient 失败: %v", err)
	}

	gotSso, err := rp.FindSsoClientByID(ctx, sso.ID)
	if err != nil || gotSso == nil || gotSso.ClientID != "by_id_sso" || gotSso.ClientSecret != strings.Repeat("s", 64) {
		t.Fatalf("FindSsoClientByID = %+v err=%v; want by_id_sso 行", gotSso, err)
	}
	gotOidc, err := rp.FindOidcClientByID(ctx, oidc.ID)
	if err != nil || gotOidc == nil || gotOidc.ClientID != "by_id_oidc" {
		t.Fatalf("FindOidcClientByID = %+v err=%v; want by_id_oidc 行", gotOidc, err)
	}
	// 顺带核对 OIDC default tag 回填（gorm 由 DB DEFAULT 回填，§4.5 行 736-737）。
	if gotOidc.AccessTokenTTL != 3600 || gotOidc.RefreshTokenTTL != 2592000 || gotOidc.Scopes != "openid,profile,email" {
		t.Errorf("OIDC default 回填 = (ttl=%d/%d scopes=%q), want 3600/2592000/openid,profile,email",
			gotOidc.AccessTokenTTL, gotOidc.RefreshTokenTTL, gotOidc.Scopes)
	}

	// Delete 后再查 → not found。
	if err := rp.DeleteSsoClient(ctx, sso.ID); err != nil {
		t.Fatalf("DeleteSsoClient 失败: %v", err)
	}
	if _, err := rp.FindSsoClientByID(ctx, sso.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Delete 后 FindSsoClientByID err = %v, want gorm.ErrRecordNotFound", err)
	}
	if _, err := rp.FindSsoClientByID(ctx, 1<<40); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("不存在主键 err = %v, want gorm.ErrRecordNotFound", err)
	}
}
