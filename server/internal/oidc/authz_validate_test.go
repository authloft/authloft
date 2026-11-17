// authz_validate.go 测试：client_id 存在且启用、redirect_uri 白名单
// （§12.3 整段匹配 / * 通配）、scope 封闭集 / 注册超集 / 必含 openid、
// 校验顺序（client → redirect → scope）与错误分类。
package oidc

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	clientpb "authloft/gen/go/client"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// fakeAuthzClients ClientFinder fake：err 模拟查询故障（非未命中）。
type fakeAuthzClients struct {
	clients map[string]*model.OidcClient
	err     error
}

func (f *fakeAuthzClients) FindOidcClientByClientID(_ context.Context, clientID string) (*model.OidcClient, error) {
	if f.err != nil {
		return nil, f.err
	}
	c, ok := f.clients[clientID]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return c, nil
}

// newAuthzClient 构造启用客户端行，uris 经 §12.3 唯一编解码出口落字节。
func newAuthzClient(clientID string, uris []string, scopes string) *model.OidcClient {
	data, err := repo.MarshalClientRedirectUris(&clientpb.ClientRedirectUris{Uris: uris})
	if err != nil {
		panic(err)
	}
	return &model.OidcClient{
		ClientID:     clientID,
		RedirectURIs: data,
		Scopes:       scopes,
		IsEnabled:    1,
	}
}

func TestAuthzValidateClient(t *testing.T) {
	ctx := context.Background()
	clients := map[string]*model.OidcClient{
		"app": newAuthzClient("app", []string{"https://app.example.com/cb"}, "openid,profile,email"),
	}
	disabled := newAuthzClient("off", []string{"https://off.example.com/cb"}, "openid")
	disabled.IsEnabled = 0
	clients["off"] = disabled

	for _, tc := range []struct {
		name     string
		clientID string
		want     error
	}{
		{"空 client_id", "", ErrAuthzClient},
		{"未注册", "ghost", ErrAuthzClient},
		{"未启用", "off", ErrAuthzClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &AuthzValidator{Clients: &fakeAuthzClients{clients: clients}}
			_, err := v.Validate(ctx, tc.clientID, "https://app.example.com/cb", "openid")
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("查询故障不吞成参数错误", func(t *testing.T) {
		v := &AuthzValidator{Clients: &fakeAuthzClients{err: errors.New("db down")}}
		_, err := v.Validate(ctx, "app", "https://app.example.com/cb", "openid")
		if errors.Is(err, ErrAuthzClient) || err == nil {
			t.Errorf("err = %v, want 非 ErrAuthzClient 的包装错误", err)
		}
	})
	t.Run("依赖未注入", func(t *testing.T) {
		v := &AuthzValidator{}
		if _, err := v.Validate(ctx, "app", "https://app.example.com/cb", "openid"); err == nil {
			t.Error("nil Clients 应报错")
		}
	})
}

func TestAuthzValidateRedirectURI(t *testing.T) {
	ctx := context.Background()
	v := &AuthzValidator{Clients: &fakeAuthzClients{clients: map[string]*model.OidcClient{
		"app": newAuthzClient("app", []string{
			"https://app.example.com/cb",
			"https://*.dev.example.com/cb",
			"http://localhost:*/callback",
		}, "openid,profile"),
		// 字面 * 条目命中任意 URI，单独建客户端验证。
		"wild": newAuthzClient("wild", []string{"*"}, "openid"),
	}}}
	for _, tc := range []struct {
		name, clientID, uri string
		want                error
	}{
		{"字面命中", "app", "https://app.example.com/cb", nil},
		{"前缀通配命中", "app", "https://abc.dev.example.com/cb", nil},
		{"通配跨段命中", "app", "https://a.b.dev.example.com/cb", nil},
		{"端口段通配命中", "app", "http://localhost:3000/callback", nil},
		{"字面 * 命中任意", "wild", "https://anything.example.net/x", nil},
		{"路径未命中", "app", "https://app.example.com/other", ErrAuthzRedirect},
		{"方案未命中", "app", "ftp://app.example.com/cb", ErrAuthzRedirect},
		{"空 redirect_uri", "app", "", ErrAuthzRedirect},
		{"白名单外主机", "app", "https://evil.example.com/cb", ErrAuthzRedirect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Validate(ctx, tc.clientID, tc.uri, "openid")
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate(%q) err = %v, want %v", tc.uri, err, tc.want)
			}
		})
	}
	t.Run("空白名单全拒", func(t *testing.T) {
		v := &AuthzValidator{Clients: &fakeAuthzClients{clients: map[string]*model.OidcClient{
			"app": newAuthzClient("app", nil, "openid"),
		}}}
		if _, err := v.Validate(ctx, "app", "https://app.example.com/cb", "openid"); !errors.Is(err, ErrAuthzRedirect) {
			t.Errorf("err = %v, want ErrAuthzRedirect", err)
		}
	})
}

func TestAuthzValidateScope(t *testing.T) {
	ctx := context.Background()
	v := &AuthzValidator{Clients: &fakeAuthzClients{clients: map[string]*model.OidcClient{
		// scopes 含迁移补齐产物形态（空首元素），解析须容错。
		"app": newAuthzClient("app", []string{"https://app.example.com/cb"}, ",openid,profile"),
	}}}
	for _, tc := range []struct {
		name, scope string
		want        error
	}{
		{"空格口径通过", "openid profile", nil},
		{"双口径混排按集合判定", "openid,profile email", ErrAuthzScope}, // email 未注册
		{"注册侧空首元素容错", "openid", nil},
		{"含未支持值", "openid admin", ErrAuthzScope},
		{"超出注册 scopes", "openid profile email", ErrAuthzScope},
		{"缺 openid", "profile", ErrAuthzScope},
		{"空 scope", "", ErrAuthzScope},
		{"纯分隔符 scope", " , ", ErrAuthzScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Validate(ctx, "app", "https://app.example.com/cb", tc.scope)
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate(scope=%q) err = %v, want %v", tc.scope, err, tc.want)
			}
		})
	}
}

func TestAuthzValidateOrderAndReturn(t *testing.T) {
	ctx := context.Background()
	clients := map[string]*model.OidcClient{
		"app": newAuthzClient("app", []string{"https://app.example.com/cb"}, "openid,profile"),
	}
	v := &AuthzValidator{Clients: &fakeAuthzClients{clients: clients}}
	t.Run("client 优先于 redirect 与 scope", func(t *testing.T) {
		_, err := v.Validate(ctx, "ghost", "https://evil.example.com", "admin")
		if !errors.Is(err, ErrAuthzClient) {
			t.Errorf("err = %v, want ErrAuthzClient", err)
		}
	})
	t.Run("redirect 优先于 scope（302 档位前提）", func(t *testing.T) {
		_, err := v.Validate(ctx, "app", "https://evil.example.com", "admin")
		if !errors.Is(err, ErrAuthzRedirect) {
			t.Errorf("err = %v, want ErrAuthzRedirect", err)
		}
	})
	t.Run("通过返回客户端行", func(t *testing.T) {
		client, err := v.Validate(ctx, "app", "https://app.example.com/cb", "openid profile")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if client == nil || client.ClientID != "app" {
			t.Errorf("client = %+v, want app 行", client)
		}
	})
}
