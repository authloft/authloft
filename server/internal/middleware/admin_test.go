// Admin 中间件单测（docs/接口文档.md §5 行 1145、docs/后端架构.md §21.2 E 行 1874）：
// 无会话 401 unauthorized、非管理员 404 not_found（掩护管理面）、uid=1 放行；
// 另含 Session → Admin 全链（未登录请求由 admin 判 401）。
package middleware

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"authloft/gen/go/token"
	"authloft/internal/codec"
	"authloft/internal/session"
)

// injectUID 测试助手：模拟 Session 中间件已注入的会话身份（uid>0）或未注入。
func injectUID(uid int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if uid > 0 {
			c.Request = c.Request.WithContext(
				session.WithSessionContext(c.Request.Context(), &token.SessionTokenPayload{Id: uid}))
		}
		c.Next()
	}
}

// nowUnix 当前 Unix 秒（载荷 iat/exp 构造用，session 包校验用真实时钟）。
func nowUnix() int64 { return time.Now().Unix() }

// ① ctx 无 uid（未携带有效会话）→ 401 unauthorized（§1.5 行 208）。
func TestAdminNoSessionReturns401(t *testing.T) {
	r := newTestRouter(Admin())
	r.GET("/api/admin/users", okHandler)

	rec := doRequest(r, http.MethodGet, "/api/admin/users", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	errObj := errorObject(t, decodeErrorBody(t, rec))
	if got := errObj["code"]; got != codec.CodeUnauthorized {
		t.Errorf("error.code = %v, want %q", got, codec.CodeUnauthorized)
	}
}

// ② 会话有效但 uid != 1 → 404 not_found（掩护管理面存在，§1.5 行 210）。
func TestAdminNonAdminReturns404(t *testing.T) {
	r := newTestRouter(injectUID(42), Admin())
	r.GET("/api/admin/users", okHandler)

	rec := doRequest(r, http.MethodGet, "/api/admin/users", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	errObj := errorObject(t, decodeErrorBody(t, rec))
	if got := errObj["code"]; got != codec.CodeNotFound {
		t.Errorf("error.code = %v, want %q", got, codec.CodeNotFound)
	}
}

// ③ uid == 1（安装时创建的固定管理员账号，§5 行 1143）→ 放行。
func TestAdminAdminUIDPasses(t *testing.T) {
	r := newTestRouter(injectUID(1), Admin())
	r.GET("/api/admin/users", okHandler)

	rec := doRequest(r, http.MethodGet, "/api/admin/users", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ④ Session → Admin 全链：未登录请求经 Session 放行后由 Admin 判 401；
// 管理员会话 200；普通用户会话 404。
func TestAdminAfterSessionMiddleware(t *testing.T) {
	env := newSessionEnv(t)
	admin := &token.SessionTokenPayload{
		Id: 1, Epoch: 7, Amr: []string{"pwd"}, Sid: "sid-admin",
		Iat: nowUnix(), Exp: nowUnix() + 3600,
	}
	user := &token.SessionTokenPayload{
		Id: 42, Epoch: 7, Amr: []string{"pwd"}, Sid: "sid-user",
		Iat: nowUnix(), Exp: nowUnix() + 3600,
	}
	env.epochs.values[admin.Id] = admin.Epoch
	env.epochs.values[user.Id] = user.Epoch

	r := newTestRouter(Session(env.verifier, env.renewer, env.cookie, nil), Admin())
	r.GET("/api/admin/me", okHandler)

	// 未登录（无令牌，Session 放行）→ 401 由 admin 产生。
	rec := doRequest(r, http.MethodGet, "/api/admin/me", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("未登录 status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// 管理员（uid=1）→ 200。
	req := newSessionRequest("/api/admin/me", nil)
	req.AddCookie(&http.Cookie{Name: "al_session", Value: env.sign(t, admin)})
	if rec := serveRequest(r, req); rec.Code != http.StatusOK {
		t.Errorf("管理员 status = %d, want %d", rec.Code, http.StatusOK)
	}

	// 普通用户（uid=42）→ 404。
	req2 := newSessionRequest("/api/admin/me", nil)
	req2.AddCookie(&http.Cookie{Name: "al_session", Value: env.sign(t, user)})
	if rec := serveRequest(r, req2); rec.Code != http.StatusNotFound {
		t.Errorf("普通用户 status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
