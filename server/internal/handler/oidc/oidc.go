// Package oidc 实现 OIDC REST 端点（docs/接口文档.md §4.1 行 1049-1057）：
// discovery / JWKS / token / revoke / userinfo / get_user_info。本包只做
// HTTP 绑定与编码，业务逻辑在 internal/oidc；OIDC 端点豁免 §1.0 统一信封，
// 按 RFC 6749 / 7009 / 6750 / 7517 原生格式输出。
//
// 路由由 Register 暴露，供装配层接到 bootstrap / router；本实现不接线。
// X-Request-Id 由既有 middleware.HTTPRequestID 在入口统一回写（§1.1），
// 本包不重复写。
package oidc

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/encoding/protojson"

	"authloft/internal/oidc"
)

// Deps 端点依赖（全部由装配层构造注入）。
type Deps struct {
	JWT      *oidc.JWT
	Tokens   *oidc.TokenService
	Revoker  *oidc.Revoker
	UserInfo *oidc.UserInfoService
}

// Register 注册全部 OIDC 路由（discovery / JWKS 无鉴权）。
func Register(r gin.IRouter, deps Deps) {
	h := &handler{deps: deps}
	r.GET("/.well-known/openid-configuration", h.discovery)
	r.GET("/.well-known/jwks.json", h.jwks)
	r.POST("/api/oidc/token", h.token)
	r.POST("/api/oidc/revoke", h.revoke)
	r.GET("/api/oidc/userinfo", h.userinfo)
	r.GET("/api/oidc/get_user_info", h.getUserInfo)
}

type handler struct {
	deps Deps
}

// OIDC 标准端点按 RFC 原生字段名（snake_case）输出：§4.3 / §4.5 的 JSON 示例
// 与 token.proto / userinfo.proto 字段注释逐字一致；get_user_info 走 §3.1
// Authloft 结构，按 §12.9 标准 protojson lowerCamelCase（avatarUrl / userStatus）。
var oidcJSON = protojson.MarshalOptions{UseProtoNames: true}

// discovery `GET /.well-known/openid-configuration`：issuer 与 JWT iss 逐字
// 相同（§14.1），端点由 issuer 派生。
func (h *handler) discovery(c *gin.Context) {
	issuer := h.deps.JWT.Issuer()
	body := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/auth/authorize",
		"token_endpoint":                        issuer + "/api/oidc/token",
		"revocation_endpoint":                   issuer + "/api/oidc/revoke",
		"userinfo_endpoint":                     issuer + "/api/oidc/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "phone", "phone_plain", "email_plain"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "server_error", "cannot encode discovery document")
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

// jwks `GET /.well-known/jwks.json`：全列表公钥（§14.1）。
func (h *handler) jwks(c *gin.Context) {
	raw, err := json.Marshal(h.deps.JWT.JWKS())
	if err != nil {
		writeError(c, http.StatusInternalServerError, "server_error", "cannot encode jwks")
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

// token `POST /api/oidc/token`：application/x-www-form-urlencoded（§4.3，
// 全站唯一例外；不绑定 JSON）。响应/错误统一 no-store。
func (h *handler) token(c *gin.Context) {
	setNoStore(c)
	if err := c.Request.ParseForm(); err != nil {
		writeOAuthError(c, &oidc.OAuthError{Status: 400, Code: oidc.ErrorInvalidRequest, Description: "invalid form body"})
		return
	}
	resp, oe := h.deps.Tokens.Token(c.Request.Context(), oidc.TokenInput{
		GrantType:    c.Request.PostForm.Get("grant_type"),
		Code:         c.Request.PostForm.Get("code"),
		RedirectURI:  c.Request.PostForm.Get("redirect_uri"),
		ClientID:     c.Request.PostForm.Get("client_id"),
		ClientSecret: c.Request.PostForm.Get("client_secret"),
		CodeVerifier: c.Request.PostForm.Get("code_verifier"),
		RefreshToken: c.Request.PostForm.Get("refresh_token"),
	})
	if oe != nil {
		writeOAuthError(c, oe)
		return
	}
	// RFC 6749 §5.1：expires_in 必须是 JSON number；OIDC 端点豁免 §1.0
	// 信封，不走 §12.9 的 int64→十进制字符串映射。
	writeJSON(c, http.StatusOK, tokenView{
		AccessToken:  resp.GetAccessToken(),
		TokenType:    resp.GetTokenType(),
		ExpiresIn:    resp.GetExpiresIn(),
		RefreshToken: resp.GetRefreshToken(),
		IDToken:      resp.GetIdToken(),
		Scope:        resp.GetScope(),
	})
}

// tokenView token 成功响应视图（§4.3 字段名逐字一致，snake_case）。
type tokenView struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// revoke `POST /api/oidc/revoke`：成功 / 未知 / 已吊销统一 200 空 body
// （RFC 7009、§4.4），不得返回 `{}`。
func (h *handler) revoke(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		writeOAuthError(c, &oidc.OAuthError{Status: 400, Code: oidc.ErrorInvalidRequest, Description: "invalid form body"})
		return
	}
	oe := h.deps.Revoker.Revoke(
		c.Request.Context(),
		c.Request.PostForm.Get("client_id"),
		c.Request.PostForm.Get("client_secret"),
		c.Request.PostForm.Get("token"),
		c.Request.PostForm.Get("token_type_hint"),
	)
	if oe != nil {
		writeOAuthError(c, oe)
		return
	}
	c.Status(http.StatusOK)
}

// userinfo `GET /api/oidc/userinfo`（§4.5）。
func (h *handler) userinfo(c *gin.Context) {
	token, ok := bearerToken(c)
	if !ok {
		writeInvalidToken(c, "access token is required")
		return
	}
	resp, oe := h.deps.UserInfo.Userinfo(c.Request.Context(), token)
	if oe != nil {
		writeInvalidToken(c, oe.Description)
		return
	}
	raw, err := oidcJSON.Marshal(resp)
	if err != nil {
		writeInvalidToken(c, "cannot encode userinfo")
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

// getUserInfo `GET /api/oidc/get_user_info`（§4.6，Authloft 格式）。
func (h *handler) getUserInfo(c *gin.Context) {
	token, ok := bearerToken(c)
	if !ok {
		writeInvalidToken(c, "access token is required")
		return
	}
	resp, oe := h.deps.UserInfo.GetUserInfo(c.Request.Context(), token)
	if oe != nil {
		writeInvalidToken(c, oe.Description)
		return
	}
	raw, err := protojson.Marshal(resp)
	if err != nil {
		writeInvalidToken(c, "cannot encode user info")
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

// bearerToken 解析 `Authorization: Bearer <token>`（scheme 大小写不敏感）。
func bearerToken(c *gin.Context) (string, bool) {
	parts := strings.Fields(c.GetHeader("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// setNoStore token 端点响应头（RFC 6749 §5.1）。
func setNoStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
}

// writeOAuthError RFC 6749 `{error, error_description?}`（no-store）。
func writeOAuthError(c *gin.Context, oe *oidc.OAuthError) {
	status := oe.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	body := map[string]any{"error": oe.Code}
	if oe.Description != "" {
		body["error_description"] = oe.Description
	}
	setNoStore(c)
	writeJSON(c, status, body)
}

// writeInvalidToken RFC 6750 401 + WWW-Authenticate。
func writeInvalidToken(c *gin.Context, description string) {
	c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	writeOAuthError(c, &oidc.OAuthError{Status: 401, Code: "invalid_token", Description: description})
}

// writeError 通用 JSON 错误（discovery / jwks 内部错误兜底）。
func writeError(c *gin.Context, status int, code, description string) {
	writeJSON(c, status, map[string]any{"error": code, "error_description": description})
}

// writeJSON 以 RFC 原生 JSON 输出（不套 §1.0 信封）。
func writeJSON(c *gin.Context, status int, body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Data(status, "application/json; charset=utf-8", raw)
}
