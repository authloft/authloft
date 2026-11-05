// Package connect 实现 Connect 协议的装配层拦截（docs/后端架构.md §3.14）：
// session / admin / rpc HMAC / 错误包装四类 unary interceptor，以及 rpc HMAC
// 验签所需的原始请求体捕获装配助手。
//
// 包边界（§3.14 约定）：只依赖 connect-go、生成的消息与 session / cache 包
// 接口，不 import service、不读 config；本包只产出拦截器、不挂载任何路由
// ——挂载归装配层。gateway HMAC 与 Origin/CSRF 留在 Gin 全局链，
// 不在本包。
package connect

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"authloft/internal/session"
)

// 线上错误文案（与 codec 信封时代口径一致）：作为
// connect.Error 的 underlying error，其文本会直达客户端（connect-go
// error.go 约定），一律不携带内部信息。
var (
	errInternal              = errors.New("internal error")
	errAuthRequired          = errors.New("authentication required")
	errNotFound              = errors.New("not found")
	errMissingRPCCredentials = errors.New("missing rpc credentials")
	errNonceReplay           = errors.New("nonce replay detected")
	errBadSignature          = errors.New("signature verification failed")
)

// sessionTokenHeader 小程序 / 宿主环境回传 session_token 的 Header 名
// （docs/接口文档.md §1.2 行 120）；校验通过后新令牌亦经同名响应头下发
// （§1.9 行 291）。
const sessionTokenHeader = "X-Authloft-Token"

// defaultSessionCookieName 会话 Cookie 名默认值（§1.9 行 288，settings 键
// cookie_name）。session 包的 defaultCookieName 为私有常量，此处按文档
// 口径同值另设，不为此扩大 session 包导出面。
const defaultSessionCookieName = "al_session"

// NewSessionInterceptor 返回 session 会话拦截器（docs/后端架构.md §3.14
// 行 473；语义沿用既有中间件，本处不挂载）：
//
//   - 取值优先级 X-Authloft-Token Header → Cookie（名经 cookieName 每请求
//     读取，nil / 空串回落默认 al_session）；Header 有值（哪怕无效）不回落
//     Cookie——优先级是取值顺序而非失败回退；
//   - 无令牌 / 校验失败（ErrNotAuthenticated / ErrSessionStale）→ 未登录：
//     清 Cookie 并放行匿名，不 401——401 归 admin 等下游拦截器；
//   - epoch 读取链故障（Redis 与回源均失败）→ internal（§11.1：基础设施
//     错误不得与未登录混同）；
//   - 校验通过 → uid/amr/sid 注入 ctx（session.WithSessionContext）+
//     每请求重签（§11.5：iat/exp 刷新、epoch/sid 不变、纯计算无存储写入），
//     按令牌来源下发：Header 来源 → X-Authloft-Token 响应头；Cookie 来源 →
//     Set-Cookie（完整属性 HttpOnly; Secure; SameSite=None; Path=/）。
//
// 响应头经 connect.CallInfoForHandlerContext 写回：connect-go 的 handler
// 在拦截链返回后**无条件**合并进真实响应头（含错误响应），因此下游返回
// 401/404 时清 Cookie / 重签仍落地——与 Gin 时代同名链路「先写头、再由
// 下游判定」语义一致。装配时本拦截器应挂链最外层（先于 admin，后者依赖
// 其 ctx 身份注入）。复用边界：Verifier 四步校验 / WithSessionContext /
// Renewer.Renew / Cookie.Set/Clear 全部取自 internal/session 包，与 Gin
// 链路共用同一实现，未复制任何校验逻辑。
func NewSessionInterceptor(verifier *session.Verifier, renewer *session.Renewer, cookie *session.Cookie, cookieName func() string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			tok, fromHeader := pickSessionToken(req.Header(), cookieName)
			if tok == "" {
				// 无令牌：未登录。防御性清残留同名 Cookie 后放行匿名。
				AddSessionCookie(ctx, cookie.Clear())
				return next(ctx, req)
			}
			p, err := verifier.Verify(ctx, tok)
			switch {
			case err == nil:
			case errors.Is(err, session.ErrNotAuthenticated), errors.Is(err, session.ErrSessionStale):
				// 解不开 / 过期 / epoch 不一致：未登录（§3.14 行 473 口径），
				// 清 Cookie 放行，401 由下游拦截器判定。
				AddSessionCookie(ctx, cookie.Clear())
				return next(ctx, req)
			default:
				// epoch 读取链故障：基础设施错误，按 internal 拒绝。
				return nil, connect.NewError(connect.CodeInternal, errInternal)
			}
			// 校验通过：载荷值注入 ctx（不含令牌串），重签失败（Seal 为内存
			// 操作，实际不可达）不拒绝已验证请求、仅不下发新令牌。
			ctx = session.WithSessionContext(ctx, p)
			if _, renewed, rerr := renewer.Renew(p); rerr == nil {
				if fromHeader {
					setResponseHeader(ctx, sessionTokenHeader, renewed)
				} else {
					AddSessionCookie(ctx, cookie.Set(renewed))
				}
			}
			return next(ctx, req)
		}
	}
}

// pickSessionToken 按取值优先级取 session_token（§1.2 行 120）：
// X-Authloft-Token Header → Cookie。Connect 拦截器侧拿不到 *http.Request
// （AnyRequest 只暴露 Header），故用临时 Request 借其 Cookie 解析。
func pickSessionToken(h http.Header, cookieName func() string) (tok string, fromHeader bool) {
	if v := strings.TrimSpace(h.Get(sessionTokenHeader)); v != "" {
		return v, true
	}
	name := defaultSessionCookieName
	if cookieName != nil {
		if n := strings.TrimSpace(cookieName()); n != "" {
			name = n
		}
	}
	if ck, err := (&http.Request{Header: h}).Cookie(name); err == nil {
		return ck.Value, false
	}
	return "", false
}

// setResponseHeader 写响应头：经 handler 级 CallInfo 写回（connect-go 在
// 拦截链返回后无条件合并，含错误响应）。非 handler 上下文（拦截链外直接
// 调用）拿不到 CallInfo，静默跳过。
func setResponseHeader(ctx context.Context, key, value string) {
	if info, ok := connect.CallInfoForHandlerContext(ctx); ok {
		info.ResponseHeader().Set(key, value)
	}
}

// AddSessionCookie 下发完整属性的会话 Cookie（Set / Clear 构造结果）。
// cookie.String() 即 http.SetCookie 的序列化来源，属性原样落地（§1.9）。
// 经 handler 级 CallInfo 写回（connect-go 在拦截链返回后无条件合并，含错误
// 响应）；非 handler 上下文（拦截链外直接调用）拿不到 CallInfo，静默跳过。
// 本函数是 Connect 链 Set-Cookie 写出的唯一出口，供 session 拦截器（续期 /
// 清除）与 sso 登录终点（建会话下发）共用，禁止另造第二套 Cookie 写出。
func AddSessionCookie(ctx context.Context, ck *http.Cookie) {
	if info, ok := connect.CallInfoForHandlerContext(ctx); ok {
		info.ResponseHeader().Add("Set-Cookie", ck.String())
	}
}

// adminUID 管理员固定 UID：安装时创建的 user.id = 1 账号，不设角色表、
// 不加 is_admin 列（docs/接口文档.md §5 行 1143）。ctx uid 的读取经
// session.UIDFromContext 与 Gin 链路共用同一实现（§3.14 行 473 约束）。
const adminUID int64 = 1

// NewAdminInterceptor 返回管理员会话校验拦截器（§5 行 1145、§3.14 行 473），
// 装配时挂在 session 拦截器之内（依赖其注入的会话身份）：
//   - ctx 无 uid（未携带有效会话 / session 拦截器放行的未登录请求）→
//     unauthenticated（HTTP 401）；
//   - uid 有但 != 1 → not_found（HTTP 404，掩护管理面存在，§1.5 行 189）；
//   - uid == 1 放行。
//
// 两错误由拦截层产生、不进 §1.6 业务词汇（行 273），不挂 ErrorInfo detail
// （标准码语义）。管理员判定仅此处与 Gin 链路各一份（§3.14 禁止散落），
// 判定依据（uid==1）唯一定义于文档。
func NewAdminInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			uid, ok := session.UIDFromContext(ctx)
			if !ok {
				return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
			}
			if uid != adminUID {
				// 文案与普通资源 404 一致，不透露「路径存在但无权」。
				return nil, connect.NewError(connect.CodeNotFound, errNotFound)
			}
			return next(ctx, req)
		}
	}
}

// rpc 域鉴权请求头（docs/接口文档.md §7 行 1367-1371）。
const (
	rpcHeaderClientID  = "X-Client-ID"
	rpcHeaderNonceID   = "X-Nonce-ID"
	rpcHeaderSignature = "X-Signature"
)

// NonceStorer nonce 去重出口（cache.NonceStore 天然满足；窄接口便于测试
// 注入）。
type NonceStorer interface {
	Store(ctx context.Context, clientID, nonce string) (bool, error)
}

// SecretLookup client_secret 查询函数：返回 clientID 对应密钥与是否已注册。
// 真源 sso_client 表；装配点归后续 handler / bootstrap。
type SecretLookup func(ctx context.Context, clientID string) (string, bool)

// rpcWriteMethodPrefixes 写接口方法名前缀集合（docs/接口文档.md §7 行 1366
//「命名决定校验」长期口径；后端 §22 第 23 条）：方法名以 Update / Delete /
// Set / Create / Revoke 任一前缀开头 = 写接口（nonce 去重），其余方法名 =
// 读接口（不去重）。该判据适用于本域全部现有与未来方法；新增写接口若不
// 属于上述前缀语义，必须显式申请扩展本集合（走契约变更评审），不得静默
// 使用读接口命名绕过 nonce 去重。集中定义以便将来显式扩展。
var rpcWriteMethodPrefixes = []string{"Update", "Delete", "Set", "Create", "Revoke"}

// isRPCWriteProcedure 按 Connect procedure（形如 /api.rpc.v1.UserService/
// UpdateUserProfile，即 req.Spec().Procedure，§7 行 1378）判定写接口：取
// 末段方法名（package.Service 段不参与判定），前缀命中 rpcWriteMethodPrefixes
// 即写。procedure 为空串（拦截链外直调、无 Spec）时方法名亦为空，不命中
// 任何前缀 → 读路径。
func isRPCWriteProcedure(procedure string) bool {
	method := procedure
	if i := strings.LastIndex(procedure, "/"); i >= 0 {
		method = procedure[i+1:]
	}
	for _, prefix := range rpcWriteMethodPrefixes {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}
	return false
}

// rawBodyKey 原始请求体的 ctx 注入键（私有类型，包外无法伪造同型键）。
type rawBodyKey struct{}

// CaptureRawBody 原始请求体捕获装配助手：读出请求体字节注入 ctx，再把
// Body 回填后交给内层 http.Handler。装配层挂载 rpc 域 connect
// handler 时必须包上这一层，否则 NewRPCHMACInterceptor 拿不到原始字节、
// 按 internal fail-closed。
//
// 为什么需要它：connect-go 的 AnyRequest 无原始 body 出口（接口仅有
// Any/Spec/Peer/Header/HTTPMethod），拦截器读不到线上字节——且请求体
// 反序列化先于拦截链进入（connect-go v1.21.1 handler.go：implementation
// 内行 70 receiveUnaryRequest 先执行、行 83 才调 untyped 即拦截链入口；
// 行 66 的 WrapUnary 是构造期包裹、非运行顺序）。而 §7 行 1377 的五项
// 签名串要求 body 段与线上字节逐字一致，不能从已反序列化消息重算
// （序列化非字节稳定）。此即「connect-go 提供的等效机制」在 connect-go
// 无原生支持时的等价落地。
func CaptureRawBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, errInternal.Error(), http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), rawBodyKey{}, raw)))
	})
}

// rpcClientIDKey 鉴权通过后 client_id 写入 ctx 的键（供下游 handler 经
// ClientIDFromContext 取调用方身份）。
type rpcClientIDKey struct{}

// ClientIDFromContext 读取注入的调用方 client_id；未注入返回 false。
func ClientIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(rpcClientIDKey{}).(string)
	return id, ok
}

// NewRPCHMACInterceptor 返回 rpc 域 HMAC 鉴权拦截器（docs/接口文档.md §7、
// 断言迁移 + 读写分流，不挂载；校验顺序硬约束：写接口
// nonce 去重 → 签名，读接口仅签名，session 步归端点自身，§7 行 1383）：
//
//  1. 三头齐全（X-Client-ID / X-Nonce-ID / X-Signature，读写接口都要求；缺任一 →
//     permission_denied，HTTP 403）；
//  2. 写接口（方法名 Update / Delete / Set / Create / Revoke 前缀，isRPCWriteProcedure
//     按 §7 行 1366「命名决定校验」分流）nonce 去重（30s 窗口重放 → 403；
//     必须先于签名校验——签名错的请求同样消耗 nonce）；读接口跳过去重，
//     nonce 仅作为下方签名项（§7 行 1381/1383）；
//  3. client 未注册 → 403（与签名错误同响应，不区分以防探测）；
//  4. 签名：HMAC-SHA256(key=client_secret, msg 五项以 ":" 连接整体入串
//     "client_id:nonce:path:body:client_secret"，§7 行
//     1374/1381）。path 段取 req.Spec().Procedure——即 Connect RPC 路径
//     （§7 行 1378，如 /api.rpc.v1.UserService/GetUserProfile），connect-go
//     将其同时用作 handler 挂载路径，天然不含 query；body 段取 ctx 中的
//     原始请求体字节（见 CaptureRawBody，空 body 即空串）；签名 hex 解码
//     后 hmac.Equal 恒时比较（十六进制大小写不敏感）。
//
// 通过后 client_id 注入 ctx（ClientIDFromContext）放行。取舍：
// nonce 存储故障 → internal fail-closed（无法判定重放不得放行；仅写接口
// 会触达存储，读接口不去重故无此分支）；原始体捕获缺失（装配层漏挂
// CaptureRawBody）→ internal fail-closed。
func NewRPCHMACInterceptor(nonces NonceStorer, lookup SecretLookup) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			clientID := req.Header().Get(rpcHeaderClientID)
			nonce := req.Header().Get(rpcHeaderNonceID)
			signature := req.Header().Get(rpcHeaderSignature)
			if clientID == "" || nonce == "" || signature == "" {
				return nil, connect.NewError(connect.CodePermissionDenied, errMissingRPCCredentials)
			}
			// 写接口（§7 行 1383 校验顺序）：nonce 去重先于签名（签名错的请求
			// 同样消耗 nonce）；读接口跳过去重，nonce 仅参与下方签名串。
			if isRPCWriteProcedure(req.Spec().Procedure) {
				first, err := nonces.Store(ctx, clientID, nonce)
				if err != nil {
					return nil, connect.NewError(connect.CodeInternal, errInternal)
				}
				if !first {
					return nil, connect.NewError(connect.CodePermissionDenied, errNonceReplay)
				}
			}
			secret, ok := lookup(ctx, clientID)
			if !ok {
				return nil, connect.NewError(connect.CodePermissionDenied, errBadSignature)
			}
			raw, ok := ctx.Value(rawBodyKey{}).([]byte)
			if !ok {
				return nil, connect.NewError(connect.CodeInternal, errInternal)
			}
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(clientID + ":" + nonce + ":" + req.Spec().Procedure + ":"))
			mac.Write(raw)
			mac.Write([]byte(":" + secret))
			given, derr := hex.DecodeString(signature)
			if derr != nil || !hmac.Equal(given, mac.Sum(nil)) {
				return nil, connect.NewError(connect.CodePermissionDenied, errBadSignature)
			}
			return next(context.WithValue(ctx, rpcClientIDKey{}, clientID), req)
		}
	}
}

// NewErrorWrapperInterceptor 返回错误包装拦截器（§3.14 行 473「最内层」：
// 装配时挂链最内侧、先看到 handler 的错误）：
//   - handler 返回非 connect.Error 的错误 → 包成 connect.CodeInternal：
//     线上文本消毒为 "internal error"（underlying 文本直达客户端，禁止
//     泄内部信息），原错误经 Unwrap 保留（errors.Is / As 可回溯）；
//     internal 兜底不挂 ErrorInfo detail（§3.14 行 479、§1.6 行 272）；
//   - 已是 connect.Error（含被包装于错误链中的）→ 原样透传（与 connect-go
//     wrapIfUncoded 同语义），其 details 归业务侧。
//
// 协议级错误（解码失败、未知字段、超限等）由 connect-go 在拦截链之前生成
// （§1.5 行 224），不经本包装。
func NewErrorWrapperInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			resp, err := next(ctx, req)
			if err == nil {
				return resp, nil
			}
			var coded *connect.Error
			if errors.As(err, &coded) {
				return resp, err
			}
			return nil, connect.NewError(connect.CodeInternal, sanitizedError{err: err})
		}
	}
}

// sanitizedError 线上文本固定为通用 internal error；Unwrap 保留原错误供
// 服务端 errors.Is / As 回溯（connect-go 的 Error.Unwrap 会穿透本层）。
type sanitizedError struct{ err error }

func (s sanitizedError) Error() string { return errInternal.Error() }

func (s sanitizedError) Unwrap() error { return s.err }
