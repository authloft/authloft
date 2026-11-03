// RPC 鉴权（docs/接口文档.md §7 行 1361-1379 + 后端架构 §3.3 行 314、§17 行 1718）：
// X-Client-ID + X-Nonce-ID（Redis 去重 TTL 30s）+ X-Signature（HMAC-SHA256）
// 校验；校验顺序硬约束：nonce 去重 → 签名（session 步归端点自身，§3.3 行 314
// rpc.go 职责不含）。nonce 存储与 client_secret 查询经构造注入（叶子件，不
// import cache / repo：真源 sso_client 表的装配归后续 handler / bootstrap 卡）。
package middleware

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
)

// RPC 鉴权请求头（接口文档 §7 行 1367-1371）。
const (
	headerClientID  = "X-Client-ID"
	headerNonceID   = "X-Nonce-ID"
	headerSignature = "X-Signature"
)

// RPCClientIDKey 鉴权通过后 client_id 写入 ctx 的键（供下游 handler 取调用方身份）。
const RPCClientIDKey = "rpc_client_id"

// NonceStorer nonce 去重出口（cache.NonceStore 天然满足；窄接口便于测试注入，
// 同构造注入口径）。
type NonceStorer interface {
	Store(ctx context.Context, clientID, nonce string) (bool, error)
}

// SecretLookup client_secret 查询函数：返回 clientID 对应密钥与是否已注册。
// 真源 sso_client 表；装配点归后续 handler / bootstrap。
type SecretLookup func(ctx context.Context, clientID string) (string, bool)

// RPCAuth 返回 RPC 鉴权中间件。校验顺序（接口文档 §7 行 1379）：
//  1. 三头齐全（缺任一 403）；
//  2. nonce 去重（§3.3 行 314：必须先于签名校验——签名错的请求同样消耗
//     nonce；去重失败 = 30s 窗口内重放 → 403）；
//  3. 签名：HMAC-SHA256(key=client_secret, msg="client_id:nonce:path:body:client_secret")
//     （§7 行 1371/1377：**五项以 ":" 连接后整体入串**（文档
//     字面优先），密钥为 client_secret；path 不含 query、body 为原始请求体
//     字节、GET 或空 body 为空串）；client 未注册或签名不符 → 403。
//
// 通过后 client_id 写入 ctx（RPCClientIDKey）并放行。取舍（文档未覆盖，待定）：
// nonce 存储故障（Redis 不可用）时 fail-closed 返回 500
// internal_error——无法判定重放不得放行，也不宜以 403 归咎调用方。
func RPCAuth(nonces NonceStorer, lookup SecretLookup) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientID := c.GetHeader(headerClientID)
		nonce := c.GetHeader(headerNonceID)
		signature := c.GetHeader(headerSignature)
		if clientID == "" || nonce == "" || signature == "" {
			codec.WriteError(c, http.StatusForbidden, codec.CodeForbidden, "missing rpc credentials")
			c.Abort()
			return
		}

		first, err := nonces.Store(c.Request.Context(), clientID, nonce)
		if err != nil {
			codec.WriteError(c, http.StatusInternalServerError, codec.CodeInternalError, "internal error")
			c.Abort()
			return
		}
		if !first {
			codec.WriteError(c, http.StatusForbidden, codec.CodeForbidden, "nonce replay detected")
			c.Abort()
			return
		}

		secret, ok := lookup(c.Request.Context(), clientID)
		if !ok {
			// 未注册 client 与签名错误同响应（403 forbidden），不区分以防探测。
			codec.WriteError(c, http.StatusForbidden, codec.CodeForbidden, "signature verification failed")
			c.Abort()
			return
		}

		// 读原始请求体后立即回填：中间件不得消费 body（下游 codec.Bind 还要读）。
		// GET / 空 body 得空字节串（§7 行 1376；GetRawData 对 nil Body 返回 nil）。
		raw, err := c.GetRawData()
		if err != nil {
			codec.WriteError(c, http.StatusInternalServerError, codec.CodeInternalError, "internal error")
			c.Abort()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))

		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(clientID + ":" + nonce + ":" + c.Request.URL.Path + ":"))
		mac.Write(raw)
		mac.Write([]byte(":" + secret)) // §7 行 1371/1377：client_secret 亦为第五项入串
		// hex.DecodeString 接受大小写混合 → 签名十六进制大小写不敏感；
		// hmac.Equal 恒时比较，防时序侧信道。
		given, err := hex.DecodeString(signature)
		if err != nil || !hmac.Equal(given, mac.Sum(nil)) {
			codec.WriteError(c, http.StatusForbidden, codec.CodeForbidden, "signature verification failed")
			c.Abort()
			return
		}

		c.Set(RPCClientIDKey, clientID)
		c.Next()
	}
}
