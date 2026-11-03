package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// gatewayTokenHeader 网关调用凭据 Header（docs/接口文档.md §6 行 1344：
// X-Gateway-Token: {gateway_token}，后台可配多个）。
const gatewayTokenHeader = "X-Gateway-Token"

// Gateway 网关 Token 校验中间件（docs/接口文档.md §6 行 1342-1344、
// docs/后端架构.md §3.3 行 293，仅挂 /api/gateway/**）：
// X-Gateway-Token 头不在令牌列表 → 403（§1.5 行 188「网关 Token 无效」）；
// 在列表 → 放行。
//
// 403 出口为豁免端点原生形态——gateway decode 纯响应头、无响应体
// （§1.0 行 66），故 AbortWithStatus 空体；X-Request-Id
// 响应头由 requestid 中间件写入。令牌列表经 tokens 函数每请求读取
// （settings 键 gateway_tokens 快照，可多个、热更新对后续请求生效；
// middleware 不 import settings，叶子件口径同 origin.go）。tokens 为
// nil（未装配）时保守拒绝——与 origin.go 的「缺配置默认拒绝」口径一致，
// 空列表本就无一可通过。
func Gateway(tokens func() []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tok := strings.TrimSpace(c.GetHeader(gatewayTokenHeader))
		if tok != "" && gatewayTokenAllowed(tokens, tok) {
			c.Next()
			return
		}
		c.AbortWithStatus(http.StatusForbidden)
	}
}

// gatewayTokenAllowed 恒定时间比对（crypto/subtle）防逐字节时序探测；
// 列表中的空串脏值不参与比对（不得令空 Header 通过）。
func gatewayTokenAllowed(tokens func() []string, tok string) bool {
	if tokens == nil {
		return false
	}
	for _, want := range tokens() {
		if want == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(want)) == 1 {
			return true
		}
	}
	return false
}
