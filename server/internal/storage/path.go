// path.go storage_path 模板渲染（§15.1「小程序码路径」：JSONata 表达式，
// 内置变量 ticket_id、timestamp；例 'qrcodes_' & $.ticket_id & '.jpg'）。
// 求值复用 internal/jsonata（§3.12 行 471 单一封装入口，gnata；user_mapping
// 后续共用；求值失败归一口径见接口文档 §5.3 行 1261-1263）。
package storage

import (
	"fmt"
	"strconv"
	"strings"

	"authloft/internal/jsonata"
)

// RenderKey 渲染码图 object key。timestamp 取拉码时刻（TicketPayload.iat，
// §11.6.4）——轮询侧码图自动删除用同一模板 + ticket_id + iat 重算
// （§13.3「无需任何额外存储」：iat 内嵌在加密 ticket 里，重算确定性成立）。
// 模板为空 / 求值失败 / 渲染结果非法（空 key、绝对 key、穿越段）返回错误，
// 由调用方按 provider 未配置收敛（§13.0）。
func RenderKey(template, ticketID string, timestamp int64) (string, error) {
	key, err := jsonata.Evaluate(template, map[string]string{
		"ticket_id": ticketID,
		"timestamp": strconv.FormatInt(timestamp, 10),
	})
	if err != nil {
		return "", fmt.Errorf("storage: render key: %w", err)
	}
	if err := validateKey(key); err != nil {
		return "", fmt.Errorf("storage: render key: %w", err)
	}
	return key, nil
}

// validateKey 渲染结果合法性（空 key / 绝对 key / ".." 段 / 盘符 / 反斜杠
// 一律拒绝，§15.1「渲染结果非法返回错误」），错误由 RenderKey 统一包装。
// 与写盘实现（provider/storage/local）的自守校验同一规则，两处须保持同步。
func validateKey(key string) error {
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") ||
		strings.Contains(key, ":") {
		return fmt.Errorf("invalid key %q", key)
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return fmt.Errorf("invalid key %q", key)
		}
	}
	return nil
}
