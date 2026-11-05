// Package qrcode 是小程序码链的纯逻辑件（docs/后端架构.md §3.4 行 469：
// `qrcode/wxacode.go` —— GetwxacodeUnlimit + JPEG 压缩；`ticket_id` 长度
// 上限见 §11.6.4）。SDK 调用本体隔离在 internal/provider/oauth/wechat_mp*
// 适配器内（§13.0 行 1578「唯一可引用该 SDK 的包」），本包只持有：
//
//   - CompressJPEG：码图有损压缩（§13.2：JPEG 压缩 75%）；
//   - DeleteTask / DeleteExecutor：码图自动删除（§13.3：qrcode_auto_delete
//     开启时 PC 端完成 SSO 投延迟队列，后台 worker 调 Storage.Delete）。
package qrcode

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png" // 解码注册：微信可能下发 PNG，统一转 JPEG
	"log/slog"

	"authloft/internal/asyncqueue"
	"authloft/internal/storage"
)

// jpegQuality 有损压缩质量（§13.2 行 1593：JPEG 有损压缩（75%））。
const jpegQuality = 75

// CompressJPEG 把码图重编码为 quality=75 的 JPEG（§13.2）。微信侧可能
// 下发 PNG 或 JPEG，一律解码后统一转 JPEG（有损压缩 + 格式归一）。入参
// 不是可解码图片时原样返回——压缩是体积优化，不改变拉码链路的成败。
func CompressJPEG(body []byte) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return body, nil
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: jpegQuality}); err != nil {
		return nil, fmt.Errorf("qrcode: compress jpeg: %w", err)
	}
	return out.Bytes(), nil
}

// DeleteTask 码图自动删除任务（§13.3）：StorageKey 为码图所属存储
// Provider（wechat_mp_scan 的 Ext.storage_provider），ObjectKey 为拉码时
// 同一 storage_path 模板 + ticket_id + iat 重算的 key（§13.3「无需任何
// 额外存储」——iat 内嵌于加密 ticket，重算确定性成立）。
type DeleteTask struct {
	StorageKey string
	ObjectKey  string
}

// StorageResolver 按 storage provider key 解析 Storage 实现；
// *storage.Resolver 天然满足。
type StorageResolver interface {
	Resolve(ctx context.Context, storageProviderKey string) (storage.Storage, error)
}

// DeleteExecutor 消费 DeleteTask（asyncqueue.Executor，§5.2 攒批后调
// Execute）。解析存储 Provider → Storage.Delete；失败只 WARN——§13.3 行
// 1622「删除失败不影响已完成的登录」，现有队列骨架无重试（§5.2 行 886），
// 丢弃即告警。
type DeleteExecutor struct {
	Resolver StorageResolver
}

// NewDeleteExecutor 构造。
func NewDeleteExecutor(resolver StorageResolver) *DeleteExecutor {
	return &DeleteExecutor{Resolver: resolver}
}

// Execute 只消费 DeleteTask，其余任务类型原样忽略（同 provider.SendExecutor
// 口径，多执行器合批互不干扰）。
func (e *DeleteExecutor) Execute(ctx context.Context, tasks []asyncqueue.Task) {
	for _, task := range tasks {
		del, ok := task.Value.(DeleteTask)
		if !ok {
			continue
		}
		st, err := e.Resolver.Resolve(ctx, del.StorageKey)
		if err != nil {
			warnDeleteFailed(del, err)
			continue
		}
		if err := st.Delete(ctx, del.ObjectKey); err != nil {
			warnDeleteFailed(del, err)
		}
	}
}

// warnDeleteFailed 删除失败告警（§13.3：失败可重试 N 次后丢弃并告警——
// 队列无重试骨架，丢弃即告警，不影响已完成的登录）。
func warnDeleteFailed(del DeleteTask, err error) {
	slog.Warn("qrcode: auto delete failed",
		"storage_provider", del.StorageKey, "object_key", del.ObjectKey, "error", err)
}
