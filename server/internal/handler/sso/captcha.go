// captcha.go 实现 SsoService/CreateCaptchaImage（docs/后端架构.md §3.4
// 行 328、docs/接口文档.md §2.5 行 491-498）：复用 internal/captcha/image.go
// 唯一自绘实现（两位数加减法），答案经注入的 ImageCaptcha 落
// al:cap:{id}（EX 300 由 cache.CaptchaStore 固定），响应直接返回
// {id, imageBase64, expiresIn}——前端用 data:image/png;base64 渲染，
// 无二次取图接口。
package sso

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	ssov1 "authloft/gen/go/api/sso/v1"
)

// CreateCaptchaImage 新建自绘图形码。存储故障等按 Connect internal 错误
// 返回；本端点无业务失败分支（生成即成功）。
func (h *Handler) CreateCaptchaImage(ctx context.Context, req *connect.Request[ssov1.CreateCaptchaImageRequest]) (*connect.Response[ssov1.CreateCaptchaImageResponse], error) {
	if h.images == nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("sso: captcha image not configured"))
	}
	ch, err := h.images.Generate(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("sso: generate captcha image: %w", err))
	}
	return connect.NewResponse(&ssov1.CreateCaptchaImageResponse{
		Id:          ch.ID,
		ImageBase64: base64.StdEncoding.EncodeToString(ch.PNG),
		ExpiresIn:   int64(ch.ExpiresIn),
	}), nil
}
