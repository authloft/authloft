// template.go 实现 AdminService 模板管理族五方法（接口文档 §5.7）：handler
// 只做分页归一、请求拆解与消息投影，业务校验 / 缓存失效在 service；错误映射
// 复用 mapWriteError（同一套 ErrInvalidRequest / 唯一键冲突 / 资源不存在口径）。
// Connect 经 NewAdminServiceHandler(h) 一次性注册整个 service，本文件不逐 rpc 装配。
package admin

import (
	"context"

	connectrpc "connectrpc.com/connect"

	adminv1 "authloft/gen/go/api/admin/v1"
	"authloft/internal/repo/model"
)

// ListTemplates 分页列表 + 可选 q 按 name 模糊筛选；只返回 DB 自定义模板行。
func (h *Handler) ListTemplates(ctx context.Context, req *connectrpc.Request[adminv1.ListTemplatesRequest]) (*connectrpc.Response[adminv1.ListTemplatesResponse], error) {
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.templates.List(ctx, page, size, req.Msg.GetQ())
	if err != nil {
		return nil, mapWriteError("list templates", err)
	}
	items := make([]*adminv1.Template, len(rows))
	for i := range rows {
		items[i] = templateMessage(&rows[i])
	}
	return connectrpc.NewResponse(&adminv1.ListTemplatesResponse{
		Items:    items,
		Total:    total,
		Page:     int64(page),
		PageSize: int64(size),
	}), nil
}

// CreateTemplate 新建自定义模板；template_key 校验与内置 key 冲突在 service。
func (h *Handler) CreateTemplate(ctx context.Context, req *connectrpc.Request[adminv1.CreateTemplateRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.templates.Create(ctx, req.Msg.GetTemplateKey(), req.Msg.GetName(), req.Msg.GetContent()); err != nil {
		return nil, mapWriteError("create template", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// GetTemplate {id} 定位 → 详情含 content。
func (h *Handler) GetTemplate(ctx context.Context, req *connectrpc.Request[adminv1.GetTemplateRequest]) (*connectrpc.Response[adminv1.Template], error) {
	row, err := h.templates.Get(ctx, req.Msg.GetId())
	if err != nil {
		return nil, mapWriteError("get template", err)
	}
	return connectrpc.NewResponse(templateMessage(row)), nil
}

// UpdateTemplate 部分更新（PATCH）；key / name / content 指针原样透传，缺省保留。
func (h *Handler) UpdateTemplate(ctx context.Context, req *connectrpc.Request[adminv1.UpdateTemplateRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.templates.Update(ctx, req.Msg.GetId(), req.Msg.TemplateKey, req.Msg.Name, req.Msg.Content); err != nil {
		return nil, mapWriteError("update template", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// DeleteTemplate {id} 硬删；写路径失效缓存由 service 完成。
func (h *Handler) DeleteTemplate(ctx context.Context, req *connectrpc.Request[adminv1.DeleteTemplateRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.templates.Delete(ctx, req.Msg.GetId()); err != nil {
		return nil, mapWriteError("delete template", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// templateMessage template 行 → Template 消息（列表 / 详情两用）；时间戳由
// service 维护，本处只做投影。
func templateMessage(row *model.Template) *adminv1.Template {
	if row == nil {
		return &adminv1.Template{}
	}
	return &adminv1.Template{
		Id:          row.ID,
		TemplateKey: row.TemplateKey,
		Name:        row.Name,
		Content:     row.Content,
		CreatedAt:   row.CreatedAt.Unix(),
		UpdatedAt:   row.UpdatedAt.Unix(),
	}
}
