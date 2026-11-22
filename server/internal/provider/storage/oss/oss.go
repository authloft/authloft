// Package oss 阿里云 OSS 存储薄封装（docs/后端架构.md §15.5 薄封装总则、
// §15.1 oss / cos 预设行）：传输与签名整链复用 storage/s3 基座导出构造器
// NewS3（SigV4 标准库自实现，x-amz-content-sha256 非 chunked 恰为 OSS S3
// 兼容 V4 的要求形态），本包不重写上传逻辑，只做构造期派生与 Schema 收窄：
//
//   - endpoint 由 region_id 构造期派生 S3 兼容域名
//     https://s3.oss-{region}.aliyuncs.com（必须带 s3. 前缀——OSS 自有域名
//     oss-{region}.aliyuncs.com 走自有签名体系，基座不认）；region_id 实质
//     必填，缺失装配期 fail-closed 拒绝、不走基座 us-east-1 回退（地域错配
//     → SignatureDoesNotMatch）；
//   - endpoint 为固化派生参数不进 Schema、不在表单透出（未声明字段提交即
//     invalid_request，接口文档 §5.3）；intranet_endpoint 不保留（基座不消费
//     该键，声明即违反声明即消费，内网回源二期随基座改造）；path_style 保留
//     可选（default false，老桶名含下划线的路径风格场景），经 Ext 原样透传。
package oss

import (
	"fmt"
	"strings"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/storage/s3"

	"google.golang.org/protobuf/proto"
)

// Type 注册类型（§15.1 内置清单 oss）。字面量落本包、不上移 provider 包，
// 同 s3 先例：根包注册表门禁不得 import 实现子包（测试二进制自身触发 init
// 注册会使门禁恒绿）。
const Type = "oss"

func init() {
	provider.RegisterStorage(Type, provider.Meta{
		DisplayName: "阿里云 OSS",
		Category:    provider.CategoryStorage,
		Schema:      schema,
	}, newStorage)
}

// newStorage 注册表工厂：region 缺失 fail-closed；派生 endpoint 写入 Ext
// 副本后委托基座——不写回原 Ext（Loader 行缓存共享，原地变异会外溢）。
// 其余字段（bucket / 凭证 / path_style / 限额）取值口径与基座逐字一致，
// bucket 非法、凭证缺失同由基座 fail-closed（ErrNotConfigured）。
func newStorage(p *provider.Provider) (provider.Storage, error) {
	ext, err := derivedExt(p)
	if err != nil {
		return nil, err
	}
	return s3.NewS3(ext)
}

// derivedExt 深拷贝 Ext 并注入派生 endpoint（proto.Clone 防止 map 字段浅
// 共享带来的意外变异面）。region 先去两端空白，与基座 TrimSpace 口径一致。
func derivedExt(p *provider.Provider) (*providerpb.Ext, error) {
	var region string
	if p != nil && p.Ext != nil {
		region = strings.TrimSpace(p.Ext.GetRegionId())
	}
	if region == "" {
		return nil, fmt.Errorf("%w: oss: region_id empty (endpoint derived from region)", provider.ErrNotConfigured)
	}
	ext := proto.Clone(p.Ext).(*providerpb.Ext)
	ext.Endpoint = "https://s3.oss-" + region + ".aliyuncs.com"
	return ext, nil
}

// schema /schema 唯一数据源（表列 + Ext，接口文档 §5.3）：以 s3 行字段表为
// 底、按收窄边界裁剪——endpoint（固化派生）与 intranet_endpoint（不保留）
// 不声明；Label 全部复用既有 i18n 键（新增键须与 zh / en 文案同批落地，
// web 字典零改动）。region_id 不挂 Help：既有 s3RegionHelp 文案是「留空回退
// us-east-1」，对本渠道不成立，宁缺勿错，region 必须为实际地域 ID 的语义
// 见包注释；必填由 Required 前端拦截 + 装配期 fail-closed 双道兜底。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 17)
	fields = append(fields,
		provider.FieldMeta{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic", Required: true,
			Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "display_name", Label: "admin.schemaField.displayNameLabel", Type: "text", Section: "basic", Required: true, Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "bucket", Label: "admin.schemaField.s3BucketLabel", Type: "text", Section: "endpoint", Required: true,
			Help: "admin.schemaField.s3BucketHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "region_id", Label: "admin.schemaField.s3RegionLabel", Type: "text", Section: "endpoint", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "path_style", Label: "admin.schemaField.s3PathStyleLabel", Type: "checkbox", Section: "endpoint", Advanced: true,
			Help: "admin.schemaField.s3PathStyleHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "client_id", Label: "admin.schemaField.aliyunAccessKeyIdLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "client_secret", Label: "admin.schemaField.aliyunAccessKeySecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "path_prefix", Label: "admin.schemaField.storagePathPrefixLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "domain", Label: "admin.schemaField.storageDomainLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "public_read", Label: "admin.schemaField.s3PublicReadLabel", Type: "checkbox", Section: "policy", Advanced: true,
			Help: "admin.schemaField.s3PublicReadHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "upload_mode", Label: "admin.schemaField.uploadModeLabel", Type: "select", Section: "policy",
			Options: []string{"proxy", "direct"}, Default: "proxy", Help: "admin.schemaField.uploadModeHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "presign_ttl", Label: "admin.schemaField.presignTtlLabel", Type: "number", Section: "policy", Advanced: true,
			Help: "admin.schemaField.presignTtlHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "max_size", Label: "admin.schemaField.maxSizeLabel", Type: "number", Section: "policy", Advanced: true,
			Help: "admin.schemaField.maxSizeHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "allowed_types", Label: "admin.schemaField.allowedTypesLabel", Type: "text", Section: "policy", Advanced: true,
			Help: "admin.schemaField.allowedTypesHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "icon_url", Label: "admin.schemaField.iconUrlLabel", Type: "text", Section: "display",
			Pattern: "^https?://", Help: "admin.schemaField.iconUrlHelp", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "sort_order", Label: "admin.schemaField.sortOrderLabel", Type: "number", Section: "display", Default: "0", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "remark", Label: "admin.schemaField.remarkLabel", Type: "text", Section: "display", Advanced: true, Storage: provider.StorageColumn},
	)
	return fields
}
