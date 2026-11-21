// Package s3 S3 兼容对象存储实现（docs/后端架构.md §15.1 表：MinIO、腾讯云
// COS、阿里云 OSS、七牛、AWS S3 均兼容 S3 协议，一个实现覆盖，endpoint +
// path_style 区分）。init() 经 RegisterStorage 自注册进统一注册表（§15.3
// 与 local 同机制），bootstrap 以 blank import 触发；factory 只从 Ext 取
// 配置（§13.0 装配期取 Ext，运行期不回读）。
//
// 签名：AWS Signature Version 4 stdlib 自实现（零第三方依赖，选型依据见
// sigv4.go 头注释），正确性由 botocore 权威矢量锁定。
//
// 字段映射（Ext 字段语义见接口文档 §12.1 / §5.3 storage 行清单）：
//   - Ext.client_id / client_secret → AccessKeyId / SecretAccessKey（同
//     aliyun_sms 的通用凭证字段复用口径）；
//   - Ext.endpoint → S3 兼容服务地址（可带 scheme，默认 https；内网 MinIO
//     用 http://host:port）；
//   - Ext.region_id → SigV4 region（空回退 us-east-1——MinIO 等常见默认）；
//   - Ext.bucket / path_style → 存储桶与寻址风格（virtual-host / path）；
//   - Ext.path_prefix / domain / public_read → 键前缀 / 公开域名（URL()
//     优先 domain，同 local 口径）/ 上传带 public-read ACL；
//   - Ext.upload_mode / presign_ttl / max_size / allowed_types → 上传模式
//     与限额，由头像上传链消费（dto.AccountAvatarUpload / PresignAvatar），
//     本包只消费 presign_ttl 作预签名有效期。
//
// key 安全：key 由服务端生成（头像 avatarObjectKey / 码图 RenderKey），渲染
// 侧（internal/storage path.go）与写盘实现（storage/local）按同一规则前置
// 校验；本实现自守同一套（三处保持同步），不信任上游。
package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"authloft/internal/provider"

	providerpb "authloft/gen/go/provider"
)

// Type 注册类型（§15.1 内置清单 s3）。字面量暂落本包、未上移 provider 包
// servicetype.go：根包注册表门禁（CODE_GUIDE §3.3）不得 import 实现子包——
// 测试二进制自身的 import 会触发 init 注册、使门禁恒绿，故门禁以字面量
// 断言、实现包自持常量，字面量上移统一另行处理。
const Type = "s3"

const (
	// presignTTLDefault 预签名有效期默认（接口文档 §12.1 presign_ttl 未配置
	// → 300，与头像侧归一口径一致）。
	presignTTLDefault = int64(300)
	// presignTTLMax S3 协议预签名上限 7 天（超出服务端拒绝），构造期收敛。
	presignTTLMax = int64(604800)
)

// httpClient 单对象上传/取回/删除的共享客户端；超时防悬挂，短于 ctx 全链
// 预算（ctx 截止同样生效）。
var httpClient = &http.Client{Timeout: 30 * time.Second}

// init 注册进统一注册表（§15.3）：Schema 是 /schema 的唯一数据源（表列 +
// Ext，接口文档 §5.3），只声明本渠道运行期实际消费的 Ext 字段。
func init() {
	provider.RegisterStorage(Type, provider.Meta{
		DisplayName: "S3 兼容对象存储",
		Category:    provider.CategoryStorage,
		Schema:      storageS3Schema,
	}, newStorage)
}

// newStorage 注册表工厂：从 Provider 实例取 Ext 构造。
func newStorage(p *provider.Provider) (provider.Storage, error) {
	return NewS3(p.Ext)
}

// S3 S3 兼容存储实现。
type S3 struct {
	scheme     string // http / https（endpoint 缺省时默认 https）
	host       string // host[:port]（去默认端口）
	bucket     string
	region     string
	accessKey  string
	secretKey  string
	pathStyle  bool
	prefix     string
	domain     string
	publicRead bool
	ttl        int64 // 预签名有效期（秒），构造期归一
}

// NewS3 从 Ext 构造；endpoint / bucket / 凭证任一为空即未配置（§13.0「按
// 失败处理」）。
func NewS3(ext *providerpb.Ext) (*S3, error) {
	if ext == nil {
		return nil, fmt.Errorf("%w: nil ext", provider.ErrNotConfigured)
	}
	accessKey := strings.TrimSpace(ext.GetClientId())
	secretKey := strings.TrimSpace(ext.GetClientSecret())
	scheme, host, err := splitEndpoint(strings.TrimSpace(ext.GetEndpoint()))
	if err != nil {
		return nil, fmt.Errorf("%w: s3: %w", provider.ErrNotConfigured, err)
	}
	bucket := strings.TrimSpace(ext.GetBucket())
	if bucket == "" || strings.ContainsAny(bucket, "/\\") {
		return nil, fmt.Errorf("%w: s3: bucket(%q) empty or invalid", provider.ErrNotConfigured, ext.GetBucket())
	}
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("%w: s3: access key / secret key empty", provider.ErrNotConfigured)
	}
	region := strings.TrimSpace(ext.GetRegionId())
	if region == "" {
		region = "us-east-1"
	}
	return &S3{
		scheme:     scheme,
		host:       host,
		bucket:     bucket,
		region:     region,
		accessKey:  accessKey,
		secretKey:  secretKey,
		pathStyle:  ext.GetPathStyle(),
		prefix:     trimPrefix(ext.GetPathPrefix()),
		domain:     strings.TrimRight(strings.TrimSpace(ext.GetDomain()), "/"),
		publicRead: ext.GetPublicRead(),
		ttl:        normalizeTTL(ext.GetPresignTtl()),
	}, nil
}

// splitEndpoint 拆 scheme 与 host[:port]：可带 scheme（默认 https），剥默认
// 端口使 canonical host 与实际请求 Host 头逐字节一致（SigV4 签名抗不得漂移）。
func splitEndpoint(endpoint string) (scheme, host string, err error) {
	scheme = "https"
	host = endpoint
	if i := strings.Index(endpoint, "://"); i >= 0 {
		scheme = strings.ToLower(endpoint[:i])
		host = endpoint[i+3:]
	}
	host = strings.TrimSuffix(host, "/")
	if host == "" {
		return "", "", fmt.Errorf("endpoint %q empty host", endpoint)
	}
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("endpoint %q: unsupported scheme %q", endpoint, scheme)
	}
	if (scheme == "https" && strings.HasSuffix(host, ":443")) ||
		(scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndex(host, ":")]
	}
	return scheme, host, nil
}

// normalizeTTL 预签名有效期归一：≤0（未配置 / 乱配）→ 默认 300，超协议
// 上限收敛到 7 天（镜像头像侧 avatarNormalizeTTL 的零值兜底风格）。
func normalizeTTL(ttl int32) int64 {
	if ttl <= 0 {
		return presignTTLDefault
	}
	if int64(ttl) > presignTTLMax {
		return presignTTLMax
	}
	return int64(ttl)
}

// Put 中转上传（码图等）：单对象 PUT，x-amz-content-sha256 载荷签名，
// public_read 时附 public-read ACL。返回公开 URL。
func (s *S3) Put(ctx context.Context, key string, body []byte, contentType string) (string, error) {
	req, err := s.signedRequest(ctx, http.MethodPut, key, body, sha256Hex(body), putHeaders(contentType, s.publicRead))
	if err != nil {
		return "", fmt.Errorf("storage: s3: put: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("storage: s3: put: %w", err)
	}
	defer drainClose(resp)
	if err := statusError("put", resp); err != nil {
		return "", err
	}
	return s.URL(key), nil
}

// Get 单对象取回。
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	req, err := s.signedRequest(ctx, http.MethodGet, key, nil, emptyPayloadSHA, nil)
	if err != nil {
		return nil, fmt.Errorf("storage: s3: get: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("storage: s3: get: %w", err)
	}
	defer drainClose(resp)
	if err := statusError("get", resp); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("storage: s3: get: read body: %w", err)
	}
	return body, nil
}

// Delete 删除对象；S3 DELETE 语义幂等（不存在亦 2xx，部分兼容实现返 404），
// 404 同按成功（§13.3 删除幂等——重试与 TTL 过期后重复删除不报错）。
func (s *S3) Delete(ctx context.Context, key string) error {
	req, err := s.signedRequest(ctx, http.MethodDelete, key, nil, emptyPayloadSHA, nil)
	if err != nil {
		return fmt.Errorf("storage: s3: delete: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("storage: s3: delete: %w", err)
	}
	defer drainClose(resp)
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return statusError("delete", resp)
}

// URL 拼接公开地址：domain 优先（同 local 口径），否则由 endpoint + bucket
// 按寻址风格派生。
func (s *S3) URL(key string) string {
	p := key
	if s.prefix != "" {
		p = s.prefix + "/" + key
	}
	if s.domain != "" {
		return s.domain + "/" + p
	}
	return s.scheme + "://" + s.objectHost() + s.objectPath(key)
}

// PresignPut 直传预签名（§15.1：签发有时效的 PUT URL，前端据此直传）。
// SignedHeaders = host + content-type（非空时）+ x-amz-acl（public_read 时），
// 返回的 headers 即前端 PUT 必须原样携带的头（签名与之绑定，篡改即 403）。
// size 不参与签名——S3 预签名 PUT 无请求体大小绑定能力，上限由调用方
// （PresignAvatar）在签发前校验，commit 后可异步 HEAD 复核（§15.1）。
func (s *S3) PresignPut(_ context.Context, key string, contentType string, _ int64) (string, map[string]string, error) {
	if err := validateKey(key); err != nil {
		return "", nil, err
	}
	url, headers := s.presignPut(key, contentType, time.Now())
	return url, headers, nil
}

// presignPut 确定性预签名（now 注入供权威矢量测试）。
func (s *S3) presignPut(key, contentType string, now time.Time) (string, map[string]string) {
	return s.presign(http.MethodPut, key, putHeaders(contentType, s.publicRead), now)
}

// presign 通用查询串预签名：extra 参与签名并原样作为响应 headers 返回
// （前端 PUT 必须原样携带，签名与之绑定）。
func (s *S3) presign(method, key string, extra map[string]string, now time.Time) (string, map[string]string) {
	headers := signedHeaders{"host": s.objectHost()}
	out := make(map[string]string, len(extra))
	for name, value := range extra {
		headers[strings.ToLower(name)] = value
		out[name] = value
	}
	block, list := headers.canonical()

	amzDate := now.UTC().Format(amzTimeFormat)
	dateStamp := now.UTC().Format(amzDateFormat)
	scope := dateStamp + "/" + s.region + "/s3/aws4_request"
	query := map[string]string{
		"X-Amz-Algorithm":     sigAlgorithm,
		"X-Amz-Credential":    s.accessKey + "/" + scope,
		"X-Amz-Date":          amzDate,
		"X-Amz-Expires":       strconv.FormatInt(s.ttl, 10),
		"X-Amz-SignedHeaders": list,
	}
	canonicalRequest := strings.Join([]string{
		method,
		uriEncode(s.objectPath(key), false),
		canonicalQuery(query),
		block,
		list,
		unsignedPayload,
	}, "\n")
	sig := signature(stringToSign(amzDate, scope, canonicalRequest), s.secretKey, dateStamp, s.region, "s3")
	url := s.scheme + "://" + s.objectHost() + uriEncode(s.objectPath(key), false) +
		"?" + canonicalQuery(query) + "&X-Amz-Signature=" + sig
	return url, out
}

// signedRequest 构造头签名请求（Put / Get / Delete 共用）：path 为编码后
// canonical URI，body 非空即随请求下发，extra 参与签名并随请求下发。
func (s *S3) signedRequest(ctx context.Context, method, key string, body []byte, payloadHash string, extra map[string]string) (*http.Request, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method,
		s.scheme+"://"+s.objectHost()+uriEncode(s.objectPath(key), false), reader)
	if err != nil {
		return nil, err
	}
	s.signRequest(req, payloadHash, extra, time.Now())
	return req, nil
}

// signRequest 计算头签名三件套并就地写入 x-amz-date / x-amz-content-sha256 /
// extra / Authorization。host 取 URL.Host，与 net/http 实际发送的 Host 头
// 一致（默认端口已在构造期剥离）。
func (s *S3) signRequest(req *http.Request, payloadHash string, extra map[string]string, now time.Time) {
	amzDate := now.UTC().Format(amzTimeFormat)
	dateStamp := now.UTC().Format(amzDateFormat)
	scope := dateStamp + "/" + s.region + "/s3/aws4_request"
	headers := signedHeaders{
		"host":                 req.URL.Host,
		"x-amz-date":           amzDate,
		"x-amz-content-sha256": payloadHash,
	}
	for name, value := range extra {
		headers[strings.ToLower(name)] = value
	}
	block, list := headers.canonical()
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		"", // 单对象操作无查询串
		block,
		list,
		payloadHash,
	}, "\n")
	sig := signature(stringToSign(amzDate, scope, canonicalRequest), s.secretKey, dateStamp, s.region, "s3")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	for name, value := range extra {
		req.Header.Set(name, value)
	}
	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigAlgorithm, s.accessKey, scope, list, sig))
}

// putHeaders 上传附加头：content-type 非空即签名（服务端 MIME 闸门之外，
// 直传侧再锁一道）；public_read 即附 public-read ACL。
func putHeaders(contentType string, publicRead bool) map[string]string {
	headers := make(map[string]string, 2)
	if contentType != "" {
		headers["Content-Type"] = contentType
	}
	if publicRead {
		headers["X-Amz-Acl"] = "public-read"
	}
	return headers
}

// objectHost 请求目标 host：path-style 用 endpoint host，virtual-host 桶名
// 前缀（S3 规范寻址两式）。
func (s *S3) objectHost() string {
	if s.pathStyle {
		return s.host
	}
	return s.bucket + "." + s.host
}

// objectPath 请求 path（编码前）：path-style 桶名入路径，前缀同 local 拼接。
func (s *S3) objectPath(key string) string {
	p := key
	if s.prefix != "" {
		p = s.prefix + "/" + key
	}
	if s.pathStyle {
		p = s.bucket + "/" + p
	}
	return "/" + p
}

// validateKey key 自守校验：空 / 绝对 / ".." 段 / 反斜杠 / 盘符一律拒绝。
// 与渲染侧（internal/storage path.go）、写盘实现（storage/local）同一规则，
// 三处保持同步。
func validateKey(key string) error {
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") ||
		strings.Contains(key, ":") {
		return fmt.Errorf("storage: s3: invalid key %q", key)
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return fmt.Errorf("storage: s3: invalid key %q", key)
		}
	}
	return nil
}

// trimPrefix path_prefix 去两端斜杠（空串保持空），同 local。
func trimPrefix(raw string) string {
	return strings.Trim(strings.TrimSpace(raw), "/")
}

// statusError 非 2xx 统一包装：状态码 + 截断的响应片段（S3 错误 XML 含
// NoSuchBucket 等可判别码，无敏感信息，供排障；截断防日志刷屏）。
func statusError(op string, resp *http.Response) error {
	if resp.StatusCode/100 == 2 {
		return nil
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("storage: s3: %s: HTTP %d: %s", op, resp.StatusCode, strings.TrimSpace(string(snippet)))
}

// drainClose 读完剩余体再关闭连接（连接复用要求体被排空）。
func drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
}

// storageS3Schema storage/s3 的完整字段声明（表列 + Ext，接口文档 §5.3），
// 每次调用返回新切片。凭证复用 aliyun_sms 引入的 AccessKeyId / SecretKey
// 文案键（同语义）；domain / path_prefix 复用 storage 既有键。upload_mode /
// presign_ttl / max_size / allowed_types 为头像上传链消费的上传模式与限额
// （接口文档 §12.1 storage 行清单后四项），direct 模式经 PresignPut 生效。
// storage 恒可用（不消费 is_enabled），is_enabled 不在声明内——列表页 /
// 编辑表单对该类别不出现启停。
func storageS3Schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 20)
	fields = append(fields,
		provider.FieldMeta{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic", Required: true,
			Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "display_name", Label: "admin.schemaField.displayNameLabel", Type: "text", Section: "basic", Required: true, Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "endpoint", Label: "admin.schemaField.providerUrlLabel", Type: "text", Section: "endpoint", Required: true,
			Help: "admin.schemaField.s3EndpointHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "bucket", Label: "admin.schemaField.s3BucketLabel", Type: "text", Section: "endpoint", Required: true,
			Help: "admin.schemaField.s3BucketHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "region_id", Label: "admin.schemaField.s3RegionLabel", Type: "text", Section: "endpoint", Advanced: true,
			Help: "admin.schemaField.s3RegionHelp", Storage: provider.StorageExt},
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
