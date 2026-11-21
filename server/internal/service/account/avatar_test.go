// avatar_test.go account 域头像上传三桩 service 层单测（不连 DB，
// Settings / Providers / Users / Resolver / Storage 全 fake 注入，
// profile_test.go 先例）：数据源链未配置四态、mode 与方法不符（presign
// 非 direct / upload 非 proxy）、MIME / 超限 / 空内容 / size≤0 拒绝、
// key 服务端生成（uid 前缀 / 无客户端路径成分 / 同参两次不同 key）、
// Resolve 与 PresignPut / Put 入参透传、TTL 兜底 0→300、
// commit 不回读（Get 零调用）与 URL 拼接、commit key 边界、基础设施错误
// 透传、404 存在性先判。
package account

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"database/sql"
	"google.golang.org/protobuf/proto"

	accountv1 "authloft/gen/go/api/account/v1"
	providerpb "authloft/gen/go/provider"
	storagelocal "authloft/internal/provider/storage/local"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
	"authloft/internal/storage"
)

const (
	avatarTestProviderKey = "avatar-s3"
	avatarTestUID         = int64(10086)
	avatarTestCDNBase     = "https://cdn.example.com/"
	avatarTestPresignURL  = "https://s3.example.com/put?sig=x"
	avatarTestPutURL      = "https://cdn.example.com/avatars/put.png"
)

// avatarFakeSettings AvatarSettings fake：键值回放。
type avatarFakeSettings struct{ values map[string]string }

func (f *avatarFakeSettings) GetString(key string) (string, bool) {
	v, ok := f.values[key]
	return v, ok
}

// avatarFakeProviders AvatarProviderStore fake：行集回放 + 错误注入；
// 未命中回放包装 sql.ErrNoRows（repo 同口径）。
type avatarFakeProviders struct {
	rows  map[string]*model.Provider
	err   error
	calls []string
}

func (f *avatarFakeProviders) FindByKey(_ context.Context, providerKey string) (*model.Provider, error) {
	f.calls = append(f.calls, providerKey)
	if f.err != nil {
		return nil, f.err
	}
	row, ok := f.rows[providerKey]
	if !ok {
		return nil, fmt.Errorf("provider repo: find by key: %w", sql.ErrNoRows)
	}
	return row, nil
}

// avatarFakeUsers AvatarUserStore fake：missing 时回放包装 ErrRecordNotFound。
type avatarFakeUsers struct{ missing bool }

func (f *avatarFakeUsers) FindByID(_ context.Context, _ int64) (*model.User, error) {
	if f.missing {
		return nil, fmt.Errorf("user repo: find by id: %w", sql.ErrNoRows)
	}
	return &model.User{ID: avatarTestUID}, nil
}

// avatarFakeResolver AvatarStorageResolver fake：调用记录 + 错误注入。
type avatarFakeResolver struct {
	st    storage.Storage
	err   error
	calls []string
}

func (f *avatarFakeResolver) Resolve(_ context.Context, providerKey string) (storage.Storage, error) {
	f.calls = append(f.calls, providerKey)
	if f.err != nil {
		return nil, f.err
	}
	return f.st, nil
}

// avatarPresignCall PresignPut 入参记录（透传断言用）。
type avatarPresignCall struct {
	key         string
	contentType string
	size        int64
}

// avatarPutCall Put 入参记录（UploadAvatar 落盘透传断言用）。
type avatarPutCall struct {
	key         string
	content     []byte
	contentType string
}

// avatarFakeStorage storage.Storage fake：presign / put 回放 + Get 计数（commit
// 不回读断言）+ URL 拼接回放。
type avatarFakeStorage struct {
	presignCalls   []avatarPresignCall
	presignErr     error
	presignURL     string
	presignHeaders map[string]string
	putCalls       []avatarPutCall
	putErr         error
	putURL         string
	urlCalls       []string
	getCalls       int
	deleteCalls    int
}

func (f *avatarFakeStorage) Put(_ context.Context, key string, content []byte, contentType string) (string, error) {
	f.putCalls = append(f.putCalls, avatarPutCall{key: key, content: content, contentType: contentType})
	if f.putErr != nil {
		return "", f.putErr
	}
	return f.putURL, nil
}

func (f *avatarFakeStorage) Get(context.Context, string) ([]byte, error) {
	f.getCalls++
	return nil, nil
}

func (f *avatarFakeStorage) Delete(context.Context, string) error {
	f.deleteCalls++
	return nil
}

func (f *avatarFakeStorage) URL(key string) string {
	f.urlCalls = append(f.urlCalls, key)
	return avatarTestCDNBase + key
}

func (f *avatarFakeStorage) PresignPut(_ context.Context, key, contentType string, size int64) (string, map[string]string, error) {
	f.presignCalls = append(f.presignCalls, avatarPresignCall{key: key, contentType: contentType, size: size})
	if f.presignErr != nil {
		return "", nil, f.presignErr
	}
	return f.presignURL, f.presignHeaders, nil
}

var _ storage.Storage = (*avatarFakeStorage)(nil)

// avatarTestExt 构造 storage 扩展字段（§12.1）。
func avatarTestExt(uploadMode string, ttl int32, maxSize int64, allowed string) *providerpb.Ext {
	return &providerpb.Ext{
		UploadMode:   uploadMode,
		PresignTtl:   ttl,
		MaxSize:      maxSize,
		AllowedTypes: allowed,
	}
}

// avatarTestProviderRow 构造 storage 生效行（ext 序列化进 row.Ext，生产
// repo.ParseProviderExt 反序列化路径全覆盖）。
func avatarTestProviderRow(t *testing.T, typ string, ext *providerpb.Ext) *model.Provider {
	t.Helper()
	data, err := proto.Marshal(ext)
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	return &model.Provider{
		ProviderKey: avatarTestProviderKey,
		Category:    "storage",
		Type:        typ,
		IsEnabled:   1,
		Ext:         data,
	}
}

// avatarTestEnv 全链路可用装配：s3 + direct + ttl 600 + 2MB + png/jpeg
// 白名单；变体测试直接改字段（fake 持引用，无需重建 svc）。
type avatarTestEnv struct {
	settings  *avatarFakeSettings
	providers *avatarFakeProviders
	users     *avatarFakeUsers
	resolver  *avatarFakeResolver
	storage   *avatarFakeStorage
	svc       *AvatarService
}

func avatarTestEnvNew(t *testing.T) *avatarTestEnv {
	t.Helper()
	e := &avatarTestEnv{
		settings: &avatarFakeSettings{values: map[string]string{
			settings.KeyAvatarStorageProvider: avatarTestProviderKey,
		}},
		providers: &avatarFakeProviders{rows: map[string]*model.Provider{
			avatarTestProviderKey: avatarTestProviderRow(t, "s3", avatarTestExt("direct", 600, 2<<20, "image/png,image/jpeg")),
		}},
		users: &avatarFakeUsers{},
		storage: &avatarFakeStorage{
			presignURL:     avatarTestPresignURL,
			presignHeaders: map[string]string{"Content-Type": "image/png"},
			putURL:         avatarTestPutURL,
		},
	}
	e.resolver = &avatarFakeResolver{st: e.storage}
	e.svc = NewAvatarService(AvatarDeps{Settings: e.settings, Providers: e.providers, Users: e.users, Resolver: e.resolver})
	return e
}

func (e *avatarTestEnv) presign(in *accountv1.PresignAvatarRequest) (*accountv1.AvatarPresignResponse, error) {
	return e.svc.PresignAvatar(context.Background(), avatarTestUID, in)
}

func avatarTestPresignReq() *accountv1.PresignAvatarRequest {
	return &accountv1.PresignAvatarRequest{Filename: "avatar.png", ContentType: "image/png", Size: 1024}
}

// TestAvatarPresignHappyPath 全链路：key 服务端生成（uid 前缀 / 基段无路径
// 成分 / 白名单扩展名保留）、数据源链与 Resolve / PresignPut 入参透传、
// uploadUrl / headers 透传、expiresIn = presign_ttl、同参两次不同 key。
func TestAvatarPresignHappyPath(t *testing.T) {
	e := avatarTestEnvNew(t)
	resp, err := e.presign(avatarTestPresignReq())
	if err != nil {
		t.Fatalf("PresignAvatar: %v", err)
	}

	prefix := avatarKeyPrefix(avatarTestUID)
	if !strings.HasPrefix(resp.Key, prefix) {
		t.Errorf("key = %q, want 前缀 %q（uid 隔离）", resp.Key, prefix)
	}
	base := strings.TrimPrefix(resp.Key, prefix)
	if base == "" || strings.Contains(base, "/") || strings.Contains(base, "\\") || strings.Contains(base, "..") {
		t.Errorf("key 基段 = %q, want 无客户端路径成分", base)
	}
	if !strings.HasSuffix(base, ".png") {
		t.Errorf("key 基段 = %q, want 白名单扩展名 .png 保留", base)
	}

	if len(e.providers.calls) != 1 || e.providers.calls[0] != avatarTestProviderKey {
		t.Errorf("FindByKey 调用 = %v, want [%s]（数据源链透传）", e.providers.calls, avatarTestProviderKey)
	}
	if len(e.resolver.calls) != 1 || e.resolver.calls[0] != avatarTestProviderKey {
		t.Errorf("Resolve 调用 = %v, want [%s]（provider key 透传）", e.resolver.calls, avatarTestProviderKey)
	}
	if len(e.storage.presignCalls) != 1 {
		t.Fatalf("PresignPut 调用 = %d, want 1", len(e.storage.presignCalls))
	}
	c := e.storage.presignCalls[0]
	if c.key != resp.Key || c.contentType != "image/png" || c.size != 1024 {
		t.Errorf("PresignPut 入参 = (%q, %q, %d), want (%q, image/png, 1024)",
			c.key, c.contentType, c.size, resp.Key)
	}
	if resp.UploadUrl != avatarTestPresignURL {
		t.Errorf("uploadUrl = %q, want %q（透传）", resp.UploadUrl, avatarTestPresignURL)
	}
	if len(resp.Headers) != 1 || resp.Headers["Content-Type"] != "image/png" {
		t.Errorf("headers = %v, want 透传 {Content-Type: image/png}", resp.Headers)
	}
	if resp.ExpiresIn != 600 {
		t.Errorf("expiresIn = %d, want 600（= presign_ttl）", resp.ExpiresIn)
	}

	// 同参两次生成不同 key（随机成分防猜测，覆盖即失效）。
	resp2, err := e.presign(avatarTestPresignReq())
	if err != nil {
		t.Fatalf("PresignAvatar 2nd: %v", err)
	}
	if resp2.Key == resp.Key {
		t.Errorf("两次 key 相同 %q, want 不同", resp.Key)
	}
}

// TestAvatarPresignKeyServerGenerated filename 攻击形态不进 key 路径：
// 穿越 / 反斜杠 / 非法扩展名全被洗掉，至多保留白名单扩展名。
func TestAvatarPresignKeyServerGenerated(t *testing.T) {
	e := avatarTestEnvNew(t)
	prefix := avatarKeyPrefix(avatarTestUID)
	for name, filename := range map[string]string{
		"路径穿越":  "../../../../etc/passwd.png",
		"反斜杠":   `C:\Users\me\avatar.png`,
		"无扩展名":  "photo",
		"非法扩展名": "avatar.php?x=1",
		"纯点":    "..",
	} {
		resp, err := e.presign(&accountv1.PresignAvatarRequest{Filename: filename, ContentType: "image/png", Size: 100})
		if err != nil {
			t.Fatalf("%s: PresignAvatar: %v", name, err)
		}
		if !strings.HasPrefix(resp.Key, prefix) {
			t.Errorf("%s: key = %q, want 前缀 %q", name, resp.Key, prefix)
			continue
		}
		base := strings.TrimPrefix(resp.Key, prefix)
		if base == "" || strings.Contains(base, "/") || strings.Contains(base, "\\") ||
			strings.Contains(base, "..") || strings.ContainsAny(base, ":?") {
			t.Errorf("%s: key 基段 = %q, want 无客户端路径成分", name, base)
		}
		switch name {
		case "无扩展名", "非法扩展名", "纯点":
			if strings.Contains(base, ".") {
				t.Errorf("%s: key 基段 = %q, want 无（被丢弃的）扩展名", name, base)
			}
		case "路径穿越":
			if !strings.HasSuffix(base, ".png") {
				t.Errorf("%s: key 基段 = %q, want 白名单扩展名 .png 保留", name, base)
			}
		}
	}
}

// TestAvatarPresignMIMERejected MIME 不在白名单 → ErrAvatarFileTypeNotAllowed；
// 空 contentType 同拒、空白名单 fail-closed（自决）；拒绝时零 PresignPut。
func TestAvatarPresignMIMERejected(t *testing.T) {
	e := avatarTestEnvNew(t)
	for name, ct := range map[string]string{"不在白名单": "image/webp", "空串": ""} {
		_, err := e.presign(&accountv1.PresignAvatarRequest{Filename: "a.webp", ContentType: ct, Size: 100})
		if !errors.Is(err, ErrAvatarFileTypeNotAllowed) {
			t.Errorf("%s: err = %v, want ErrAvatarFileTypeNotAllowed", name, err)
		}
	}
	if len(e.storage.presignCalls) != 0 {
		t.Errorf("PresignPut 调用 = %d, want 0（校验在签发前）", len(e.storage.presignCalls))
	}

	// 空白名单 fail-closed（自决）：direct 行未配 allowed_types → 全拒。
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("direct", 600, 2<<20, ""))
	if _, err := e.presign(avatarTestPresignReq()); !errors.Is(err, ErrAvatarFileTypeNotAllowed) {
		t.Errorf("空白名单 err = %v, want ErrAvatarFileTypeNotAllowed（fail-closed）", err)
	}
}

// TestAvatarPresignTooLarge size > maxSize → ErrAvatarFileTooLarge；
// dto maxSize 零值兜底 2MB 与 service 判定口径一致（≤2MB 过、>2MB 拒）。
func TestAvatarPresignTooLarge(t *testing.T) {
	e := avatarTestEnvNew(t)
	_, err := e.presign(&accountv1.PresignAvatarRequest{Filename: "a.png", ContentType: "image/png", Size: 2<<20 + 1})
	if !errors.Is(err, ErrAvatarFileTooLarge) {
		t.Fatalf("err = %v, want ErrAvatarFileTooLarge", err)
	}
	if len(e.storage.presignCalls) != 0 {
		t.Errorf("PresignPut 调用 = %d, want 0（校验在签发前）", len(e.storage.presignCalls))
	}

	// MaxSize 0 → dto 兜底 2MB（dto/account.go AccountAvatarUpload）。
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("direct", 600, 0, "image/png"))
	if _, err := e.presign(&accountv1.PresignAvatarRequest{Filename: "a.png", ContentType: "image/png", Size: 2 << 20}); err != nil {
		t.Errorf("size = 2MB err = %v, want nil（兜底上限内）", err)
	}
	if _, err := e.presign(&accountv1.PresignAvatarRequest{Filename: "a.png", ContentType: "image/png", Size: 2<<20 + 1}); !errors.Is(err, ErrAvatarFileTooLarge) {
		t.Errorf("size = 2MB+1 err = %v, want ErrAvatarFileTooLarge", err)
	}
}

// TestAvatarPresignInvalidSize size≤0 自决拒绝 → ErrAvatarInvalidRequest
// （文档未覆盖：零 / 负 size 头像无意义），零 PresignPut。
func TestAvatarPresignInvalidSize(t *testing.T) {
	e := avatarTestEnvNew(t)
	for name, size := range map[string]int64{"零": 0, "负": -1024} {
		_, err := e.presign(&accountv1.PresignAvatarRequest{Filename: "a.png", ContentType: "image/png", Size: size})
		if !errors.Is(err, ErrAvatarInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrAvatarInvalidRequest", name, err)
		}
	}
	if len(e.storage.presignCalls) != 0 {
		t.Errorf("PresignPut 调用 = %d, want 0", len(e.storage.presignCalls))
	}
}

// TestAvatarPresignNotConfigured provider 未配置各态 + settings 未装配 →
// ErrAvatarNotConfigured（直调上传接口按 internal 映射，不新增错误码），
// 零 Resolve / 零 PresignPut。
func TestAvatarPresignNotConfigured(t *testing.T) {
	oauthRow := avatarTestProviderRow(t, "s3", avatarTestExt("direct", 600, 2<<20, "image/png"))
	oauthRow.Category = "auth"

	for name, mutate := range map[string]func(e *avatarTestEnv){
		"settings 键空串":     func(e *avatarTestEnv) { e.settings.values[settings.KeyAvatarStorageProvider] = "" },
		"settings 键缺失":     func(e *avatarTestEnv) { delete(e.settings.values, settings.KeyAvatarStorageProvider) },
		"provider 行查无":     func(e *avatarTestEnv) { delete(e.providers.rows, avatarTestProviderKey) },
		"category≠storage": func(e *avatarTestEnv) { e.providers.rows[avatarTestProviderKey] = oauthRow },
	} {
		e := avatarTestEnvNew(t)
		mutate(e)
		_, err := e.presign(avatarTestPresignReq())
		if !errors.Is(err, ErrAvatarNotConfigured) {
			t.Errorf("%s: err = %v, want ErrAvatarNotConfigured", name, err)
		}
		if len(e.resolver.calls) != 0 || len(e.storage.presignCalls) != 0 {
			t.Errorf("%s: Resolve/PresignPut = %d/%d, want 0/0", name, len(e.resolver.calls), len(e.storage.presignCalls))
		}
	}

	// Settings 未装配（nil）：防御读按未配置处理（handler 同款）。
	e := avatarTestEnvNew(t)
	e.svc = NewAvatarService(AvatarDeps{Providers: e.providers, Users: e.users, Resolver: e.resolver})
	if _, err := e.presign(avatarTestPresignReq()); !errors.Is(err, ErrAvatarNotConfigured) {
		t.Errorf("settings nil err = %v, want ErrAvatarNotConfigured", err)
	}
}

// TestAvatarDisabledRowStillUploads storage 恒可用（不消费 is_enabled）：
// 行停用（is_enabled=0）presign / 上传两链照常走通——与 storage.Resolver
// 同口径，启停语义只留给登录入口类类别。
func TestAvatarDisabledRowStillUploads(t *testing.T) {
	row := avatarTestProviderRow(t, "s3", avatarTestExt("direct", 600, 2<<20, "image/png"))
	row.IsEnabled = 0
	e := avatarTestEnvNew(t)
	e.providers.rows[avatarTestProviderKey] = row
	resp, err := e.presign(avatarTestPresignReq())
	if err != nil {
		t.Fatalf("PresignAvatar(is_enabled=0): %v, want nil（storage 恒可用）", err)
	}
	if resp.GetUploadUrl() != avatarTestPresignURL {
		t.Errorf("uploadUrl = %q, want %q", resp.GetUploadUrl(), avatarTestPresignURL)
	}

	row = avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png"))
	row.IsEnabled = 0
	e = avatarTestEnvNew(t)
	e.providers.rows[avatarTestProviderKey] = row
	up, err := e.upload(avatarTestUploadReq())
	if err != nil {
		t.Fatalf("UploadAvatar(is_enabled=0): %v, want nil（storage 恒可用）", err)
	}
	if up.GetUrl() != avatarTestPutURL {
		t.Errorf("url = %q, want %q", up.GetUrl(), avatarTestPutURL)
	}
}

// TestAvatarPresignModeNotDirect mode≠direct → ErrAvatarPresignUnavailable
// （internal 口径）：显式 proxy 与 local+direct 回退（dto 折 proxy，
// §15.1 表）两态同判；零 Resolve / 零 PresignPut。
func TestAvatarPresignModeNotDirect(t *testing.T) {
	for name, row := range map[string]*model.Provider{
		"显式 proxy": avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png")),
		"local 回退": avatarTestProviderRow(t, "local", avatarTestExt("direct", 600, 2<<20, "image/png")),
	} {
		e := avatarTestEnvNew(t)
		e.providers.rows[avatarTestProviderKey] = row
		_, err := e.presign(avatarTestPresignReq())
		if !errors.Is(err, ErrAvatarPresignUnavailable) {
			t.Errorf("%s: err = %v, want ErrAvatarPresignUnavailable", name, err)
		}
		if len(e.resolver.calls) != 0 || len(e.storage.presignCalls) != 0 {
			t.Errorf("%s: Resolve/PresignPut = %d/%d, want 0/0", name, len(e.resolver.calls), len(e.storage.presignCalls))
		}
	}
}

// TestAvatarPresignTTLFallback expiresIn = presign_ttl；0（未配置）→ 300
// （§12.1 注释默认），负值自决同兜底。
func TestAvatarPresignTTLFallback(t *testing.T) {
	for name, ttl := range map[string]int32{"未配置 0": 0, "乱配负值": -5, "显式 120": 120} {
		e := avatarTestEnvNew(t)
		e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("direct", ttl, 2<<20, "image/png"))
		resp, err := e.presign(avatarTestPresignReq())
		if err != nil {
			t.Fatalf("%s: PresignAvatar: %v", name, err)
		}
		want := int64(ttl)
		if ttl <= 0 {
			want = 300
		}
		if resp.ExpiresIn != want {
			t.Errorf("%s: expiresIn = %d, want %d", name, resp.ExpiresIn, want)
		}
	}
}

// TestAvatarPresignInfraErrors 基础设施错误包装透传（非哨兵，按
// internal 映射）：FindByKey 查询故障 / ext 解析失败 / Resolve 失败 /
// PresignPut 失败。
func TestAvatarPresignInfraErrors(t *testing.T) {
	boom := errors.New("avatar test: db down")

	e := avatarTestEnvNew(t)
	e.providers.err = boom
	if _, err := e.presign(avatarTestPresignReq()); !errors.Is(err, boom) || errors.Is(err, ErrAvatarNotConfigured) {
		t.Errorf("FindByKey 故障 err = %v, want 包装 boom 透传（非未配置哨兵）", err)
	}

	e = avatarTestEnvNew(t)
	row := avatarTestProviderRow(t, "s3", avatarTestExt("direct", 600, 2<<20, "image/png"))
	row.Ext = []byte{0xff, 0xff, 0xff, 0x7f} // 非法 proto 字节
	e.providers.rows[avatarTestProviderKey] = row
	if _, err := e.presign(avatarTestPresignReq()); err == nil || errors.Is(err, ErrAvatarNotConfigured) {
		t.Errorf("ext 解析失败 err = %v, want 包装上抛（非未配置哨兵）", err)
	}

	e = avatarTestEnvNew(t)
	e.resolver.err = storage.ErrNotConfigured
	if _, err := e.presign(avatarTestPresignReq()); !errors.Is(err, storage.ErrNotConfigured) {
		t.Errorf("Resolve 失败 err = %v, want 包装 storage.ErrNotConfigured 透传", err)
	}

	e = avatarTestEnvNew(t)
	e.storage.presignErr = storagelocal.ErrPresignNotSupported
	if _, err := e.presign(avatarTestPresignReq()); !errors.Is(err, storagelocal.ErrPresignNotSupported) {
		t.Errorf("PresignPut 失败 err = %v, want 包装 storagelocal.ErrPresignNotSupported 透传", err)
	}
}

// TestAvatarUserNotFound user 行不存在 → sql.ErrNoRows 透传
// （handler 转 not_found，profile.go 先例 404 优先），两桩同口径，零 Resolve。
func TestAvatarUserNotFound(t *testing.T) {
	e := avatarTestEnvNew(t)
	e.users.missing = true

	if _, err := e.presign(avatarTestPresignReq()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("presign err = %v, want sql.ErrNoRows 透传", err)
	}
	key := avatarKeyPrefix(avatarTestUID) + "x.png"
	if _, err := e.svc.CommitAvatar(context.Background(), avatarTestUID, &accountv1.CommitAvatarRequest{Key: key}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("commit err = %v, want sql.ErrNoRows 透传", err)
	}
	if len(e.resolver.calls) != 0 {
		t.Errorf("Resolve 调用 = %d, want 0（存在性先判在前）", len(e.resolver.calls))
	}
}

// TestAvatarCommitURL commit 正常链：URL(key) 拼接回显；不回读校验（
// Get / Put / Delete / PresignPut 全零调用），Resolve 传 avatar_storage_provider。
func TestAvatarCommitURL(t *testing.T) {
	e := avatarTestEnvNew(t)
	key := avatarKeyPrefix(avatarTestUID) + "abc123.png"
	resp, err := e.svc.CommitAvatar(context.Background(), avatarTestUID, &accountv1.CommitAvatarRequest{Key: key})
	if err != nil {
		t.Fatalf("CommitAvatar: %v", err)
	}
	if resp.Url != avatarTestCDNBase+key {
		t.Errorf("url = %q, want %q（URL(key) 拼接）", resp.Url, avatarTestCDNBase+key)
	}
	if e.storage.getCalls != 0 {
		t.Errorf("Get 调用 = %d, want 0（不回读）", e.storage.getCalls)
	}
	if len(e.storage.putCalls) != 0 || e.storage.deleteCalls != 0 || len(e.storage.presignCalls) != 0 {
		t.Errorf("Put/Delete/PresignPut = %d/%d/%d, want 全 0",
			len(e.storage.putCalls), e.storage.deleteCalls, len(e.storage.presignCalls))
	}
	if len(e.resolver.calls) != 1 || e.resolver.calls[0] != avatarTestProviderKey {
		t.Errorf("Resolve 调用 = %v, want [%s]", e.resolver.calls, avatarTestProviderKey)
	}
}

// TestAvatarCommitKeyRejected key 边界（avatarCommitKeyOK）：空串必拒、
// 跨用户前缀拒、无头像前缀拒、uid 前缀不完整拒、相对段拒、反斜杠拒 →
// ErrAvatarInvalidRequest，零 Resolve（拒绝在解析前）。
func TestAvatarCommitKeyRejected(t *testing.T) {
	e := avatarTestEnvNew(t)
	for name, key := range map[string]string{
		"空串":        "",
		"跨用户":       "avatars/999/x.png",
		"无头像前缀":     "files/x.png",
		"uid 前缀不完整": "avatars/100869/x.png",
		"相对段":       "avatars/10086/../10087/a.png",
		"反斜杠":       `avatars\10086\a.png`,
	} {
		_, err := e.svc.CommitAvatar(context.Background(), avatarTestUID, &accountv1.CommitAvatarRequest{Key: key})
		if !errors.Is(err, ErrAvatarInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrAvatarInvalidRequest", name, err)
		}
	}
	if len(e.resolver.calls) != 0 {
		t.Errorf("Resolve 调用 = %d, want 0（key 拒绝在解析前）", len(e.resolver.calls))
	}
}

// TestAvatarCommitResolveError Resolve 失败包装透传（internal 口径），
// 零 URL 拼接。
func TestAvatarCommitResolveError(t *testing.T) {
	e := avatarTestEnvNew(t)
	e.resolver.err = storage.ErrNotConfigured
	key := avatarKeyPrefix(avatarTestUID) + "x.png"
	_, err := e.svc.CommitAvatar(context.Background(), avatarTestUID, &accountv1.CommitAvatarRequest{Key: key})
	if !errors.Is(err, storage.ErrNotConfigured) {
		t.Errorf("err = %v, want 包装 storage.ErrNotConfigured 透传", err)
	}
	if len(e.storage.urlCalls) != 0 {
		t.Errorf("URL 拼接 = %d, want 0", len(e.storage.urlCalls))
	}
}

// avatarTestUploadReq proxy 模式上传请求样例（1KB png 字节）。
func avatarTestUploadReq() *accountv1.UploadAvatarRequest {
	return &accountv1.UploadAvatarRequest{Filename: "avatar.png", ContentType: "image/png", Content: make([]byte, 1024)}
}

// (e *avatarTestEnv) upload proxy 模式上传桩。
func (e *avatarTestEnv) upload(in *accountv1.UploadAvatarRequest) (*accountv1.AvatarResponse, error) {
	return e.svc.UploadAvatar(context.Background(), avatarTestUID, in)
}

// TestAvatarUploadHappyPath proxy 模式全链路：key 服务端生成（uid 前缀 /
// 白名单扩展名保留 / 无客户端路径成分）、Resolve 与 Put 入参透传
// （key / content 逐字节 / contentType）、Put 返回 URL 回显、同参两次不同 key。
func TestAvatarUploadHappyPath(t *testing.T) {
	e := avatarTestEnvNew(t)
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png,image/jpeg"))
	in := avatarTestUploadReq()
	resp, err := e.upload(in)
	if err != nil {
		t.Fatalf("UploadAvatar: %v", err)
	}
	if resp.Url != avatarTestPutURL {
		t.Errorf("url = %q, want %q（Put 返回回显）", resp.Url, avatarTestPutURL)
	}
	if len(e.resolver.calls) != 1 || e.resolver.calls[0] != avatarTestProviderKey {
		t.Errorf("Resolve 调用 = %v, want [%s]（provider key 透传）", e.resolver.calls, avatarTestProviderKey)
	}
	if len(e.storage.putCalls) != 1 {
		t.Fatalf("Put 调用 = %d, want 1", len(e.storage.putCalls))
	}
	c := e.storage.putCalls[0]
	if !strings.HasPrefix(c.key, avatarKeyPrefix(avatarTestUID)) {
		t.Errorf("key = %q, want 前缀 %q（uid 隔离）", c.key, avatarKeyPrefix(avatarTestUID))
	}
	base := strings.TrimPrefix(c.key, avatarKeyPrefix(avatarTestUID))
	if base == "" || strings.ContainsAny(base, `/\:`) || strings.Contains(base, "..") {
		t.Errorf("key 基段 = %q, want 无客户端路径成分", base)
	}
	if !strings.HasSuffix(base, ".png") {
		t.Errorf("key 基段 = %q, want 白名单扩展名 .png 保留", base)
	}
	if !bytes.Equal(c.content, in.GetContent()) {
		t.Errorf("Put content = %d bytes, want 原样透传 %d bytes", len(c.content), len(in.GetContent()))
	}
	if c.contentType != "image/png" {
		t.Errorf("Put contentType = %q, want image/png", c.contentType)
	}

	// 同参两次生成不同 key（随机成分防猜测，覆盖即失效）。
	if _, err := e.upload(avatarTestUploadReq()); err != nil {
		t.Fatalf("UploadAvatar 2nd: %v", err)
	}
	if len(e.storage.putCalls) != 2 || e.storage.putCalls[0].key == e.storage.putCalls[1].key {
		t.Errorf("两次 key 相同 %q, want 不同", e.storage.putCalls[0].key)
	}
}

// TestAvatarUploadModeNotProxy mode≠proxy（显式 direct）→
// ErrAvatarUploadUnavailable（internal 口径）：直调按未知异常映射，
// 零 Resolve / 零 Put。
func TestAvatarUploadModeNotProxy(t *testing.T) {
	e := avatarTestEnvNew(t) // 默认装配 direct 行
	if _, err := e.upload(avatarTestUploadReq()); !errors.Is(err, ErrAvatarUploadUnavailable) {
		t.Errorf("err = %v, want ErrAvatarUploadUnavailable", err)
	}
	if len(e.resolver.calls) != 0 || len(e.storage.putCalls) != 0 {
		t.Errorf("Resolve/Put = %d/%d, want 0/0", len(e.resolver.calls), len(e.storage.putCalls))
	}
}

// TestAvatarUploadMIMERejected MIME 不在白名单 → ErrAvatarFileTypeNotAllowed；
// 空 contentType 同拒、空白名单 fail-closed；拒绝时零 Put。
func TestAvatarUploadMIMERejected(t *testing.T) {
	for name, row := range map[string]*model.Provider{
		"显式 proxy": avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png,image/jpeg")),
		"local 回退": avatarTestProviderRow(t, "local", avatarTestExt("proxy", 600, 2<<20, "image/png")),
	} {
		e := avatarTestEnvNew(t)
		e.providers.rows[avatarTestProviderKey] = row
		for _, ct := range []string{"image/webp", ""} {
			if _, err := e.upload(&accountv1.UploadAvatarRequest{Filename: "a.webp", ContentType: ct, Content: []byte("x")}); !errors.Is(err, ErrAvatarFileTypeNotAllowed) {
				t.Errorf("%s contentType=%q: err = %v, want ErrAvatarFileTypeNotAllowed", name, ct, err)
			}
		}
		if len(e.storage.putCalls) != 0 {
			t.Errorf("%s: Put 调用 = %d, want 0（校验在落盘前）", name, len(e.storage.putCalls))
		}
	}

	// 空白名单 fail-closed（自决）：proxy 行未配 allowed_types → 全拒。
	e := avatarTestEnvNew(t)
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, ""))
	if _, err := e.upload(avatarTestUploadReq()); !errors.Is(err, ErrAvatarFileTypeNotAllowed) {
		t.Errorf("空白名单 err = %v, want ErrAvatarFileTypeNotAllowed（fail-closed）", err)
	}
}

// TestAvatarUploadTooLarge len(content) > maxSize → ErrAvatarFileTooLarge；
// dto maxSize 零值兜底 2MB 与 service 判定口径一致（≤2MB 过、>2MB 拒）。
func TestAvatarUploadTooLarge(t *testing.T) {
	e := avatarTestEnvNew(t)
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png"))
	if _, err := e.upload(&accountv1.UploadAvatarRequest{Filename: "a.png", ContentType: "image/png", Content: make([]byte, 2<<20+1)}); !errors.Is(err, ErrAvatarFileTooLarge) {
		t.Fatalf("err = %v, want ErrAvatarFileTooLarge", err)
	}
	if len(e.storage.putCalls) != 0 {
		t.Errorf("Put 调用 = %d, want 0（校验在落盘前）", len(e.storage.putCalls))
	}

	// MaxSize 0 → dto 兜底 2MB（dto/account.go AccountAvatarUpload）。
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 0, "image/png"))
	if _, err := e.upload(&accountv1.UploadAvatarRequest{Filename: "a.png", ContentType: "image/png", Content: make([]byte, 2<<20)}); err != nil {
		t.Errorf("content = 2MB err = %v, want nil（兜底上限内）", err)
	}
	if _, err := e.upload(&accountv1.UploadAvatarRequest{Filename: "a.png", ContentType: "image/png", Content: make([]byte, 2<<20+1)}); !errors.Is(err, ErrAvatarFileTooLarge) {
		t.Errorf("content = 2MB+1 err = %v, want ErrAvatarFileTooLarge", err)
	}
}

// TestAvatarUploadEmptyContent 空 content 自决拒绝 → ErrAvatarInvalidRequest
// （文档未覆盖：零字节头像无意义，镜像 presign size≤0 口径），零 Put。
func TestAvatarUploadEmptyContent(t *testing.T) {
	e := avatarTestEnvNew(t)
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png"))
	if _, err := e.upload(&accountv1.UploadAvatarRequest{Filename: "a.png", ContentType: "image/png"}); !errors.Is(err, ErrAvatarInvalidRequest) {
		t.Errorf("err = %v, want ErrAvatarInvalidRequest", err)
	}
	if len(e.storage.putCalls) != 0 {
		t.Errorf("Put 调用 = %d, want 0", len(e.storage.putCalls))
	}
}

// TestAvatarUploadNotConfigured provider 未配置各态 + settings 未装配 →
// ErrAvatarNotConfigured（直调上传接口按 internal 映射，不新增错误码），
// 零 Resolve / 零 Put。
func TestAvatarUploadNotConfigured(t *testing.T) {
	oauthRow := avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png"))
	oauthRow.Category = "auth"

	for name, mutate := range map[string]func(e *avatarTestEnv){
		"settings 键空串": func(e *avatarTestEnv) { e.settings.values[settings.KeyAvatarStorageProvider] = "" },
		"settings 键缺失": func(e *avatarTestEnv) { delete(e.settings.values, settings.KeyAvatarStorageProvider) },
		"provider 行查无": func(e *avatarTestEnv) { delete(e.providers.rows, avatarTestProviderKey) },
		"category≠storage": func(e *avatarTestEnv) {
			e.providers.rows[avatarTestProviderKey] = oauthRow
		},
	} {
		e := avatarTestEnvNew(t)
		mutate(e)
		_, err := e.upload(avatarTestUploadReq())
		if !errors.Is(err, ErrAvatarNotConfigured) {
			t.Errorf("%s: err = %v, want ErrAvatarNotConfigured", name, err)
		}
		if len(e.resolver.calls) != 0 || len(e.storage.putCalls) != 0 {
			t.Errorf("%s: Resolve/Put = %d/%d, want 0/0", name, len(e.resolver.calls), len(e.storage.putCalls))
		}
	}

	// Settings 未装配（nil）：防御读按未配置处理（handler 同款）。
	e := avatarTestEnvNew(t)
	e.svc = NewAvatarService(AvatarDeps{Providers: e.providers, Users: e.users, Resolver: e.resolver})
	if _, err := e.upload(avatarTestUploadReq()); !errors.Is(err, ErrAvatarNotConfigured) {
		t.Errorf("settings nil err = %v, want ErrAvatarNotConfigured", err)
	}
}

// TestAvatarUploadInfraErrors 基础设施错误包装透传（非哨兵，按 internal
// 映射）：Resolve 失败 / Put 失败；user 行不存在 404 优先。
func TestAvatarUploadInfraErrors(t *testing.T) {
	e := avatarTestEnvNew(t)
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png"))
	e.resolver.err = storage.ErrNotConfigured
	if _, err := e.upload(avatarTestUploadReq()); !errors.Is(err, storage.ErrNotConfigured) {
		t.Errorf("Resolve 失败 err = %v, want 包装 storage.ErrNotConfigured 透传", err)
	}

	e = avatarTestEnvNew(t)
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png"))
	e.storage.putErr = errors.New("avatar test: put down")
	if _, err := e.upload(avatarTestUploadReq()); err == nil || !strings.Contains(err.Error(), "put down") {
		t.Errorf("Put 失败 err = %v, want 包装上抛", err)
	}

	e = avatarTestEnvNew(t)
	e.providers.rows[avatarTestProviderKey] = avatarTestProviderRow(t, "s3", avatarTestExt("proxy", 600, 2<<20, "image/png"))
	e.users.missing = true
	if _, err := e.upload(avatarTestUploadReq()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("user 不存在 err = %v, want sql.ErrNoRows 透传（404 优先）", err)
	}
	if len(e.resolver.calls) != 0 {
		t.Errorf("Resolve 调用 = %d, want 0（存在性先判在前）", len(e.resolver.calls))
	}
}
