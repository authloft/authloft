// provider 表 repo 层测试：真实 MariaDB 测试实例经
// UC_TEST_MYSQL_DSN env 注入，无 env 时集成用例 skip（ext 纯函数用例
// 始终本地可跑）。表结构由 migrate.Up 建（§3.16 DDL 唯一来源）；用例
// 开始 drop 全表、结束 drop 全表 + assertNoTables 自证零残留（同既有
// repo 测试口径）。跨二进制互斥由 settings_repo_test.go
// 的 TestMain（GET_LOCK uc_test_db_slot）保证；共享辅助 dropAllTables /
// assertNoTables / dbTestConfig 在彼处与 db_test.go。连接串只经环境变量
// 注入，代码不含主机 / 凭证信息。
package repo

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	"authloft/gen/go/provider"
	"authloft/internal/migrate"
	"authloft/internal/repo/model"
)

// providerTestSetup 清库 + 建表 + 注册测后零残留清理，返回就绪的
// ProviderRepo 与 BindRepo（bind_repo_test.go 复用同一 setup）。
func providerTestSetup(t *testing.T) (*ProviderRepo, *BindRepo) {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 provider repo 集成用例")
	}
	ctx := context.Background()
	raw, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := raw.Ping(); err != nil {
		t.Fatalf("连接 MariaDB 测试实例失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := dropAllTables(raw); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	if err := migrate.Up(ctx, dsn); err != nil {
		t.Fatalf("migrate up 失败: %v", err)
	}
	t.Cleanup(func() {
		if err := dropAllTables(raw); err != nil {
			t.Errorf("测后清空测试库失败: %v", err)
		}
		if err := assertNoTables(raw); err != nil {
			t.Errorf("零残留自证失败: %v", err)
		}
	})
	db, err := Open(dbTestConfig(dsn, 10, 5, time.Minute))
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return NewProviderRepo(db), NewBindRepo(db)
}

// providerTestExt 构造覆盖 §12.1 各字段段的样例 Ext（凭证 / 端点 /
// 存储 / 上传模式 / 消息 / 长尾 map）。
func providerTestExt() *provider.Ext {
	return &provider.Ext{
		ClientId:          "wx_appid_123",
		ClientSecret:      "secret_do_not_leak",
		AppId:             "tp_appid",
		Cert:              "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq\n-----END PUBLIC KEY-----\n",
		Scopes:            "snsapi_login",
		UserMapping:       map[string]string{"nickname": "raw.nickname", "avatar": "raw.avatar_url"},
		ProviderUrl:       "https://auth.example.com",
		CustomAuthUrl:     "https://auth.example.com/authorize",
		CustomTokenUrl:    "https://auth.example.com/token",
		CustomUserInfoUrl: "https://auth.example.com/userinfo",
		Host:              "smtp.example.com",
		Port:              465,
		DisableSsl:        true,
		IntranetEndpoint:  "http://intranet.example.com",
		Bucket:            "al-storage",
		RegionId:          "cn-hangzhou",
		PathPrefix:        "u/{uid}/",
		Domain:            "https://cdn.example.com",
		Endpoint:          "https://s3.example.com",
		PathStyle:         true,
		PublicRead:        false,
		QrcodeAutoDelete:  true,
		StorageProvider:   "al-storage",
		StoragePath:       "qrcode/{ticket_id}.png",
		UploadMode:        "direct",
		PresignTtl:        300,
		MaxSize:           2097152,
		AllowedTypes:      "image/png,image/jpeg",
		From:              "noreply@example.com",
		SignName:          "Authloft",
		TemplateCode:      "SMS_12345678",
		Metadata:          map[string]string{"sign_type": "RSA2", "acl": "private"},
	}
}

// TestProviderRepoExtRoundTrip（纯函数，无 env 本地可跑）：Marshal 与
// Parse 互逆（proto.Equal 逐字段）；nil / 空输入边界；1 MiB 业务上限
// 拒绝；坏字节解析报错。
func TestProviderRepoExtRoundTrip(t *testing.T) {
	// nil → nil（ext 列 NULL 语义）。
	data, err := MarshalProviderExt(nil)
	if err != nil || data != nil {
		t.Fatalf("Marshal(nil) = %v, %v; want nil, nil", data, err)
	}

	// 空 Ext → 空字节（proto3 空消息零长度）→ 解析回空消息。
	data, err = MarshalProviderExt(&provider.Ext{})
	if err != nil {
		t.Fatalf("Marshal(空 Ext) 失败: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("空 Ext 序列化应为零长度, got %d bytes", len(data))
	}
	got, err := ParseProviderExt(nil)
	if err != nil || got == nil {
		t.Fatalf("Parse(nil) = %v, %v; want 非 nil 空消息, nil", got, err)
	}
	got, err = ParseProviderExt(data)
	if err != nil || got == nil {
		t.Fatalf("Parse(空字节) = %v, %v; want 非 nil 空消息, nil", got, err)
	}

	// 全字段 round-trip：proto.Equal 逐字段深度比较（含两个 map）。
	src := providerTestExt()
	data, err = MarshalProviderExt(src)
	if err != nil {
		t.Fatalf("Marshal 样例 Ext 失败: %v", err)
	}
	if len(data) == 0 || len(data) > providerExtMaxBytes {
		t.Fatalf("序列化长度 %d 异常", len(data))
	}
	got, err = ParseProviderExt(data)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if !proto.Equal(src, got) {
		t.Errorf("round-trip 后消息不一致:\nsrc = %v\ngot = %v", src, got)
	}

	// 超 1 MiB 拒绝（§4.1 行 615：写入前校验，超限直接拒绝）。
	big := providerTestExt()
	big.Cert = strings.Repeat("x", 1<<20+1)
	if _, err := MarshalProviderExt(big); err == nil {
		t.Error("超 1 MiB 的 Ext 应被拒绝, got nil error")
	}

	// 坏字节解析报错（非 Protobuf 线格式）。
	if _, err := ParseProviderExt([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Error("坏字节解析应报错, got nil error")
	}
}

// TestProviderRepoCRUD（env-skip）：Create 默认值回填（default tag 值
// 显式写入）→ FindByKey 命中与字段一致（ext 落库读回再 Parse 的
// round-trip）→ uk_provider_key 冲突判别与不入库 → Update 覆盖与
// 同值幂等 → Delete 与重复 Delete。
func TestProviderRepoCRUD(t *testing.T) {
	rp, _ := providerTestSetup(t)
	ctx := context.Background()

	extData, err := MarshalProviderExt(providerTestExt())
	if err != nil {
		t.Fatalf("MarshalProviderExt 失败: %v", err)
	}
	p := &model.Provider{
		ProviderKey:   "qq_test",
		UnionProvider: "tencent_union",
		DisplayName:   "QQ 登录",
		Category:      "oauth",
		Type:          "qq",
		IconURL:       "https://cdn.example.com/qq.png",
		Remark:        "测试渠道",
		Ext:           extData,
	}
	if err := rp.Create(ctx, p); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	if p.ID == 0 {
		t.Fatal("Create 后 ID 应非零（自增回填）")
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Error("Create 应自动填充 created_at / updated_at")
	}
	// default tag 值回填（§4.1 DDL 默认：1 / 1 / 0 / email,phone / 1 /
	// social / 0 / ''）。
	if p.EnableSignin != 1 || p.EnableSignup != 1 || p.AutoBind != 0 ||
		p.AutoBindFields != "email,phone" || p.IsEnabled != 1 ||
		p.UiGroup != "social" || p.SortOrder != 0 {
		t.Errorf("Create 后默认值回填不一致: %+v", p)
	}

	got, err := rp.FindByKey(ctx, "qq_test")
	if err != nil {
		t.Fatalf("FindByKey 失败: %v", err)
	}
	if got.ID != p.ID || got.UnionProvider != "tencent_union" ||
		got.DisplayName != "QQ 登录" || got.Category != "oauth" ||
		got.Type != "qq" || got.IconURL != "https://cdn.example.com/qq.png" {
		t.Errorf("FindByKey 字段不一致: %+v", got)
	}
	// ext 落库读回 round-trip：字节相等 → Parse 后 proto 相等。
	if string(got.Ext) != string(extData) {
		t.Errorf("ext 落库读回字节不一致: %d vs %d bytes", len(got.Ext), len(extData))
	}
	extParsed, err := ParseProviderExt(got.Ext)
	if err != nil {
		t.Fatalf("ParseProviderExt(落库 ext) 失败: %v", err)
	}
	if !proto.Equal(providerTestExt(), extParsed) {
		t.Error("ext 落库读回 round-trip 不一致")
	}

	// 未命中。
	if _, err := rp.FindByKey(ctx, "nope"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("FindByKey 未命中应 ErrRecordNotFound, got %v", err)
	}

	// uk_provider_key 冲突：同 key 再建 → ErrProviderDuplicate，不入库。
	if err := rp.Create(ctx, &model.Provider{
		ProviderKey: "qq_test", UnionProvider: "", DisplayName: "重复",
		Category: "oauth", Type: "qq",
	}); !errors.Is(err, ErrProviderDuplicate) {
		t.Errorf("同 provider_key 冲突应 ErrProviderDuplicate, got %v", err)
	}
	if _, total, err := rp.ListProviders(ctx, ProviderListQuery{}); err != nil || total != 1 {
		t.Errorf("冲突不应入库: total=%d err=%v; want 1/nil", total, err)
	}

	// Update：改 display_name / 置 is_enabled=0（列级 UPDATE 落 0，default
	// tag 只影响 Create）/ 换 ext。
	got.DisplayName = "QQ 互联"
	got.IsEnabled = 0
	newExt, err := MarshalProviderExt(&provider.Ext{ClientId: "changed", Scopes: "read"})
	if err != nil {
		t.Fatalf("MarshalProviderExt 二次失败: %v", err)
	}
	got.Ext = newExt
	if err := rp.Update(ctx, got); err != nil {
		t.Fatalf("Update 失败: %v", err)
	}
	after, err := rp.FindByKey(ctx, "qq_test")
	if err != nil {
		t.Fatalf("Update 后 FindByKey 失败: %v", err)
	}
	if after.DisplayName != "QQ 互联" || after.IsEnabled != 0 {
		t.Errorf("Update 后字段不一致: %+v", after)
	}
	extAfter, err := ParseProviderExt(after.Ext)
	if err != nil || extAfter.ClientId != "changed" || extAfter.Scopes != "read" {
		t.Errorf("Update 后 ext 不一致: %v, %v", extAfter, err)
	}
	// 同值二次 Update：changed-rows 语义 rows=0 但行存在 → 幂等成功不误报。
	if err := rp.Update(ctx, after); err != nil {
		t.Errorf("同值二次 Update 应幂等成功: %v", err)
	}

	// Update 不存在的行（传完整行口径：带合法时间，避免零值 DATETIME
	// 在 strict mode 下先行报错掩盖 not found 语义）。
	ghostAt := time.Now().Truncate(time.Second)
	ghost := &model.Provider{ID: 404, ProviderKey: "ghost", UnionProvider: "", DisplayName: "ghost", Category: "oauth", Type: "qq", CreatedAt: ghostAt, UpdatedAt: ghostAt}
	if err := rp.Update(ctx, ghost); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Update 不存在的行应 ErrRecordNotFound, got %v", err)
	}

	// Delete：删后查无此行；重复删可判别 not found。
	if err := rp.Delete(ctx, p.ID); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	if _, err := rp.FindByKey(ctx, "qq_test"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Delete 后 FindByKey 应 ErrRecordNotFound, got %v", err)
	}
	if err := rp.Delete(ctx, p.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("重复 Delete 应 ErrRecordNotFound, got %v", err)
	}
}

// TestProviderRepoColumnUpdates（env-skip）：列级 UPDATE 最小增量——
// SetEnabled 置 0/置 1、同值幂等、行不存在判别；UpdateSortOrders 批量落库
// 与「含不存在 key 全批回滚」。
func TestProviderRepoColumnUpdates(t *testing.T) {
	rp, _ := providerTestSetup(t)
	ctx := context.Background()

	seed := []model.Provider{
		{ProviderKey: "wx", UnionProvider: "", DisplayName: "微信", Category: "oauth", Type: "wechat_mp", SortOrder: 10, IsEnabled: 1},
		{ProviderKey: "smtp", UnionProvider: "", DisplayName: "SMTP", Category: "email", Type: "smtp", SortOrder: 20, IsEnabled: 1},
	}
	for i := range seed {
		if err := rp.Create(ctx, &seed[i]); err != nil {
			t.Fatalf("Create %s 失败: %v", seed[i].ProviderKey, err)
		}
	}
	wx := seed[0]

	// SetEnabled 置 0（禁用零值只能走列级 UPDATE，default tag 只影响 Create）。
	if err := rp.SetEnabled(ctx, wx.ID, 0); err != nil {
		t.Fatalf("SetEnabled(0) 失败: %v", err)
	}
	got, err := rp.FindByKey(ctx, "wx")
	if err != nil {
		t.Fatalf("FindByKey 失败: %v", err)
	}
	if got.IsEnabled != 0 {
		t.Errorf("SetEnabled 后 is_enabled = %d, want 0", got.IsEnabled)
	}
	if got.DisplayName != "微信" || got.SortOrder != 10 {
		t.Errorf("列级 UPDATE 不得波及其他列: %+v", got)
	}

	// 同值二次 SetEnabled：changed-rows rows=0 但行在 → 幂等成功不误报。
	if err := rp.SetEnabled(ctx, wx.ID, 0); err != nil {
		t.Errorf("同值 SetEnabled 应幂等成功: %v", err)
	}
	// 置回 1。
	if err := rp.SetEnabled(ctx, wx.ID, 1); err != nil {
		t.Fatalf("SetEnabled(1) 失败: %v", err)
	}
	// 行不存在：rows=0 补查 → ErrRecordNotFound。
	if err := rp.SetEnabled(ctx, 404, 1); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("SetEnabled 不存在的行应 ErrRecordNotFound, got %v", err)
	}

	// UpdateSortOrders 批量落库：两行 sort_order 互换。
	if err := rp.UpdateSortOrders(ctx, []ProviderSortUpdate{
		{ProviderKey: "wx", SortOrder: 20},
		{ProviderKey: "smtp", SortOrder: 10},
	}); err != nil {
		t.Fatalf("UpdateSortOrders 失败: %v", err)
	}
	for key, want := range map[string]int32{"wx": 20, "smtp": 10} {
		row, err := rp.FindByKey(ctx, key)
		if err != nil {
			t.Fatalf("FindByKey(%s) 失败: %v", key, err)
		}
		if row.SortOrder != want {
			t.Errorf("%s sort_order = %d, want %d", key, row.SortOrder, want)
		}
	}

	// 含不存在 key：全批回滚（事务语义），已存在行的值不变。
	err = rp.UpdateSortOrders(ctx, []ProviderSortUpdate{
		{ProviderKey: "wx", SortOrder: 99},
		{ProviderKey: "nope", SortOrder: 1},
	})
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("含不存在 key 应 ErrRecordNotFound, got %v", err)
	}
	row, err := rp.FindByKey(ctx, "wx")
	if err != nil {
		t.Fatalf("回滚后 FindByKey 失败: %v", err)
	}
	if row.SortOrder != 20 {
		t.Errorf("回滚后 wx sort_order = %d, want 20（全批回滚）", row.SortOrder)
	}

	// 空 updates：no-op 成功。
	if err := rp.UpdateSortOrders(ctx, nil); err != nil {
		t.Errorf("空 updates 应 no-op: %v", err)
	}
}

// TestProviderRepoList（env-skip）：category / type / is_enabled 过滤 +
// §1.7 分页参数归一 + sort_order ASC, id ASC 全序稳定。
func TestProviderRepoList(t *testing.T) {
	rp, _ := providerTestSetup(t)
	ctx := context.Background()

	// 5 行：2 个 oauth、1 个 captcha、1 个 sms、1 个 email；sort_order
	// 交错验证排序，id 递增保证同 sort_order 内次序稳定。
	seed := []model.Provider{
		{ProviderKey: "qq", UnionProvider: "tencent", DisplayName: "QQ", Category: "oauth", Type: "qq", SortOrder: 30},
		{ProviderKey: "wechat_mp_1", UnionProvider: "wechat", DisplayName: "小程序 1", Category: "oauth", Type: "wechat_mp", SortOrder: 10},
		{ProviderKey: "turnstile", UnionProvider: "", DisplayName: "Turnstile", Category: "captcha", Type: "turnstile", SortOrder: 20},
		{ProviderKey: "aliyun_sms", UnionProvider: "", DisplayName: "阿里云短信", Category: "sms", Type: "aliyun_sms", SortOrder: 40},
		{ProviderKey: "smtp", UnionProvider: "", DisplayName: "SMTP", Category: "email", Type: "smtp", SortOrder: 10},
	}
	for i := range seed {
		if err := rp.Create(ctx, &seed[i]); err != nil {
			t.Fatalf("Create %s 失败: %v", seed[i].ProviderKey, err)
		}
	}

	// 无过滤全量：sort_order ASC, id ASC → wechat_mp_1(10) → smtp(10) →
	// turnstile(20) → qq(30) → aliyun_sms(40)。
	rows, total, err := rp.ListProviders(ctx, ProviderListQuery{})
	if err != nil || total != 5 || len(rows) != 5 {
		t.Fatalf("全量 = %d 行 total=%d err=%v; want 5/5/nil", len(rows), total, err)
	}
	wantOrder := []string{"wechat_mp_1", "smtp", "turnstile", "qq", "aliyun_sms"}
	for i, want := range wantOrder {
		if rows[i].ProviderKey != want {
			t.Errorf("全量顺序[%d] = %s, want %s（sort_order ASC, id ASC）", i, rows[i].ProviderKey, want)
		}
	}

	// 分页：page1 取 2 → wechat_mp_1, smtp。
	if rows, total, err = rp.ListProviders(ctx, ProviderListQuery{Page: 1, PageSize: 2}); err != nil ||
		total != 5 || len(rows) != 2 ||
		rows[0].ProviderKey != "wechat_mp_1" || rows[1].ProviderKey != "smtp" {
		t.Errorf("page1 = %+v total=%d err=%v; want wechat_mp_1,smtp", rows, total, err)
	}
	// 分页参数归一：Page<1 归 1；PageSize<1 默认 20；PageSize>100 clamp。
	if rows, _, err = rp.ListProviders(ctx, ProviderListQuery{Page: 0, PageSize: 2}); err != nil || len(rows) != 2 {
		t.Errorf("Page=0 应归 1: %d 行 err=%v", len(rows), err)
	}
	if _, _, err = rp.ListProviders(ctx, ProviderListQuery{Page: 1, PageSize: 150}); err != nil {
		t.Errorf("PageSize=150 应 clamp 100 不报错: %v", err)
	}

	// category 过滤（oauth 2 行：qq、wechat_mp_1）。
	oauth := "oauth"
	if rows, total, err = rp.ListProviders(ctx, ProviderListQuery{Category: &oauth}); err != nil ||
		total != 2 || len(rows) != 2 {
		t.Fatalf("category=oauth: %d 行 total=%d err=%v; want 2/2", len(rows), total, err)
	}
	for _, r := range rows {
		if r.Category != "oauth" {
			t.Errorf("category 过滤泄漏: %+v", r)
		}
	}

	// type 过滤。
	tp := "wechat_mp"
	if _, total, err = rp.ListProviders(ctx, ProviderListQuery{Type: &tp}); err != nil || total != 1 {
		t.Errorf("type=wechat_mp: total=%d err=%v; want 1", total, err)
	}

	// is_enabled 过滤（构造 0 态：列级 UPDATE，default tag 只在 Create
	// 显式写入 1，与 userTestSetStatus 同构）。
	zero := int8(0)
	if err := rp.db.Model(&model.Provider{}).
		Where("provider_key = ?", "qq").
		Update("is_enabled", 0).Error; err != nil {
		t.Fatalf("置 is_enabled=0 失败: %v", err)
	}
	if _, total, err = rp.ListProviders(ctx, ProviderListQuery{IsEnabled: &zero}); err != nil || total != 1 {
		t.Errorf("is_enabled=0: total=%d err=%v; want 1", total, err)
	}
	one := int8(1)
	if _, total, err = rp.ListProviders(ctx, ProviderListQuery{Category: &oauth, IsEnabled: &one}); err != nil || total != 1 {
		t.Errorf("category=oauth 且 is_enabled=1: total=%d err=%v; want 1（qq 已禁用）", total, err)
	}
}
