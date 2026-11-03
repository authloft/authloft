// user_thirdparty_bind 表 repo 层测试：真实 MariaDB 测试实例
// 经 UC_TEST_MYSQL_DSN env 注入，无 env 时 skip。表结构由 migrate.Up 建
//（§3.16 DDL 唯一来源）；用例开始 drop 全表、结束 drop 全表 +
// assertNoTables 自证零残留（同既有 repo 测试口径）。
// setup（providerTestSetup）与共享辅助在 provider_repo_test.go、
// settings_repo_test.go、db_test.go。user_id 是逻辑引用（§4.3 无外键），
// 用例直接用字面值构造归属关系，不依赖 user 表行。连接串只经环境变量
// 注入，代码不含主机 / 凭证信息。
package repo

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	"authloft/internal/repo/model"
)

// TestBindRepoCreateAndFind（env-skip）：Create → FindByProviderOpenID
// 命中与字段一致（extra 字节透传不解析）→ 默认值（union_id/nickname/
// avatar 空串、extra NULL）→ 未命中 → ListByUserID 按用户隔离。
func TestBindRepoCreateAndFind(t *testing.T) {
	_, br := providerTestSetup(t)
	ctx := context.Background()

	extra := []byte{0x82, 0xa4, 'n', 'a', 'm', 'e'} // 伪 msgpack：repo 只透传不解析
	b := &model.UserThirdpartyBind{
		UserID:      7,
		ProviderKey: "qq",
		OpenID:      "openid_qq_1",
		UnionID:     "union_tencent_1",
		Nickname:    "QQ 昵称",
		AvatarURL:   "https://q.cn/a.png",
		Extra:       extra,
	}
	if err := br.Create(ctx, b); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	if b.ID == 0 {
		t.Fatal("Create 后 ID 应非零（自增回填）")
	}
	if b.CreatedAt.IsZero() {
		t.Error("Create 应自动填充 created_at")
	}

	got, err := br.FindByProviderOpenID(ctx, "qq", "openid_qq_1")
	if err != nil {
		t.Fatalf("FindByProviderOpenID 失败: %v", err)
	}
	if got.ID != b.ID || got.UserID != 7 || got.UnionID != "union_tencent_1" ||
		got.Nickname != "QQ 昵称" || got.AvatarURL != "https://q.cn/a.png" {
		t.Errorf("FindByProviderOpenID 字段不一致: %+v", got)
	}
	if !bytes.Equal(got.Extra, extra) {
		t.Errorf("extra 应字节透传不解析: %v, want %v", got.Extra, extra)
	}

	// 最小字段 Create：union_id / nickname / avatar 默认空串、extra NULL。
	b2 := &model.UserThirdpartyBind{UserID: 7, ProviderKey: "wechat", OpenID: "openid_wx_1"}
	if err := br.Create(ctx, b2); err != nil {
		t.Fatalf("最小字段 Create 失败: %v", err)
	}
	got2, err := br.FindByProviderOpenID(ctx, "wechat", "openid_wx_1")
	if err != nil {
		t.Fatalf("FindByProviderOpenID 二次失败: %v", err)
	}
	if got2.UnionID != "" || got2.Nickname != "" || got2.AvatarURL != "" {
		t.Errorf("默认值应为空串: %+v", got2)
	}
	if got2.Extra != nil && len(got2.Extra) != 0 {
		t.Errorf("extra 默认应 NULL/空: %v", got2.Extra)
	}

	// 未命中。
	if _, err := br.FindByProviderOpenID(ctx, "qq", "nope"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("未命中应 ErrRecordNotFound, got %v", err)
	}

	// ListByUserID：用户 7 两行；用户 8 一行，互不泄漏。
	b3 := &model.UserThirdpartyBind{UserID: 8, ProviderKey: "qq", OpenID: "openid_qq_2"}
	if err := br.Create(ctx, b3); err != nil {
		t.Fatalf("用户 8 Create 失败: %v", err)
	}
	rows, err := br.ListByUserID(ctx, 7)
	if err != nil || len(rows) != 2 {
		t.Fatalf("用户 7 绑定列表 = %d 行 err=%v; want 2/nil", len(rows), err)
	}
	if rows[0].ProviderKey != "qq" || rows[1].ProviderKey != "wechat" {
		t.Errorf("用户 7 列表顺序（id ASC）不符: %+v", rows)
	}
	rows, err = br.ListByUserID(ctx, 8)
	if err != nil || len(rows) != 1 || rows[0].OpenID != "openid_qq_2" {
		t.Fatalf("用户 8 绑定列表 = %+v err=%v; want openid_qq_2", rows, err)
	}
	if rows, err = br.ListByUserID(ctx, 404); err != nil || len(rows) != 0 {
		t.Errorf("无绑定用户应空列表: %d 行 err=%v", len(rows), err)
	}
}

// TestBindRepoDuplicate（env-skip）：uk_provider_openid 冲突判别——
// 同 (provider_key, open_id) 已绑他人再 Create → ErrBindDuplicate 且
// 不入库；不同 provider 同 open_id 不冲突。
func TestBindRepoDuplicate(t *testing.T) {
	_, br := providerTestSetup(t)
	ctx := context.Background()

	if err := br.Create(ctx, &model.UserThirdpartyBind{
		UserID: 1, ProviderKey: "qq", OpenID: "openid_dup",
	}); err != nil {
		t.Fatalf("首个绑定 Create 失败: %v", err)
	}

	// 已绑用户 1，用户 2 再绑同一 (provider_key, open_id)。
	if err := br.Create(ctx, &model.UserThirdpartyBind{
		UserID: 2, ProviderKey: "qq", OpenID: "openid_dup",
	}); !errors.Is(err, ErrBindDuplicate) {
		t.Errorf("open_id 已绑他人应 ErrBindDuplicate, got %v", err)
	}

	// 冲突不入库：用户 2 名下无绑定行。
	rows, err := br.ListByUserID(ctx, 2)
	if err != nil || len(rows) != 0 {
		t.Errorf("冲突不应入库: %d 行 err=%v; want 0/nil", len(rows), err)
	}

	// 不同 provider_key 同 open_id：不冲突。
	if err := br.Create(ctx, &model.UserThirdpartyBind{
		UserID: 2, ProviderKey: "wechat", OpenID: "openid_dup",
	}); err != nil {
		t.Errorf("不同 provider 同 open_id 应成功: %v", err)
	}

	// 原行不受影响：仍属用户 1。
	orig, err := br.FindByProviderOpenID(ctx, "qq", "openid_dup")
	if err != nil || orig.UserID != 1 {
		t.Errorf("原绑定行应仍属用户 1: %+v, %v", orig, err)
	}
}

// TestBindRepoUnbind（env-skip）：本人解绑成功且行消失；他人解绑
// ErrBindNotOwned 且行仍在；不存在的 id → ErrRecordNotFound。
func TestBindRepoUnbind(t *testing.T) {
	_, br := providerTestSetup(t)
	ctx := context.Background()

	b := &model.UserThirdpartyBind{UserID: 5, ProviderKey: "qq", OpenID: "openid_u5"}
	if err := br.Create(ctx, b); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}

	// 本人解绑：成功、行消失。
	if err := br.Unbind(ctx, b.ID, 5); err != nil {
		t.Fatalf("本人 Unbind 失败: %v", err)
	}
	if _, err := br.FindByProviderOpenID(ctx, "qq", "openid_u5"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("解绑后应查无此行, got %v", err)
	}

	// 重新绑定后，他人解绑：归属校验失败、行保留。
	if err := br.Create(ctx, b); err != nil {
		t.Fatalf("二次 Create 失败: %v", err)
	}
	if err := br.Unbind(ctx, b.ID, 6); !errors.Is(err, ErrBindNotOwned) {
		t.Errorf("他人 Unbind 应 ErrBindNotOwned, got %v", err)
	}
	if _, err := br.FindByProviderOpenID(ctx, "qq", "openid_u5"); err != nil {
		t.Errorf("归属校验失败时行应保留: %v", err)
	}

	// 本人才可删。
	if err := br.Unbind(ctx, b.ID, 5); err != nil {
		t.Fatalf("本人二次 Unbind 失败: %v", err)
	}

	// 不存在的 id。
	if err := br.Unbind(ctx, 404, 5); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("不存在 id 应 ErrRecordNotFound, got %v", err)
	}
}

// TestBindRepoFindByUnionID（env-skip）：idx_provider_unionid 查询——
// §12.7 场景（union provider 行 + 实际 provider 行同 union_id）各自
// 命中；同 provider 下多行同 union_id 全量返回（索引非唯一）；不匹配
// 行与空 union_id 行不泄漏。
func TestBindRepoFindByUnionID(t *testing.T) {
	_, br := providerTestSetup(t)
	ctx := context.Background()

	// §12.7 例：wechat_union（虚拟 Union Provider，open_id 即 unionid）
	// 与 wechat_mp_1 的绑定行同记 union_wx；另有一行 union_id 为空。
	seed := []model.UserThirdpartyBind{
		{UserID: 9, ProviderKey: "wechat_mp_1", OpenID: "openid_mp_1", UnionID: "union_wx", Nickname: "mp1"},
		{UserID: 9, ProviderKey: "wechat_union", OpenID: "union_wx", UnionID: "union_wx"},
		{UserID: 10, ProviderKey: "wechat_mp_2", OpenID: "openid_mp_2", UnionID: "union_wx", Nickname: "mp2"},
		{UserID: 10, ProviderKey: "qq", OpenID: "openid_qq", UnionID: "", Nickname: "qq"},
	}
	for i := range seed {
		if err := br.Create(ctx, &seed[i]); err != nil {
			t.Fatalf("Create %+v 失败: %v", seed[i], err)
		}
	}

	// 按 wechat_mp_1 + union_wx：只命中自己那行（union 行的 provider_key
	// 是 wechat_union，不属于 wechat_mp_1 的结果）。
	rows, err := br.FindByUnionID(ctx, "wechat_mp_1", "union_wx")
	if err != nil || len(rows) != 1 {
		t.Fatalf("wechat_mp_1+union_wx = %d 行 err=%v; want 1/nil", len(rows), err)
	}
	if rows[0].OpenID != "openid_mp_1" || rows[0].UserID != 9 {
		t.Errorf("命中行不符: %+v", rows[0])
	}

	// Union 归并查询（wechat_union + union_wx，open_id 即 unionid）：命中
	// union provider 行（§12.7「两边均可登录」的数据来源）。
	rows, err = br.FindByUnionID(ctx, "wechat_union", "union_wx")
	if err != nil || len(rows) != 1 || rows[0].OpenID != "union_wx" || rows[0].UserID != 9 {
		t.Errorf("wechat_union+union_wx = %+v err=%v; want open_id=union_wx uid=9", rows, err)
	}

	// 同 provider 下多行同 union_id（追加 wechat_mp_1 第二个 open_id）。
	if err := br.Create(ctx, &model.UserThirdpartyBind{
		UserID: 11, ProviderKey: "wechat_mp_1", OpenID: "openid_mp_1b", UnionID: "union_wx",
	}); err != nil {
		t.Fatalf("追加绑定失败: %v", err)
	}
	if rows, err = br.FindByUnionID(ctx, "wechat_mp_1", "union_wx"); err != nil || len(rows) != 2 {
		t.Errorf("wechat_mp_1+union_wx = %d 行 err=%v; want 2（索引非唯一）", len(rows), err)
	}

	// 空结果。
	if rows, err = br.FindByUnionID(ctx, "wechat_mp_1", "union_other"); err != nil || len(rows) != 0 {
		t.Errorf("无匹配应空列表: %d 行 err=%v", len(rows), err)
	}
}
