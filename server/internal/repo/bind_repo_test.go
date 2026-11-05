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
// 命中与字段一致（extra 字节透传不解析）→ 默认值（nickname/avatar 空串、
// extra NULL）→ 未命中 → ListByUserID 按用户隔离。
func TestBindRepoCreateAndFind(t *testing.T) {
	_, br := providerTestSetup(t)
	ctx := context.Background()

	extra := []byte{0x82, 0xa4, 'n', 'a', 'm', 'e'} // 伪 msgpack：repo 只透传不解析
	b := &model.UserThirdpartyBind{
		UserID:      7,
		ProviderKey: "qq",
		OpenID:      "openid_qq_1",
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
	if got.ID != b.ID || got.UserID != 7 ||
		got.Nickname != "QQ 昵称" || got.AvatarURL != "https://q.cn/a.png" {
		t.Errorf("FindByProviderOpenID 字段不一致: %+v", got)
	}
	if !bytes.Equal(got.Extra, extra) {
		t.Errorf("extra 应字节透传不解析: %v, want %v", got.Extra, extra)
	}

	// 最小字段 Create：nickname / avatar 默认空串、extra NULL。
	b2 := &model.UserThirdpartyBind{UserID: 7, ProviderKey: "wechat", OpenID: "openid_wx_1"}
	if err := br.Create(ctx, b2); err != nil {
		t.Fatalf("最小字段 Create 失败: %v", err)
	}
	got2, err := br.FindByProviderOpenID(ctx, "wechat", "openid_wx_1")
	if err != nil {
		t.Fatalf("FindByProviderOpenID 二次失败: %v", err)
	}
	if got2.Nickname != "" || got2.AvatarURL != "" {
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

// TestBindRepoUnionRowByProviderOpenID（env-skip）：§12.7 Union 归并最终口径——
// Union 行以 (Union Provider 的 provider_key, open_id=unionid) 唯一存储，可被
// FindByProviderOpenID 命中；普通 Provider 行只按渠道 openid 命中（不存 unionid）；
// 同 unionid 的不同普通 Provider 归并到同一 Union 行（uk_provider_openid 保证
// 同一 unionid 全局只归并到一个账号）。
func TestBindRepoUnionRowByProviderOpenID(t *testing.T) {
	_, br := providerTestSetup(t)
	ctx := context.Background()

	const (
		unionProviderKey = "wechat_union" // category=union 的虚拟 Union Provider
		unionID          = "union_wx_001" // unionid 值，作为 Union 行的 open_id
	)

	// 普通 Provider 行：只存渠道 openid（不存 unionid）。
	mp1 := &model.UserThirdpartyBind{UserID: 9, ProviderKey: "wechat_mp_1", OpenID: "openid_mp_1", Nickname: "mp1"}
	mp2 := &model.UserThirdpartyBind{UserID: 9, ProviderKey: "wechat_mp_2", OpenID: "openid_mp_2", Nickname: "mp2"}
	// Union 行：provider_key = Union Provider，open_id = unionid。
	unionRow := &model.UserThirdpartyBind{UserID: 9, ProviderKey: unionProviderKey, OpenID: unionID}
	for _, b := range []*model.UserThirdpartyBind{mp1, mp2, unionRow} {
		if err := br.Create(ctx, b); err != nil {
			t.Fatalf("Create %+v 失败: %v", b, err)
		}
	}

	// a) Union 行按 (Union Provider key, open_id=unionid) 可被 FindByProviderOpenID 命中。
	gotUnion, err := br.FindByProviderOpenID(ctx, unionProviderKey, unionID)
	if err != nil {
		t.Fatalf("Union 行应可被 FindByProviderOpenID 命中: %v", err)
	}
	if gotUnion.ID != unionRow.ID || gotUnion.UserID != 9 || gotUnion.OpenID != unionID {
		t.Errorf("Union 行字段不符: %+v", gotUnion)
	}

	// b) 普通 Provider 行只按渠道 openid 命中，不按 unionid 命中。
	gotMp1, err := br.FindByProviderOpenID(ctx, "wechat_mp_1", "openid_mp_1")
	if err != nil {
		t.Fatalf("普通 Provider 行应按渠道 openid 命中: %v", err)
	}
	if gotMp1.ID != mp1.ID || gotMp1.UserID != 9 {
		t.Errorf("普通行字段不符: %+v", gotMp1)
	}
	// 用 unionid 当 open_id 查普通 provider 应查无此行（普通行不存 unionid）。
	if _, err := br.FindByProviderOpenID(ctx, "wechat_mp_1", unionID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("普通行不应按 unionid 命中（不存 unionid）, got %v", err)
	}

	// c) 同 unionid 不同普通 provider 归并到同一 Union 行：两个普通行与 Union
	//    行都属用户 9；为另一用户再写同 unionid 的 Union 行会被 uk_provider_openid
	//    拒绝（同一 unionid 全局只归并到一个账号）。
	if err := br.Create(ctx, &model.UserThirdpartyBind{
		UserID: 10, ProviderKey: unionProviderKey, OpenID: unionID,
	}); !errors.Is(err, ErrBindDuplicate) {
		t.Errorf("同 unionid 的 Union 行应被 uk_provider_openid 判为 ErrBindDuplicate, got %v", err)
	}
	gotUnion, err = br.FindByProviderOpenID(ctx, unionProviderKey, unionID)
	if err != nil || gotUnion.UserID != 9 {
		t.Errorf("Union 行应仍归并到用户 9: %+v, %v", gotUnion, err)
	}
	rows, err := br.ListByUserID(ctx, 9)
	if err != nil || len(rows) != 3 {
		t.Fatalf("用户 9 绑定列表 = %d 行 err=%v; want 3/nil", len(rows), err)
	}
}

// TestBindRepoCreateWithUnion（env-skip；§12.7 行 1548 创建方向）：
// 单事务写普通行 + Union 行（open_id=unionid）；Union 键被他人占用时整体
// 回滚（普通行不留库）；无关联 Union Provider 时只写普通行（语义同 Create）。
func TestBindRepoCreateWithUnion(t *testing.T) {
	_, br := providerTestSetup(t)
	ctx := context.Background()

	const (
		unionProviderKey = "wechat_union2"
		unionID          = "union_wx_002"
	)

	// a) 普通 + Union 同事务写入：两行均落库，Union 行 open_id=unionid。
	b := &model.UserThirdpartyBind{UserID: 21, ProviderKey: "wechat_mp_a", OpenID: "openid_a", Nickname: "甲"}
	if err := br.CreateWithUnion(ctx, b, unionProviderKey, unionID); err != nil {
		t.Fatalf("CreateWithUnion 失败: %v", err)
	}
	gotA, err := br.FindByProviderOpenID(ctx, "wechat_mp_a", "openid_a")
	if err != nil || gotA.UserID != 21 {
		t.Fatalf("普通行未落库: %+v, %v", gotA, err)
	}
	gotU, err := br.FindByProviderOpenID(ctx, unionProviderKey, unionID)
	if err != nil || gotU.UserID != 21 {
		t.Fatalf("Union 行未落库（open_id 应为 unionid）: %+v, %v", gotU, err)
	}

	// b) Union 键被他人占用 → ErrBindDuplicate 且普通行整体回滚（不留
	//    孤立普通行占用唯一键）。
	b2 := &model.UserThirdpartyBind{UserID: 22, ProviderKey: "wechat_mp_b", OpenID: "openid_b"}
	if err := br.CreateWithUnion(ctx, b2, unionProviderKey, unionID); !errors.Is(err, ErrBindDuplicate) {
		t.Fatalf("Union 键冲突应 ErrBindDuplicate, got %v", err)
	}
	if _, err := br.FindByProviderOpenID(ctx, "wechat_mp_b", "openid_b"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Union 冲突时普通行应整体回滚, got %v", err)
	}

	// c) unionProviderKey 为空 → 只写普通行（语义同 Create）。
	b3 := &model.UserThirdpartyBind{UserID: 23, ProviderKey: "wechat_mp_c", OpenID: "openid_c"}
	if err := br.CreateWithUnion(ctx, b3, "", "union_x"); err != nil {
		t.Fatalf("无 Union 关联写入失败: %v", err)
	}
	if _, err := br.FindByProviderOpenID(ctx, "wechat_mp_c", "openid_c"); err != nil {
		t.Fatalf("普通行应落库: %v", err)
	}
	rows, _ := br.ListByUserID(ctx, 23)
	if len(rows) != 1 {
		t.Errorf("用户 23 应只有 1 行（无 Union 行）, got %d", len(rows))
	}

	// d) unionID 为空（适配器未返回 unionid）→ 只写普通行。
	b4 := &model.UserThirdpartyBind{UserID: 24, ProviderKey: "wechat_mp_d", OpenID: "openid_d"}
	if err := br.CreateWithUnion(ctx, b4, unionProviderKey, ""); err != nil {
		t.Fatalf("unionid 缺失时写入失败: %v", err)
	}
}
