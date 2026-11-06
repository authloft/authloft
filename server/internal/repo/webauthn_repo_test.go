// user_credential_webauthn 表 repo 层测试：env 注入口径与共享
// 辅助见 credential_repo_test.go 头注；本文件覆盖同事务建两行（主键同值，
// §4.2 行 667）、uk_kind_credid 冲突判别与回滚零残留、Delete 同事务删两行
// sign_count 单行更新（§8.3 行 1047）、CredentialMeta webauthn
// 段 round-trip。
package repo

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"gorm.io/gorm"

	"authloft/gen/go/credential"
	"authloft/internal/repo/model"
)

// TestWebauthnRepoCreateAndQuery（env-skip）：Create 同事务建两行、主键
// 同值（行 667）；FindByCredentialID uk 命中；ListByUser 列表 id DESC；
// CredentialMeta webauthn 段（transports / attestation / aaguid /
// backup_*）经 meta 列 round-trip；未命中 ErrRecordNotFound。
func TestWebauthnRepoCreateAndQuery(t *testing.T) {
	rp, wr, _ := credentialTestSetup(t)
	ctx := context.Background()
	const uid = int64(201)

	// 无凭据用户：空列表。
	rows, err := wr.ListByUser(ctx, uid)
	if err != nil || len(rows) != 0 {
		t.Fatalf("空用户 ListByUser = %d 行, err %v; want 0/nil", len(rows), err)
	}

	waMeta, err := MarshalCredentialMeta(&credential.CredentialMeta{
		Transports:      []string{"internal", "hybrid"},
		AttestationType: "none",
		Aaguid:          "0132d110-bf6e-4d7f-ba8c-07e3f48f57f0",
		BackupEligible:  true,
		BackupState:     false,
	})
	if err != nil {
		t.Fatalf("Marshal webauthn meta 失败: %v", err)
	}
	pub1 := []byte{0xa5, 0x01, 0x02, 0x03, 0x04}
	c1 := &model.UserCredential{
		UserID: uid, Kind: "webauthn", Secret: []byte("cred-A"),
		Label: "MacBook Touch ID", Meta: waMeta,
	}
	w1 := &model.UserCredentialWebauthn{
		UserID: uid, Kind: "webauthn", PublicKey: pub1, CredentialID: "cred-A",
	}
	if err := wr.Create(ctx, c1, w1); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	// 主键同值口径（行 667-668）：webauthn 行 id 与 user_credential.id 一致。
	if c1.ID == 0 || w1.ID != c1.ID {
		t.Fatalf("主键同值: c1.ID=%d w1.ID=%d", c1.ID, w1.ID)
	}

	got, err := wr.FindByCredentialID(ctx, "cred-A")
	if err != nil {
		t.Fatalf("FindByCredentialID 失败: %v", err)
	}
	if got.ID != w1.ID || got.UserID != uid || got.Kind != "webauthn" ||
		!bytes.Equal(got.PublicKey, pub1) || got.SignCount != 0 {
		t.Errorf("FindByCredentialID 字段不一致: %+v", got)
	}

	// CredentialMeta webauthn 段 round-trip（接口文档 §12.2 行 1704-1709）。
	cRow, err := rp.FindByUserAndKind(ctx, uid, "webauthn")
	if err != nil {
		t.Fatalf("FindByUserAndKind(webauthn) 失败: %v", err)
	}
	mGot, err := UnmarshalCredentialMeta(cRow.Meta)
	if err != nil {
		t.Fatalf("Unmarshal webauthn meta 失败: %v", err)
	}
	if !slices.Equal(mGot.Transports, []string{"internal", "hybrid"}) ||
		mGot.AttestationType != "none" ||
		mGot.Aaguid != "0132d110-bf6e-4d7f-ba8c-07e3f48f57f0" ||
		!mGot.BackupEligible || mGot.BackupState {
		t.Errorf("webauthn meta round-trip 不一致: %+v", mGot)
	}

	// 第二个凭据：ListByUser 2 行、id DESC（新行在前）。
	c2 := &model.UserCredential{
		UserID: uid, Kind: "webauthn", Secret: []byte("cred-B"), Label: "iPhone",
	}
	w2 := &model.UserCredentialWebauthn{
		UserID: uid, Kind: "webauthn", PublicKey: []byte{0xa5, 0x05}, CredentialID: "cred-B",
	}
	if err := wr.Create(ctx, c2, w2); err != nil {
		t.Fatalf("Create 第二凭据失败: %v", err)
	}
	rows, err = wr.ListByUser(ctx, uid)
	if err != nil || len(rows) != 2 {
		t.Fatalf("ListByUser = %d 行, err %v; want 2/nil", len(rows), err)
	}
	if rows[0].ID != w2.ID || rows[1].ID != w1.ID {
		t.Errorf("ListByUser 应 id DESC 新行在前: %d,%d", rows[0].ID, rows[1].ID)
	}

	// 未命中。
	if _, err := wr.FindByCredentialID(ctx, "nope"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("未命中应 ErrRecordNotFound, got %v", err)
	}
}

// TestWebauthnRepoDuplicateRollback（env-skip）：uk_kind_credid（行 673）
// 冲突判别 ErrWebauthnDuplicate；失败的 Create 整事务回滚——两表都无
// 残留行（跨表事务关联），uk 命中仍是首行。
func TestWebauthnRepoDuplicateRollback(t *testing.T) {
	_, wr, db := credentialTestSetup(t)
	ctx := context.Background()
	const uid = int64(202)

	c1 := &model.UserCredential{UserID: uid, Kind: "webauthn", Secret: []byte("shared-id")}
	w1 := &model.UserCredentialWebauthn{
		UserID: uid, Kind: "webauthn", PublicKey: []byte{0x01}, CredentialID: "shared-id",
	}
	if err := wr.Create(ctx, c1, w1); err != nil {
		t.Fatalf("首个 Create 失败: %v", err)
	}

	// 同 (kind, credential_id) 的第二凭据 → uk 冲突可判别。
	c2 := &model.UserCredential{UserID: uid, Kind: "webauthn", Secret: []byte("shared-id-2")}
	w2 := &model.UserCredentialWebauthn{
		UserID: uid, Kind: "webauthn", PublicKey: []byte{0x02}, CredentialID: "shared-id",
	}
	if err := wr.Create(ctx, c2, w2); !errors.Is(err, ErrWebauthnDuplicate) {
		t.Fatalf("同 credential_id 应 ErrWebauthnDuplicate, got %v", err)
	}

	// 回滚零残留：user_credential 仍只首凭据一行、webauthn 仍只一行。
	var credRows int64
	if err := db.Model(&model.UserCredential{}).
		Where("user_id = ?", uid).
		Count(&credRows).Error; err != nil || credRows != 1 {
		t.Errorf("回滚后 user_credential = %d 行 err %v; want 1（无残留）", credRows, err)
	}
	rows, err := wr.ListByUser(ctx, uid)
	if err != nil || len(rows) != 1 {
		t.Fatalf("回滚后 webauthn = %d 行 err %v; want 1（无残留）", len(rows), err)
	}
	if rows[0].ID != w1.ID {
		t.Errorf("uk 命中应仍是首行: id=%d, want %d", rows[0].ID, w1.ID)
	}
}

// TestWebauthnRepoDelete（env-skip）：Delete 同事务删两行
// （user_credential_webauthn + user_credential，行 667 主键同值口径的镜像
// 方向）；uid 不匹配（凭据属他人 / 不存在）返回 ErrRecordNotFound 且两表
// 均无残留；成功后两行齐消失、他人行不受影响；重复删除可判别 not found。
func TestWebauthnRepoDelete(t *testing.T) {
	_, wr, db := credentialTestSetup(t)
	ctx := context.Background()
	const uid, other = int64(204), int64(205)

	// uid 两凭据 + other 一凭据。
	c1 := &model.UserCredential{UserID: uid, Kind: "webauthn", Secret: []byte("d1"), Label: "Mac"}
	w1 := &model.UserCredentialWebauthn{UserID: uid, Kind: "webauthn", PublicKey: []byte{0x01}, CredentialID: "d1"}
	if err := wr.Create(ctx, c1, w1); err != nil {
		t.Fatalf("Create 1 失败: %v", err)
	}
	c2 := &model.UserCredential{UserID: uid, Kind: "webauthn", Secret: []byte("d2"), Label: "iPhone"}
	w2 := &model.UserCredentialWebauthn{UserID: uid, Kind: "webauthn", PublicKey: []byte{0x02}, CredentialID: "d2"}
	if err := wr.Create(ctx, c2, w2); err != nil {
		t.Fatalf("Create 2 失败: %v", err)
	}
	co := &model.UserCredential{UserID: other, Kind: "webauthn", Secret: []byte("o1")}
	wo := &model.UserCredentialWebauthn{UserID: other, Kind: "webauthn", PublicKey: []byte{0x03}, CredentialID: "o1"}
	if err := wr.Create(ctx, co, wo); err != nil {
		t.Fatalf("Create other 失败: %v", err)
	}

	// uid 串号防御：用 other 的 uid 删 uid 的凭据 → not found，两行均保留。
	if err := wr.Delete(ctx, w1.ID, other); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("他人 uid 删除应 ErrRecordNotFound, got %v", err)
	}
	var n int64
	db.Model(&model.UserCredentialWebauthn{}).Where("id = ?", w1.ID).Count(&n)
	if n != 1 {
		t.Fatalf("串号删除后 webauthn 行 = %d, want 1（无残留删除）", n)
	}
	db.Model(&model.UserCredential{}).Where("id = ?", c1.ID).Count(&n)
	if n != 1 {
		t.Fatalf("串号删除后 credential 行 = %d, want 1（无残留删除）", n)
	}

	// 不存在的 id → not found。
	if err := wr.Delete(ctx, 999999, uid); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("不存在 id 应 ErrRecordNotFound, got %v", err)
	}

	// 成功删除 w1：两行齐消失。
	if err := wr.Delete(ctx, w1.ID, uid); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	db.Model(&model.UserCredentialWebauthn{}).Where("id = ?", w1.ID).Count(&n)
	if n != 0 {
		t.Fatalf("删除后 webauthn 行 = %d, want 0", n)
	}
	db.Model(&model.UserCredential{}).Where("id = ?", c1.ID).Count(&n)
	if n != 0 {
		t.Fatalf("删除后 credential 行 = %d, want 0（同事务两行）", n)
	}

	// 同 id 重复删除 → not found。
	if err := wr.Delete(ctx, w1.ID, uid); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("重复删除应 ErrRecordNotFound, got %v", err)
	}

	// 他人行 / 本人另一凭据不受影响。
	rows, err := wr.ListByUser(ctx, uid)
	if err != nil || len(rows) != 1 || rows[0].ID != w2.ID {
		t.Fatalf("uid 剩余 = %+v err %v; want 仅 w2", rows, err)
	}
	oRows, err := wr.ListByUser(ctx, other)
	if err != nil || len(oRows) != 1 || oRows[0].ID != wo.ID {
		t.Fatalf("other 剩余 = %+v err %v; want 不受影响", oRows, err)
	}
}

// TestWebauthnRepoUpdateSignCount（env-skip）：sign_count 单行 UPDATE
// （§8.3 行 1047 延迟队列 flush 的写路径）；同值重放幂等；行不存在可判别。
func TestWebauthnRepoUpdateSignCount(t *testing.T) {
	_, wr, _ := credentialTestSetup(t)
	ctx := context.Background()
	const uid = int64(203)

	c := &model.UserCredential{UserID: uid, Kind: "webauthn", Secret: []byte("sc")}
	w := &model.UserCredentialWebauthn{
		UserID: uid, Kind: "webauthn", PublicKey: []byte{0x03}, CredentialID: "sc-id",
	}
	if err := wr.Create(ctx, c, w); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}

	// 初始 sign_count=0（行 672 DDL 默认）。
	got, err := wr.FindByCredentialID(ctx, "sc-id")
	if err != nil {
		t.Fatalf("FindByCredentialID 失败: %v", err)
	}
	if got.SignCount != 0 {
		t.Fatalf("初始 sign_count = %d, want 0", got.SignCount)
	}

	// 递增落库：5 → 9。
	if err := wr.UpdateSignCount(ctx, w.ID, 5); err != nil {
		t.Fatalf("UpdateSignCount(5) 失败: %v", err)
	}
	if err := wr.UpdateSignCount(ctx, w.ID, 9); err != nil {
		t.Fatalf("UpdateSignCount(9) 失败: %v", err)
	}
	got, err = wr.FindByCredentialID(ctx, "sc-id")
	if err != nil {
		t.Fatalf("更新后读回失败: %v", err)
	}
	if got.SignCount != 9 {
		t.Errorf("sign_count = %d, want 9", got.SignCount)
	}

	// 同值重放（队列幂等）：changed-rows=0 但行在，不误报。
	if err := wr.UpdateSignCount(ctx, w.ID, 9); err != nil {
		t.Errorf("同值 UpdateSignCount 应幂等成功: %v", err)
	}
	// 行不存在可判别。
	if err := wr.UpdateSignCount(ctx, 404, 1); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("不存在行应 ErrRecordNotFound, got %v", err)
	}
}
