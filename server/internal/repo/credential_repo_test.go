// credential / webauthn 表 repo 层测试：真实 MariaDB 测试实例经
// UC_TEST_MYSQL_DSN env 注入，无 env 时 skip。表结构由 migrate.Up 建
//（§3.16 DDL 唯一来源）；用例开始 drop 全表、结束 drop 全表 +
// assertNoTables 自证零残留（口径同 user_repo_test）。跨二进制互斥
// 由 settings_repo_test.go 的 TestMain（GET_LOCK uc_test_db_slot）保证；
// 共享辅助 dropAllTables / assertNoTables / dbTestConfig 在彼处与
// db_test.go。连接串只经环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/gen/go/credential"
	"authloft/internal/migrate"
	"authloft/internal/repo/model"
)

// credentialTestSetup 清库 + 建表 + 注册测后零残留清理，返回就绪的
// CredentialRepo 与 WebauthnRepo（同一连接 *gorm.DB 供跨表事务断言
// 直接查行）。
func credentialTestSetup(t *testing.T) (*CredentialRepo, *WebauthnRepo, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 credential repo 集成用例")
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
	return NewCredentialRepo(db), NewWebauthnRepo(db), db
}

// TestCredentialRepoKindRows（env-skip）：kind 行隔离——同 user 多 kind
// 各一行、secret 按行存取不串；CredentialMeta 经 meta 列 round-trip
//（totp 段 / recovery_code 段 / NULL 列空 meta）；改密 Update（§4.2 行
// 681 = UPDATE 这一行）全列落库 + 同值重放幂等；SetEnabled 切换 + 同值
// 幂等；未命中与不存在行均可判别。
func TestCredentialRepoKindRows(t *testing.T) {
	rp, _, _ := credentialTestSetup(t)
	ctx := context.Background()
	const uid = int64(101)

	// 封装口径先行（不涉库）：nil meta → nil 字节；NULL / 空列 → 空
	// meta（非 nil，调用方免判空）。
	b, err := MarshalCredentialMeta(nil)
	if err != nil || b != nil {
		t.Fatalf("Marshal(nil) = %v, err %v; want nil, nil", b, err)
	}
	if m, err := UnmarshalCredentialMeta(nil); err != nil || m == nil {
		t.Fatalf("Unmarshal(nil) = %v, err %v; want 空 meta 非 nil", m, err)
	}

	// kind 行隔离（行 680-684）：password / totp / recovery_code 各一行，
	// secret 拿到什么存什么（password=argon2id 串、totp=Base32，行
	// 681-682，repo 不校验）。
	pwSecret := []byte("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$c2hhcmVk")
	pw := &model.UserCredential{UserID: uid, Kind: "password", Secret: pwSecret}
	if err := rp.Create(ctx, pw); err != nil {
		t.Fatalf("Create password 失败: %v", err)
	}
	if pw.ID == 0 || pw.CreatedAt.IsZero() || pw.UpdatedAt.IsZero() {
		t.Fatal("Create 后应回填 ID / created_at / updated_at")
	}

	totpSecret := []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	totpMeta, err := MarshalCredentialMeta(&credential.CredentialMeta{TotpDigits: 6, TotpPeriod: 30})
	if err != nil {
		t.Fatalf("Marshal totp meta 失败: %v", err)
	}
	totp := &model.UserCredential{UserID: uid, Kind: "totp", Secret: totpSecret, Meta: totpMeta}
	if err := rp.Create(ctx, totp); err != nil {
		t.Fatalf("Create totp 失败: %v", err)
	}

	codes := make([]string, 10)
	for i := range codes {
		codes[i] = fmt.Sprintf("abcd%04d", i)
	}
	rcMeta, err := MarshalCredentialMeta(&credential.CredentialMeta{RecoveryCodes: codes})
	if err != nil {
		t.Fatalf("Marshal recovery meta 失败: %v", err)
	}
	rc := &model.UserCredential{UserID: uid, Kind: "recovery_code", Secret: []byte{}, Meta: rcMeta}
	if err := rp.Create(ctx, rc); err != nil {
		t.Fatalf("Create recovery_code 失败: %v", err)
	}

	// password 行读回：secret 一致，默认 label='' / is_enabled=1 /
	// meta NULL / last_used_at NULL（行 656-659 DDL 默认）。
	gotPw, err := rp.FindByUserAndKind(ctx, uid, "password")
	if err != nil {
		t.Fatalf("FindByUserAndKind(password) 失败: %v", err)
	}
	if !bytes.Equal(gotPw.Secret, pwSecret) || gotPw.Label != "" ||
		gotPw.IsEnabled != 1 || gotPw.Meta != nil {
		t.Errorf("password 行字段不一致: %+v", gotPw)
	}
	if gotPw.LastUsedAt != nil {
		t.Errorf("last_used_at 初始应为 NULL: %v", gotPw.LastUsedAt)
	}

	// totp 行读回：secret 不串行 + meta round-trip。
	gotTotp, err := rp.FindByUserAndKind(ctx, uid, "totp")
	if err != nil {
		t.Fatalf("FindByUserAndKind(totp) 失败: %v", err)
	}
	if !bytes.Equal(gotTotp.Secret, totpSecret) {
		t.Errorf("totp secret 串行: %s", gotTotp.Secret)
	}
	totpGot, err := UnmarshalCredentialMeta(gotTotp.Meta)
	if err != nil {
		t.Fatalf("Unmarshal totp meta 失败: %v", err)
	}
	if totpGot.TotpDigits != 6 || totpGot.TotpPeriod != 30 || len(totpGot.RecoveryCodes) != 0 {
		t.Errorf("totp meta round-trip 不一致: %+v", totpGot)
	}

	// recovery_code 行读回：10 个恢复码明文 round-trip（行 684、接口文档 §12.2）。
	gotRc, err := rp.FindByUserAndKind(ctx, uid, "recovery_code")
	if err != nil {
		t.Fatalf("FindByUserAndKind(recovery_code) 失败: %v", err)
	}
	rcGot, err := UnmarshalCredentialMeta(gotRc.Meta)
	if err != nil {
		t.Fatalf("Unmarshal recovery meta 失败: %v", err)
	}
	if !slices.Equal(rcGot.RecoveryCodes, codes) {
		t.Errorf("recovery_codes round-trip 不一致: %v", rcGot.RecoveryCodes)
	}

	// 未命中：该 user 无 webauthn kind 行。
	if _, err := rp.FindByUserAndKind(ctx, uid, "webauthn"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("未命中应 ErrRecordNotFound, got %v", err)
	}

	// 改密 = UPDATE 这一行（行 681）：secret / label 更新，meta 保持
	// NULL，归属列（kind / user_id）不动。
	newPw := []byte("$argon2id$v=19$m=65536,t=3,p=4$bmV3c2FsdA$bmV3c2hhcmVk")
	upd := &model.UserCredential{
		ID: gotPw.ID, Secret: newPw, Label: "主密码",
		Meta: nil, IsEnabled: 1, UpdatedAt: time.Now().Truncate(time.Second),
	}
	if err := rp.Update(ctx, upd); err != nil {
		t.Fatalf("改密 Update 失败: %v", err)
	}
	gotPw2, err := rp.FindByUserAndKind(ctx, uid, "password")
	if err != nil {
		t.Fatalf("改密后读回失败: %v", err)
	}
	if !bytes.Equal(gotPw2.Secret, newPw) || gotPw2.Label != "主密码" ||
		gotPw2.Meta != nil || gotPw2.Kind != "password" || gotPw2.UserID != uid {
		t.Errorf("改密后字段不一致: %+v", gotPw2)
	}
	// 同值重放幂等（changed-rows=0 但行仍在，不误报）。
	if err := rp.Update(ctx, upd); err != nil {
		t.Errorf("同值 Update 应幂等成功: %v", err)
	}
	// 不存在行可判别。
	if err := rp.Update(ctx, &model.UserCredential{ID: 404, Secret: newPw, UpdatedAt: time.Now()}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("Update 不存在行应 ErrRecordNotFound, got %v", err)
	}

	// 启用态切换（行 658）+ 同值幂等。
	if err := rp.SetEnabled(ctx, gotPw.ID, false); err != nil {
		t.Fatalf("SetEnabled(false) 失败: %v", err)
	}
	if err := rp.SetEnabled(ctx, gotPw.ID, false); err != nil {
		t.Errorf("同值 SetEnabled 应幂等成功: %v", err)
	}
	gotPw3, err := rp.FindByUserAndKind(ctx, uid, "password")
	if err != nil {
		t.Fatalf("停用后读回失败: %v", err)
	}
	if gotPw3.IsEnabled != 0 {
		t.Errorf("is_enabled = %d, want 0", gotPw3.IsEnabled)
	}
	if err := rp.SetEnabled(ctx, gotPw.ID, true); err != nil {
		t.Fatalf("SetEnabled(true) 失败: %v", err)
	}
	if gotPw3, err = rp.FindByUserAndKind(ctx, uid, "password"); err != nil || gotPw3.IsEnabled != 1 {
		t.Errorf("is_enabled = %d, err %v; want 1", gotPw3.IsEnabled, err)
	}
	if err := rp.SetEnabled(ctx, 404, true); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("SetEnabled 不存在行应 ErrRecordNotFound, got %v", err)
	}
}
