// profile_test.go account 域资料更新 service 层单测（不连 DB，
// ProfileStore 全 fake 注入；proto3 optional 三态语义〔has 位区分「未设置
// = 不修改」与「显式设值 = 覆盖」〕的合并细节由 dto.MergeUserProfile 承载
// 并经 rpc 域 TestUpdateUserProfileOptionalSemantics 端到端覆盖，此处测
// ProfileService 编排：写库形态〔列级 / 整行〕、no-op、存在性先判、
// birthday 非法拒绝、现行行缺失从零值行起）。
package account

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/internal/repo/model"
)

// strPtr proto3 optional 字符串字段（has 位口径）取地址助手。
func strPtr(s string) *string { return &s }

// fakeProfileStore ProfileStore 的 fake：行集回放 + 入参记录 + 错误注入。
type fakeProfileStore struct {
	user    *model.User
	profile *model.UserProfile

	findErr    error
	getErr     error
	getMissing bool // true 时 GetProfile 回放包装 ErrRecordNotFound

	columnCalls []columnCall
	columnErr   error
	saveCalls   []*model.UserProfile
	saveErr     error
}

type columnCall struct {
	id        int64
	nickname  *string
	avatarURL *string
}

func (f *fakeProfileStore) FindByID(_ context.Context, _ int64) (*model.User, error) {
	return f.user, f.findErr
}

func (f *fakeProfileStore) GetProfile(_ context.Context, _ int64) (*model.UserProfile, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getMissing || f.profile == nil {
		return nil, fmt.Errorf("user repo: get profile: %w", gorm.ErrRecordNotFound)
	}
	return f.profile, nil
}

func (f *fakeProfileStore) UpdateProfileColumns(_ context.Context, id int64, nickname, avatarURL *string) error {
	f.columnCalls = append(f.columnCalls, columnCall{id: id, nickname: nickname, avatarURL: avatarURL})
	return f.columnErr
}

func (f *fakeProfileStore) SaveProfile(_ context.Context, p *model.UserProfile) error {
	f.saveCalls = append(f.saveCalls, p)
	return f.saveErr
}

// profileTestUser / profileTestRow 数据样例（§3.1 行 779-797 子集）。
func profileTestUser() *model.User {
	return &model.User{ID: 10086, Username: "zhang_san", Nickname: "张三"}
}

func profileTestRow() *model.UserProfile {
	birthday := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	return &model.UserProfile{
		UserID: 10086, Gender: 1, Birthday: &birthday,
		Locale: "zh-CN", Timezone: "Asia/Shanghai",
		Extra: []byte{0x81, 0xa7, 'c', 'o', 'm', 'p', 'a', 'n', 'y', 0xa4, 'A', 'c', 'm', 'e'},
	}
}

// TestProfileUpdateAllFields 全字段 has：列级更新恰一次（nickname 空串 =
// 显式清空同样写入）+ 整行 UPSERT 恰一次（profile 各子字段按 has 合并——
// gender 显式 0 覆盖 1、birthday 显式空串清空、locale / timezone 显式值
// 生效、extra 显式 Struct 覆盖原字节）。
func TestProfileUpdateAllFields(t *testing.T) {
	store := &fakeProfileStore{user: profileTestUser(), profile: profileTestRow()}
	svc := NewProfileService(store)

	extra, err := structpb.NewStruct(map[string]interface{}{"level": "vip"})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	gender := int64(0)
	if err := svc.UpdateProfile(context.Background(), 10086, &accountv1.UpdateProfileRequest{
		Nickname:  strPtr(""),
		AvatarUrl: strPtr("https://cdn.example.com/b.jpg"),
		Profile: &accountv1.UserProfile{
			Gender:   &gender,
			Birthday: strPtr(""),
			Locale:   strPtr("en-US"),
			Timezone: strPtr("Asia/Tokyo"),
			Extra:    extra,
		},
	}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}

	if n := len(store.columnCalls); n != 1 {
		t.Fatalf("UpdateProfileColumns calls = %d, want 1", n)
	}
	cu := store.columnCalls[0]
	if cu.id != 10086 || cu.nickname == nil || *cu.nickname != "" {
		t.Errorf("column update = (id=%d nickname=%v), want (10086, 显式空串)", cu.id, cu.nickname)
	}
	if cu.avatarURL == nil || *cu.avatarURL != "https://cdn.example.com/b.jpg" {
		t.Errorf("column avatarURL = %v, want 显式设值", cu.avatarURL)
	}

	if n := len(store.saveCalls); n != 1 {
		t.Fatalf("SaveProfile calls = %d, want 1", n)
	}
	saved := store.saveCalls[0]
	if saved.UserID != 10086 || saved.Gender != 0 || saved.Birthday != nil ||
		saved.Locale != "en-US" || saved.Timezone != "Asia/Tokyo" {
		t.Errorf("saved = (uid=%d gender=%d birthday=%v locale=%q timezone=%q), want has 位全覆盖",
			saved.UserID, saved.Gender, saved.Birthday, saved.Locale, saved.Timezone)
	}
	if string(saved.Extra) == string(profileTestRow().Extra) {
		t.Error("extra = 原字节, want 显式 Struct 覆盖")
	}
	if saved.UpdatedAt.IsZero() {
		t.Error("updated_at 未刷新（changed 路径应刷）")
	}
}

// TestProfileUpdatePartialColumnsOnly 仅 user 表列 has（profile 未传）：
// 恰一次列级更新、零整行 UPSERT（profile 消息 nil = 不触碰 user_profile 行）。
func TestProfileUpdatePartialColumnsOnly(t *testing.T) {
	store := &fakeProfileStore{user: profileTestUser(), profile: profileTestRow()}
	svc := NewProfileService(store)

	if err := svc.UpdateProfile(context.Background(), 10086, &accountv1.UpdateProfileRequest{
		Nickname: strPtr("李四"),
	}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if n := len(store.columnCalls); n != 1 {
		t.Fatalf("UpdateProfileColumns calls = %d, want 1", n)
	}
	cu := store.columnCalls[0]
	if cu.nickname == nil || *cu.nickname != "李四" || cu.avatarURL != nil {
		t.Errorf("column update = (nickname=%v avatarURL=%v), want (李四, nil)", cu.nickname, cu.avatarURL)
	}
	if n := len(store.saveCalls); n != 0 {
		t.Errorf("SaveProfile calls = %d, want 0（profile 未传）", n)
	}
}

// TestProfileUpdateProfileOnly 仅 profile has：零列级更新、恰一次整行
// UPSERT；未设置子字段保留现行值。
func TestProfileUpdateProfileOnly(t *testing.T) {
	store := &fakeProfileStore{user: profileTestUser(), profile: profileTestRow()}
	svc := NewProfileService(store)

	if err := svc.UpdateProfile(context.Background(), 10086, &accountv1.UpdateProfileRequest{
		Profile: &accountv1.UserProfile{Timezone: strPtr("Asia/Tokyo")},
	}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if n := len(store.columnCalls); n != 0 {
		t.Errorf("UpdateProfileColumns calls = %d, want 0（user 列未传）", n)
	}
	if n := len(store.saveCalls); n != 1 {
		t.Fatalf("SaveProfile calls = %d, want 1", n)
	}
	saved := store.saveCalls[0]
	if saved.Timezone != "Asia/Tokyo" {
		t.Errorf("timezone = %q, want Asia/Tokyo（has 生效）", saved.Timezone)
	}
	if saved.Gender != 1 || saved.Locale != "zh-CN" || saved.Birthday == nil {
		t.Errorf("未设置子字段被覆盖: gender=%d locale=%q birthday=%v", saved.Gender, saved.Locale, saved.Birthday)
	}
}

// TestProfileUpdateNoop 全字段未设置（空 body）= 合法空操作：存在性先判
// 依旧执行（404 优先于 no-op，口径同 rpc 域），此后零写库、零错误
//（§3.2 无明确空 body 口径时由实现裁量：无字段 has → 零写库直接成功）。
func TestProfileUpdateNoop(t *testing.T) {
	store := &fakeProfileStore{user: profileTestUser(), profile: profileTestRow()}
	svc := NewProfileService(store)

	for name, req := range map[string]*accountv1.UpdateProfileRequest{
		"empty body":     {},
		"empty profile":  {Profile: &accountv1.UserProfile{}},
		"nil sub-fields": {Nickname: nil, AvatarUrl: nil, Profile: nil},
	} {
		if err := svc.UpdateProfile(context.Background(), 10086, req); err != nil {
			t.Fatalf("%s: UpdateProfile: %v", name, err)
		}
	}
	if n := len(store.columnCalls); n != 0 {
		t.Errorf("UpdateProfileColumns calls = %d, want 0（no-op 零写库）", n)
	}
	if n := len(store.saveCalls); n != 0 {
		t.Errorf("SaveProfile calls = %d, want 0（no-op 零写库）", n)
	}
}

// TestProfileUpdateUserNotFound user 行不存在 → gorm.ErrRecordNotFound
// 包装透传（handler 转 not_found），零写库。
func TestProfileUpdateUserNotFound(t *testing.T) {
	store := &fakeProfileStore{findErr: fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)}
	svc := NewProfileService(store)

	err := svc.UpdateProfile(context.Background(), 404, &accountv1.UpdateProfileRequest{Nickname: strPtr("x")})
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("err = %v, want gorm.ErrRecordNotFound 透传", err)
	}
	if n := len(store.columnCalls); n != 0 {
		t.Errorf("UpdateProfileColumns calls = %d, want 0", n)
	}
	if n := len(store.saveCalls); n != 0 {
		t.Errorf("SaveProfile calls = %d, want 0", n)
	}
}

// TestProfileUpdateBadBirthday birthday 格式非法 → ErrProfileInvalidRequest
//（handler 转 invalid_argument + ErrorInfo(account, invalid_request)）、
// 零写库。
func TestProfileUpdateBadBirthday(t *testing.T) {
	store := &fakeProfileStore{user: profileTestUser(), profile: profileTestRow()}
	svc := NewProfileService(store)

	err := svc.UpdateProfile(context.Background(), 10086, &accountv1.UpdateProfileRequest{
		Profile: &accountv1.UserProfile{Birthday: strPtr("1990/01/01")},
	})
	if !errors.Is(err, ErrProfileInvalidRequest) {
		t.Fatalf("err = %v, want ErrProfileInvalidRequest", err)
	}
	if n := len(store.saveCalls); n != 0 {
		t.Errorf("SaveProfile calls = %d, want 0（非法入参不落库）", n)
	}
}

// TestProfileUpdateRowMissing 现行 user_profile 行缺失（GetProfile 回
// ErrRecordNotFound）→ 从零值行起合并（UserID 补 uid），SaveProfile 建行；
// has 子字段生效、未设置子字段保持零值。
func TestProfileUpdateRowMissing(t *testing.T) {
	store := &fakeProfileStore{user: profileTestUser(), getMissing: true}
	svc := NewProfileService(store)

	gender := int64(2)
	if err := svc.UpdateProfile(context.Background(), 10086, &accountv1.UpdateProfileRequest{
		Profile: &accountv1.UserProfile{Gender: &gender},
	}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if n := len(store.saveCalls); n != 1 {
		t.Fatalf("SaveProfile calls = %d, want 1（行缺失建行）", n)
	}
	saved := store.saveCalls[0]
	if saved.UserID != 10086 || saved.Gender != 2 {
		t.Errorf("saved = (uid=%d gender=%d), want (10086, 2)", saved.UserID, saved.Gender)
	}
	if saved.Birthday != nil || saved.Locale != "" || saved.Timezone != "" {
		t.Errorf("零值行起点的未设置字段非零: birthday=%v locale=%q timezone=%q", saved.Birthday, saved.Locale, saved.Timezone)
	}
}
