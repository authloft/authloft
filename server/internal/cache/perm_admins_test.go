package cache

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// fakePermAdminsRedis 内存 SET fake（实现 permAdminsRedis 窄接口），记录
// 命令调用次数并支持故障注入。
type fakePermAdminsRedis struct {
	sets      map[string]map[string]bool
	delCalls  int
	sAddCalls int
	sIsCalls  int
	lastSAdd  []interface{}
	delErr    error
	sAddErr   error
	sIsErr    error
}

func newFakePermAdminsRedis() *fakePermAdminsRedis {
	return &fakePermAdminsRedis{sets: map[string]map[string]bool{}}
}

func memberKey(v interface{}) string { return fmt.Sprint(v) }

func (f *fakePermAdminsRedis) SIsMember(ctx context.Context, key string, member interface{}) BoolResult {
	f.sIsCalls++
	if f.sIsErr != nil {
		return NewBoolResult(false, f.sIsErr)
	}
	return NewBoolResult(f.sets[key][memberKey(member)], nil)
}

func (f *fakePermAdminsRedis) SAdd(ctx context.Context, key string, members ...interface{}) IntResult {
	f.sAddCalls++
	f.lastSAdd = members
	if f.sAddErr != nil {
		return NewIntResult(0, f.sAddErr)
	}
	if f.sets[key] == nil {
		f.sets[key] = map[string]bool{}
	}
	for _, m := range members {
		f.sets[key][memberKey(m)] = true
	}
	return NewIntResult(int64(len(members)), nil)
}

func (f *fakePermAdminsRedis) Del(ctx context.Context, keys ...string) IntResult {
	f.delCalls++
	if f.delErr != nil {
		return NewIntResult(0, f.delErr)
	}
	for _, k := range keys {
		delete(f.sets, k)
	}
	return NewIntResult(int64(len(keys)), nil)
}

func TestPermissionAdminsKey(t *testing.T) {
	if got := PermissionAdminsKey(); got != "al:perm:admins" {
		t.Fatalf("PermissionAdminsKey = %q, want al:perm:admins", got)
	}
}

func TestPermissionAdminsRebuild(t *testing.T) {
	ctx := context.Background()
	rdb := newFakePermAdminsRedis()
	store := NewPermissionAdminsStore(rdb)

	if err := store.Rebuild(ctx, []int64{1, 2, 3}); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if rdb.delCalls != 1 || rdb.sAddCalls != 1 {
		t.Fatalf("DEL/SADD 调用 = %d/%d, want 1/1", rdb.delCalls, rdb.sAddCalls)
	}
	if len(rdb.sets[PermissionAdminsKey()]) != 3 {
		t.Fatalf("集合成员数 = %d, want 3", len(rdb.sets[PermissionAdminsKey()]))
	}

	// 二次预热须先清旧集合再重建，不残留上一生命周期成员。
	if err := store.Rebuild(ctx, []int64{9}); err != nil {
		t.Fatalf("Rebuild again: %v", err)
	}
	if got := rdb.sets[PermissionAdminsKey()]; len(got) != 1 || !got[memberKey(int64(9))] {
		t.Fatalf("二次预热后集合 = %v, want 仅 {9}", got)
	}

	// 空集合只 DEL、不 SADD。
	before := rdb.sAddCalls
	if err := store.Rebuild(ctx, nil); err != nil {
		t.Fatalf("Rebuild empty: %v", err)
	}
	if rdb.sAddCalls != before {
		t.Fatalf("空集合仍调用 SADD = %d, want %d", rdb.sAddCalls, before)
	}
}

func TestPermissionAdminsIsMemberAndAdd(t *testing.T) {
	ctx := context.Background()
	rdb := newFakePermAdminsRedis()
	store := NewPermissionAdminsStore(rdb)

	if hit, err := store.IsMember(ctx, 7); err != nil || hit {
		t.Fatalf("IsMember(空集合) = (%v, %v), want (false, nil)", hit, err)
	}
	if err := store.Add(ctx, 7); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if hit, err := store.IsMember(ctx, 7); err != nil || !hit {
		t.Fatalf("IsMember(回填后) = (%v, %v), want (true, nil)", hit, err)
	}
}

func TestPermissionAdminsRedisErrorPropagates(t *testing.T) {
	ctx := context.Background()
	rdb := newFakePermAdminsRedis()
	store := NewPermissionAdminsStore(rdb)

	rdb.sIsErr = errors.New("redis down")
	if _, err := store.IsMember(ctx, 1); err == nil {
		t.Fatal("IsMember 故障应原样上抛")
	}
	rdb.sIsErr = nil
	rdb.delErr = errors.New("redis down")
	if err := store.Rebuild(ctx, []int64{1}); err == nil {
		t.Fatal("Rebuild DEL 故障应原样上抛")
	}
}
