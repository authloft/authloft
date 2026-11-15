// 用 fake 隔离依赖，重点验证 ctx 与参数透传、错误不被吞掉。
package admin

import (
	"context"
	"errors"
	"testing"
)

// fakePermissionStore 记录调用以便断言透传。
type fakePermissionStore struct {
	hasPermissionUID   int64
	hasPermissionPoint string
	hasAnyUID          int64
	calls              int
	retHas             bool
	retAny             bool
	err                error
}

func (f *fakePermissionStore) HasPermission(ctx context.Context, uid int64, point string) (bool, error) {
	f.calls++
	f.hasPermissionUID = uid
	f.hasPermissionPoint = point
	if ctx == nil {
		panic("ctx must be forwarded")
	}
	return f.retHas, f.err
}

func (f *fakePermissionStore) HasAnyPermission(ctx context.Context, uid int64) (bool, error) {
	f.calls++
	f.hasAnyUID = uid
	if ctx == nil {
		panic("ctx must be forwarded")
	}
	return f.retAny, f.err
}

func TestPermissionServiceDelegates(t *testing.T) {
	ctx := context.Background()
	store := &fakePermissionStore{retHas: true, retAny: true}
	svc := NewPermissionService(store)

	if ok, err := svc.HasPermission(ctx, 7, PointSuperAdmin); err != nil || !ok {
		t.Fatalf("HasPermission = (%v, %v), want (true, nil)", ok, err)
	}
	if store.hasPermissionUID != 7 || store.hasPermissionPoint != PointSuperAdmin {
		t.Errorf("HasPermission 参数透传 = (%d, %q), want (7, %q)", store.hasPermissionUID, store.hasPermissionPoint, PointSuperAdmin)
	}
	if ok, err := svc.HasAnyPermission(ctx, 9); err != nil || !ok {
		t.Fatalf("HasAnyPermission = (%v, %v), want (true, nil)", ok, err)
	}
	if store.hasAnyUID != 9 {
		t.Errorf("HasAnyPermission uid 透传 = %d, want 9", store.hasAnyUID)
	}
	if store.calls != 2 {
		t.Errorf("store 调用次数 = %d, want 2", store.calls)
	}
}

func TestPermissionServicePropagatesError(t *testing.T) {
	want := errors.New("db down")
	svc := NewPermissionService(&fakePermissionStore{err: want})
	ctx := context.Background()
	if ok, err := svc.HasPermission(ctx, 1, PointSuperAdmin); ok || !errors.Is(err, want) {
		t.Errorf("HasPermission = (%v, %v), want (false, db down)", ok, err)
	}
	if ok, err := svc.HasAnyPermission(ctx, 1); ok || !errors.Is(err, want) {
		t.Errorf("HasAnyPermission = (%v, %v), want (false, db down)", ok, err)
	}
}

func TestPermissionServiceNilStorePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewPermissionService(nil) 应 fail-fast panic")
		}
	}()
	NewPermissionService(nil)
}
