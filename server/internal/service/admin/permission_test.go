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
	listUID            int64
	calls              int
	retHas             bool
	retAny             bool
	retList            []string
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

func (f *fakePermissionStore) ListPermissions(ctx context.Context, uid int64) ([]string, error) {
	f.calls++
	f.listUID = uid
	if ctx == nil {
		panic("ctx must be forwarded")
	}
	return f.retList, f.err
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

func TestPermissionServiceListPermissions(t *testing.T) {
	ctx := context.Background()
	store := &fakePermissionStore{retList: []string{PointSuperAdmin}}
	svc := NewPermissionService(store)

	got, err := svc.ListPermissions(ctx, 5)
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	if len(got) != 1 || got[0] != PointSuperAdmin {
		t.Fatalf("ListPermissions = %v, want [%s]", got, PointSuperAdmin)
	}
	if store.listUID != 5 {
		t.Errorf("uid 透传 = %d, want 5", store.listUID)
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
	if got, err := svc.ListPermissions(ctx, 1); got != nil || !errors.Is(err, want) {
		t.Errorf("ListPermissions = (%v, %v), want (nil, db down)", got, err)
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

// fakeAdminsCache 登录签发侧集合读 / 回填 fake，记录回填调用并支持故障注入。
type fakeAdminsCache struct {
	member    bool
	memberErr error
	addErr    error
	addCalls  int
	addedUID  int64
}

func (f *fakeAdminsCache) IsMember(context.Context, int64) (bool, error) {
	return f.member, f.memberErr
}

func (f *fakeAdminsCache) Add(_ context.Context, uid int64) error {
	f.addCalls++
	f.addedUID = uid
	return f.addErr
}

// newProbe 构造签发探针，返回 DB 回源调用计数供断言（缓存命中时须为 0）。
func newProbe(admins *fakeAdminsCache, hasAny bool, dbErr error) (*IssuingPermissionProbe, *int) {
	calls := 0
	probe := NewIssuingPermissionProbe(admins, func(context.Context, int64) (bool, error) {
		calls++
		return hasAny, dbErr
	})
	return probe, &calls
}

func TestIssuingProbeCacheHit(t *testing.T) {
	admins := &fakeAdminsCache{member: true}
	probe, calls := newProbe(admins, false, nil)

	got, err := probe.Probe(context.Background(), 1)
	if err != nil || !got {
		t.Fatalf("Probe = (%v, %v), want (true, nil)", got, err)
	}
	if *calls != 0 {
		t.Errorf("命中时回源调用 = %d, want 0", *calls)
	}
	if admins.addCalls != 0 {
		t.Errorf("命中时回填调用 = %d, want 0", admins.addCalls)
	}
}

func TestIssuingProbeMissFallsBackToDB(t *testing.T) {
	cases := []struct {
		name      string
		memberErr error
		dbHas     bool
		want      bool
		wantAdd   int
	}{
		{"miss 回源 true 回填", nil, true, true, 1},
		{"miss 回源 false 不回填", nil, false, false, 0},
		{"Redis 故障回源 true", errors.New("redis down"), true, true, 1},
		{"Redis 故障回源 false", errors.New("redis down"), false, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			admins := &fakeAdminsCache{memberErr: tc.memberErr}
			probe, calls := newProbe(admins, tc.dbHas, nil)

			got, err := probe.Probe(context.Background(), 42)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Probe = %v, want %v", got, tc.want)
			}
			if *calls != 1 {
				t.Errorf("回源调用 = %d, want 1", *calls)
			}
			if admins.addCalls != tc.wantAdd {
				t.Errorf("回填调用 = %d, want %d", admins.addCalls, tc.wantAdd)
			}
			if tc.wantAdd > 0 && admins.addedUID != 42 {
				t.Errorf("回填 uid = %d, want 42", admins.addedUID)
			}
		})
	}
}

func TestIssuingProbeBackfillErrorIgnored(t *testing.T) {
	admins := &fakeAdminsCache{addErr: errors.New("sadd failed")}
	probe, _ := newProbe(admins, true, nil)

	got, err := probe.Probe(context.Background(), 1)
	if err != nil || !got {
		t.Fatalf("Probe = (%v, %v), want (true, nil)（回填失败仅忽略）", got, err)
	}
}

func TestIssuingProbeDBErrorPropagates(t *testing.T) {
	want := errors.New("db down")
	probe, _ := newProbe(&fakeAdminsCache{}, false, want)

	got, err := probe.Probe(context.Background(), 1)
	if got || !errors.Is(err, want) {
		t.Fatalf("Probe = (%v, %v), want (false, db down)", got, err)
	}
}

func TestNewIssuingProbeNilDependencyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("nil 依赖应 fail-fast panic")
		}
	}()
	NewIssuingPermissionProbe(nil, func(context.Context, int64) (bool, error) { return false, nil })
}
