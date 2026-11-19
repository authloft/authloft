package partition

import (
	"reflect"
	"testing"
	"time"
)

// mustDate 测试辅助：ISO 日期字面量转零点时刻，输入写错直接 panic 暴露。
func mustDate(s string) time.Time {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return d
}

// named 构造规范命名的实体分区视图。
func named(name, upper string) Partition {
	return Partition{Name: name, Upper: mustDate(upper)}
}

func TestPlanCreate(t *testing.T) {
	// 每个用例：输入（分区视图 / today / N）→ 期望的切分结论。
	cases := []struct {
		name      string
		parts     []Partition
		today     time.Time
		n         int
		wantCut   bool
		wantPlan  Partition
		wantStart time.Time
	}{
		{
			// 尚无实体分区：首切自今天起算，下界为零值（PG 侧译为 MINVALUE）。
			name:      "no entity partitions cuts first",
			parts:     nil,
			today:     mustDate("2026-11-20"),
			n:         7,
			wantCut:   true,
			wantPlan:  named("p20261127", "2026-11-27"),
			wantStart: time.Time{},
		},
		{
			// 最后一个分区还覆盖得住今天：不切。
			name:    "covered by last upper no cut",
			parts:   []Partition{named("p20261125", "2026-11-25")},
			today:   mustDate("2026-11-20"),
			n:       7,
			wantCut: false,
		},
		{
			// today == 上界：RANGE 上界含即落兜底，必须切；下界 = 既有上界。
			name:      "today equals upper cuts",
			parts:     []Partition{named("p20261125", "2026-11-25")},
			today:     mustDate("2026-11-25"),
			n:         7,
			wantCut:   true,
			wantPlan:  named("p20261202", "2026-12-02"),
			wantStart: mustDate("2026-11-25"),
		},
		{
			// today 已越过上界：新分区自既有上界起、跨度大于间隔天数，
			// 兜底积压一次性分流。
			name:      "today past upper widens span",
			parts:     []Partition{named("p20261101", "2026-11-01")},
			today:     mustDate("2026-11-20"),
			n:         7,
			wantCut:   true,
			wantPlan:  named("p20261127", "2026-11-27"),
			wantStart: mustDate("2026-11-01"),
		},
		{
			// 多个分区取最大上界为 U。
			name: "upper is max over partitions",
			parts: []Partition{
				named("p20261101", "2026-11-01"),
				named("p20261115", "2026-11-15"),
			},
			today:     mustDate("2026-11-21"),
			n:         1,
			wantCut:   true,
			wantPlan:  named("p20261122", "2026-11-22"),
			wantStart: mustDate("2026-11-15"),
		},
		{
			// 计划名已存在则不再切（输入不一致的防御场景：名字存在但上界
			// 早于 today，正常枚举不会产出这种组合）。
			name:    "planned name exists no recut",
			parts:   []Partition{named("p20261127", "2026-11-01")},
			today:   mustDate("2026-11-20"),
			n:       7,
			wantCut: false,
		},
		{
			// N 钳制下界：0 → 1 天。
			name:      "interval clamped to minimum",
			parts:     nil,
			today:     mustDate("2026-11-20"),
			n:         0,
			wantCut:   true,
			wantPlan:  named("p20261121", "2026-11-21"),
			wantStart: time.Time{},
		},
		{
			// N 钳制上界：1000 → 365 天。
			name:      "interval clamped to maximum",
			parts:     nil,
			today:     mustDate("2026-11-20"),
			n:         1000,
			wantCut:   true,
			wantPlan:  named("p20271120", "2027-11-20"),
			wantStart: time.Time{},
		},
		{
			// today 只取墙钟日期，时钟部分不参与决策。
			name:      "today clock part ignored",
			parts:     nil,
			today:     time.Date(2026, 11, 20, 23, 59, 59, 0, time.UTC),
			n:         7,
			wantCut:   true,
			wantPlan:  named("p20261127", "2026-11-27"),
			wantStart: time.Time{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, start, cut := PlanCreate(tc.parts, tc.today, tc.n)
			if cut != tc.wantCut {
				t.Fatalf("cut = %v, want %v", cut, tc.wantCut)
			}
			if !tc.wantCut {
				return
			}
			if plan.Name != tc.wantPlan.Name {
				t.Errorf("plan name = %q, want %q", plan.Name, tc.wantPlan.Name)
			}
			if !plan.Upper.Equal(tc.wantPlan.Upper) {
				t.Errorf("plan upper = %s, want %s", plan.Upper, tc.wantPlan.Upper)
			}
			if !start.Equal(tc.wantStart) {
				t.Errorf("start = %s, want %s", start, tc.wantStart)
			}
		})
	}
}

func TestPlanDrop(t *testing.T) {
	// 五个连续分区（上界 11-01 / 08 / 15 / 22 / 29），各用例按序引用。
	five := func() []Partition {
		return []Partition{
			named("p20261101", "2026-11-01"),
			named("p20261108", "2026-11-08"),
			named("p20261115", "2026-11-15"),
			named("p20261122", "2026-11-22"),
			named("p20261129", "2026-11-29"),
		}
	}
	cases := []struct {
		name    string
		parts   []Partition
		x       int
		wantNil bool
		want    []string
	}{
		{
			name:    "under quota no drop",
			parts:   five(),
			x:       5,
			wantNil: true,
		},
		{
			name:    "at quota no drop",
			parts:   five(),
			x:       5,
			wantNil: true,
		},
		{
			name:  "drops oldest in ascending order",
			parts: five(),
			x:     3,
			want:  []string{"p20261101", "p20261108"},
		},
		{
			// 输入顺序不影响淘汰对象：按上界日期排序而非出现顺序。
			name: "input order irrelevant",
			parts: []Partition{
				named("p20261129", "2026-11-29"),
				named("p20261101", "2026-11-01"),
				named("p20261115", "2026-11-15"),
				named("p20261108", "2026-11-08"),
				named("p20261122", "2026-11-22"),
			},
			x:    3,
			want: []string{"p20261101", "p20261108"},
		},
		{
			// X 钳制下界：0 → 1，只保留最新一个。
			name:  "quota clamped to minimum keeps one",
			parts: five(),
			x:     0,
			want:  []string{"p20261101", "p20261108", "p20261115", "p20261122"},
		},
		{
			// X 钳制上界：365 远超现存数量，无淘汰。
			name:    "quota clamped to maximum no drop",
			parts:   five(),
			x:       365,
			wantNil: true,
		},
		{
			// 上界缺失的分区不参与淘汰：余量按全量条目计，跳过后从有上界的
			// 最老开始取。
			name:  "missing upper never dropped",
			parts: append([]Partition{{Name: "pmanually"}}, five()...),
			x:     3,
			want:  []string{"p20261101", "p20261108", "p20261115"},
		},
		{
			// 上界相同按名字升序决出先后。
			name: "equal upper tiebreak by name",
			parts: []Partition{
				named("p20261102", "2026-11-15"),
				named("p20261101", "2026-11-15"),
			},
			x:    1,
			want: []string{"p20261101"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PlanDrop(tc.parts, tc.x)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("drop = %v, want nil", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("drop = %v, want %v", got, tc.want)
			}
		})
	}
}
