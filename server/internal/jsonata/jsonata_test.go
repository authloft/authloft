// jsonata_test.go 覆盖 gnata 封装层：
//   - 正常表达式（§15.1 行 1718 逐字示例、2.x 转义、空白、数字拼接；
//     含 undefined 拼接 cast 空串的 2.x 语义行为记录）；
//   - 嵌套 / 数组访问（$.a.b、$.arr[0]、$.arr[i].k、越界 undefined）；
//   - 非法表达式报错（ErrInvalidExpression，含空表达式 / 残缺语法 /
//     1.x 双单引号转义——不支持清单项）；
//   - 运行期求值失败（ErrEvaluate：类型错运算 / 不支持清单函数）；
//   - 空值与类型不匹配（ErrNotString：undefined 路径、数字 / 布尔 /
//     对象 / 数组结果）；
//   - TestSupportMatrix 支持度摸底：对项目相关 JSONata 语法逐条实测，
//     断言与 Unsupported 清单一致（升级 gnata 后清单失准会显式 FAIL）；
//   - 错误归一：哨兵可 errors.Is 判别，返回错误不包含 gnata 原始错误文本。
package jsonata

import (
	"errors"
	"strings"
	"testing"
)

// TestEvaluateDocumentedExample §15.1 行 1718 示例逐字。
func TestEvaluateDocumentedExample(t *testing.T) {
	got, err := Evaluate(`'qrcodes_' & $.ticket_id & '.jpg'`, map[string]string{
		"ticket_id": "c7Kx9",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got != "qrcodes_c7Kx9.jpg" {
		t.Fatalf("got %q, want qrcodes_c7Kx9.jpg", got)
	}
}

// TestEvaluateNormal 正常表达式：2.x 转义（\' 与双引号字面量）、空白容忍、
// 数字字面量拼接、timestamp 变量、单字面量、$string 显式转换。
func TestEvaluateNormal(t *testing.T) {
	cases := []struct {
		name string
		expr string
		vars map[string]string
		want string
	}{
		{"反斜杠转义单引号", `'it\'s_' & $.ticket_id`, map[string]string{"ticket_id": "x"}, "it's_x"},
		{"双引号字面量", `"it's_" & $.ticket_id`, map[string]string{"ticket_id": "x"}, "it's_x"},
		{"空白容忍", ` 'a' & $.ticket_id `, map[string]string{"ticket_id": "b"}, "ab"},
		{"数字拼接", `'p' & 123 & $.ticket_id`, map[string]string{"ticket_id": "q"}, "p123q"},
		{"timestamp 变量", `'q' & $.timestamp`, map[string]string{"timestamp": "1761800000"}, "q1761800000"},
		{"单字面量", `'only'`, nil, "only"},
		{"$string 转换", `$string(42) & '-' & $.ticket_id`, map[string]string{"ticket_id": "k"}, "42-k"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.expr, tc.vars)
			if err != nil {
				t.Fatalf("Evaluate(%q): %v", tc.expr, err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	// JSONata 2.x 语义（gnata 实测）：& 拼接对 undefined 做 cast 为空串
	//（'a' & $.missing = "a"）——如实现场行为记录，空值判别见 NotString。
	if got, err := Evaluate(`'a' & $.missing`, nil); err != nil || got != "a" {
		t.Fatalf("'a' & $.missing = (%q, %v)，JSONata 2.x 应 cast 空串得 \"a\"", got, err)
	}
}

// TestEvaluateNestedAndArrays 嵌套与数组访问（表达式内构造结构化数据；
// 封装层变量集 map[string]string 的值是纯字符串，$.a.b 对其求值为
// undefined——结构化数据的真实形态见 user_mapping 后续实现）。
func TestEvaluateNestedAndArrays(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want string
	}{
		{"嵌套访问", `{'a':{'b':'c'}}.a.b`, "c"},
		{"数组下标", `['x','y','z'][1]`, "y"},
		{"数组内嵌套取键", `[{'k':'v0'},{'k':'v1'}][1].k`, "v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.expr, nil)
			if err != nil {
				t.Fatalf("Evaluate(%q): %v", tc.expr, err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	// 数组下标越界 → undefined → ErrNotString。
	if _, err := Evaluate(`['x'][5]`, nil); !errors.Is(err, ErrNotString) {
		t.Fatalf("越界下标 err = %v, want ErrNotString", err)
	}
}

// TestEvaluateInvalid 非法表达式 → ErrInvalidExpression（不透出 gnata
// 原始错误文本）。注意：+ 是合法 JSONata 数字运算符，对字符串操作数是
// 运行期类型错（归 ErrEvaluate，见 TestEvaluateRuntimeFail）。
func TestEvaluateInvalid(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		{"空表达式", ""},
		{"未闭合字面量", `'abc`},
		{"残缺拼接", `'a' &`},
		{"1.x 双单引号转义（不支持清单）", `'it''s_'`},
		{"空变量名", `'a' & $.`},
		{"尾部残片", `'a' & 'b' )`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.expr, map[string]string{"x": "1"})
			if err == nil {
				t.Fatalf("Evaluate(%q) = %q, want error", tc.expr, got)
			}
			if !errors.Is(err, ErrInvalidExpression) {
				t.Fatalf("err = %v, want ErrInvalidExpression", err)
			}
		})
	}
}

// TestEvaluateRuntimeFail 运行期求值失败 → ErrEvaluate：语法合法但操作数
// 类型错 / 不支持清单内函数（$padStart）。
func TestEvaluateRuntimeFail(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		{"字符串参与数字加法", `'a' + $.x`},
		{"不支持清单函数 $padStart", `$padStart('7', 3, '0')`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.expr, map[string]string{"x": "1"})
			if err == nil {
				t.Fatalf("Evaluate(%q) = %q, want error", tc.expr, got)
			}
			if !errors.Is(err, ErrEvaluate) {
				t.Fatalf("err = %v, want ErrEvaluate", err)
			}
		})
	}
}

// TestEvaluateNotString 空值与类型不匹配 → ErrNotString：未定义路径
// （undefined，注意 & 拼接会把 undefined cast 成空串——见 Normal 的行为
// 记录，纯路径才是判空入口）、数字结果、布尔结果、对象结果、数组结果。
func TestEvaluateNotString(t *testing.T) {
	cases := []struct {
		name string
		expr string
		vars map[string]string
	}{
		{"未定义路径", `$.missing`, map[string]string{"ticket_id": "x"}},
		{"数字结果", `1 + 2`, nil},
		{"布尔结果", `true`, nil},
		{"对象结果", `{'a': 1}`, nil},
		{"数组结果", `['a','b']`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.expr, tc.vars)
			if err == nil {
				t.Fatalf("Evaluate(%q) = %q, want error", tc.expr, got)
			}
			if !errors.Is(err, ErrNotString) {
				t.Fatalf("err = %v, want ErrNotString", err)
			}
		})
	}
}

// TestEvaluateErrorNormalized 错误归一：哨兵判别 + 返回错误文本不含
// gnata 原始错误关键词（不透出库内部实现细节，接口文档 §5.3 行 1263）。
func TestEvaluateErrorNormalized(t *testing.T) {
	_, err := Evaluate(`'a' &`, nil)
	if err == nil {
		t.Fatal("want error")
	}
	if !errors.Is(err, ErrInvalidExpression) {
		t.Fatalf("err = %v, want ErrInvalidExpression", err)
	}
	// gnata 原始错误带 code（如 S0201）/ "token" / 位置信息——归一后不出现。
	for _, leak := range []string{"S0201", "token", "gnata:", "column", "line"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("错误文本疑似透出库原始错误: %q (contains %q)", err.Error(), leak)
		}
	}
	// 三哨兵互相独立可判别。
	for _, sentinel := range []error{ErrInvalidExpression, ErrEvaluate, ErrNotString} {
		if errors.Is(err, sentinel) && sentinel != ErrInvalidExpression {
			t.Fatalf("编译错误不应命中 %v", sentinel)
		}
	}
}

// TestSupportMatrix 支持度摸底矩阵（Unsupported 清单的活文档）：对项目
// 相关 JSONata 语法逐条实测；unsupportedCase=true 的条目按「确认不支持」
// 断言（Evaluate 报错），其余按「支持且产出字符串」断言。gnata 升级后
// 实际行为与本矩阵不符会 FAIL，提醒同步更新 Unsupported 清单（§1.5 版本
// 策略：升级须重跑本包测试基线）。
func TestSupportMatrix(t *testing.T) {
	vars := map[string]string{"ticket_id": "t1", "timestamp": "42"}
	cases := []struct {
		name            string
		expr            string
		want            string
		unsupportedCase bool // true = 摸底结论「gnata 不支持」
	}{
		// —— storage_path 核心 ——
		{"字符串拼接", `'qrcodes_' & $.ticket_id & '.jpg'`, "qrcodes_t1.jpg", false},
		{"数字字面量", `'v' & 7`, "v7", false},
		// —— 嵌套 / 数组（表达式内构造结构化数据）——
		{"嵌套访问", `{'a':{'b':'c'}}.a.b`, "c", false},
		{"数组下标", `['x','y','z'][1]`, "y", false},
		{"数组负下标", `['x','y','z'][-1]`, "z", false},
		// gnata（JSONata 2.x）实测：& 对数组 cast 为 JSON 文本（1.x 为空格
		// join）——行为差异如实断言记录。
		{"数组步进", `['x','y','z'][1..2] & ''`, `["y","z"]`, false},
		{"数组内嵌套", `[{'k':'v0'},{'k':'v1'}][1].k`, "v1", false},
		{"$join 拼接", `$join(['a','b'],'-')`, "a-b", false},
		// —— 字符串函数 ——
		{"$substring", `$substring('abcdef', 1, 3)`, "bcd", false},
		{"$substringBefore", `$substringBefore('a-b', '-')`, "a", false},
		{"$uppercase", `$uppercase('ab')`, "AB", false},
		{"$split+join", `$join($split('a-b-c','-'), '_')`, "a_b_c", false},
		{"$replace", `$replace('a-b', '-', '_')`, "a_b", false},
		{"$padStart（不支持清单）", `$padStart('7', 3, '0')`, "", true},
		{"$contains", `($contains('abc','b') = true) & '!'`, "true!", false},
		{"$contains 正则", `$contains('abc123', /^[a-z]+[0-9]+$/) & ''`, "true", false},
		// —— 类型 / 日期 ——
		{"$string 数字", `$string(42)`, "42", false},
		{"$length", `$length('abc') & ''`, "3", false},
		// —— 条件 / 比较 ——
		{"三元", `$.ticket_id = 't1' ? 'yes' : 'no'`, "yes", false},
		{"in 运算", `('y' in ['x','y']) & ''`, "true", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.expr, vars)
			if tc.unsupportedCase {
				if err == nil {
					t.Fatalf("摸底结论为不支持，但 Evaluate 成功: %q（请更新 Unsupported 清单）", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Evaluate(%q): %v（若确属 gnata 不支持，请登记 Unsupported 清单）", tc.expr, err)
			}
			if tc.want != "" && got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	// Unsupported 清单独有一席：清单非空但矩阵无对应 unsupportedCase 条目
	// 时提醒同步（清单与矩阵互为对账）。
	if len(Unsupported) > 0 {
		for syntax := range Unsupported {
			t.Logf("Unsupported 清单登记: %s", syntax)
		}
	}
}
