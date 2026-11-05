// Package jsonata 是 JSONata 表达式求值的唯一内部封装层
// （docs/后端架构.md §1.5 第三方库 / §3.12 行 471；docs/接口文档.md
// §5.3 行 1259-1263 表达式字段约定，已定稿）：
//
//   - 求值引擎统一使用 gnata（github.com/recolabs/gnata v0.6.2，
//     2026-11-05 定稿），**不自研表达式解析 / 求值**；本包是全库唯一
//     import gnata 之处，service / handler 只 import 本包，替换实现只改
//     本文件（gnata 类型不外泄到包外）。
//   - 错误归一（接口文档 §5.3 行 1261-1263）：编译失败 →
//     ErrInvalidExpression（保存预校验映射 admin 域 invalid_request）；
//     运行期求值失败 → ErrEvaluate（登录链路映射 §1.6 既有兜底）；结果
//     非字符串（含 undefined 空值 / 数字 / 对象等）→ ErrNotString。三类
//     均为内部哨兵，**不透出 gnata 原始错误**——库原始错误仅进 DEBUG
//     日志供排查。
//   - gnata 不支持的 JSONata 语法在本包维护不支持清单（Unsupported
//     变量 + 摸底测试），如实记录、不以自研补齐，随库升级同步更新
//     （升级须重跑本包测试基线，§1.5 版本策略）。
//
// module path 大小写说明：文档 §1.5 写 github.com/RecoLabs/gnata，库自身
// go.mod 声明为小写 github.com/recolabs/gnata（Go module path 大小写
// 敏感，按库声明引入），版本 v0.6.2 与文档 pin 一致。
package jsonata

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	gnata "github.com/recolabs/gnata"
)

// 归一哨兵错误（接口文档 §5.3：调用方按所在域既有错误码映射，本包不
// 生成 Connect 错误体）。
var (
	// ErrInvalidExpression 表达式编译失败（语法非法）——保存预校验口径
	//（admin 域 invalid_request）。
	ErrInvalidExpression = errors.New("jsonata: invalid expression")
	// ErrEvaluate 运行期求值失败——登录链路 §1.6 既有兜底口径。
	ErrEvaluate = errors.New("jsonata: evaluate failed")
	// ErrNotString 求值结果非字符串（undefined 空值 / 数字 / 布尔 /
	// 对象 / 数组）——storage_path / user_mapping 的值域都是字符串。
	ErrNotString = errors.New("jsonata: result is not a string")
)

// Unsupported 是 gnata v0.6.2 对项目相关 JSONata 语法的支持度摸底清单
// （如实记录、不补齐；随库升级同步更新——摸底测试 TestSupportMatrix
// 逐条断言本清单，升级后清单与实际不符会显式 FAIL 提醒更新）。
var Unsupported = map[string]bool{
	// 字符串字面量的 1.x 双单引号转义（'it''s'）：JSONata 2.x（gnata）
	// 不支持，编译失败；2.x 转义形态为反斜杠 \' 或改用双引号字面量。
	"字符串字面量 1.x 双单引号转义（''）": true,
	// $padStart / $padEnd 字符串填充函数：gnata v0.6.2 未提供（求值报
	// 函数未定义）；填充需求可用 $substring + $repeat 组合或前置补零在
	// 调用方业务层实现。
	"$padStart / $padEnd": true,
}

// Evaluate 对表达式求值并返回字符串结果（调用方 storage.RenderKey 的
// 既有签名，零改动沿用）。vars 为内置变量集（storage_path：ticket_id /
// timestamp；user_mapping 后续共用），表达式经 `$.<name>` 引用。
//
// 失败归一为三类哨兵（见包注释），不透出 gnata 原始错误；每次调用现编译
// （拉码 / 登录链路 QPS 远低于热路径，编译开销可接受；高频场景的编译缓存
// 归后续有实测需求的卡，不提前设计）。
func Evaluate(expr string, vars map[string]string) (string, error) {
	if expr == "" {
		return "", fmt.Errorf("%w: empty expression", ErrInvalidExpression)
	}
	compiled, err := gnata.Compile(expr)
	if err != nil {
		slog.Debug("jsonata: gnata compile failed", "err", err.Error())
		return "", fmt.Errorf("%w", ErrInvalidExpression)
	}
	// vars → 输入数据（$ 绑定）：map[string]any 形态，$.<name> 逐键访问。
	data := make(map[string]any, len(vars))
	for k, v := range vars {
		data[k] = v
	}
	result, err := compiled.Eval(context.Background(), data)
	if err != nil {
		slog.Debug("jsonata: gnata eval failed", "err", err.Error())
		return "", fmt.Errorf("%w", ErrEvaluate)
	}
	// undefined 结果（如 $.missing）gnata 返回 (nil, nil)——归一为
	// ErrNotString（空值类），空串同判（storage_path 渲染空 key 无意义）。
	s, ok := result.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("%w: %T", ErrNotString, result)
	}
	return s, nil
}
