// Package main 是 buf check 插件：拦截 .proto 中的 32 位整型字段。
//
// 依据：
//   - docs/后端架构.md §1.6 行 89：「.proto 中只用 int64 → buf lint 加自定义规则拦 int32 / uint32 / fixed32」
//   - docs/接口文档.md §12.9：「整型一律 int64（§1.12），布尔用 bool，时间用 Unix 秒 int64」
//
// 机制：buf 官方 check 插件协议（buf.build/go/bufplugin SDK），
// 由 server/buf.yaml 的 lint.plugins 以 `go -C ./tools/bufcheck run .` 调起。
package main

import (
	"context"

	"buf.build/go/bufplugin/check"
	"buf.build/go/bufplugin/check/checkutil"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// fieldNo32BitIntRuleID 是本规则的 Rule ID。
// 插件规则必须与 buf 内置规则 ID 唯一，故带 PLUGIN_ 前缀。
const fieldNo32BitIntRuleID = "PLUGIN_FIELD_NO_32BIT_INT"

var spec = &check.Spec{
	Rules: []*check.RuleSpec{
		{
			ID:      fieldNo32BitIntRuleID,
			Default: true,
			Purpose: "Checks that no field uses a 32-bit integer type (int32, uint32, sint32, fixed32, sfixed32); use int64 instead.",
			Type:    check.RuleTypeLint,
			Handler: checkutil.NewFieldRuleHandler(checkFieldNo32BitInt, checkutil.WithoutImports()),
		},
	},
}

func main() {
	check.Main(spec)
}

// checkFieldNo32BitInt 对每个字段检查其标量类型：32 位整型一律报错，要求改用 int64。
func checkFieldNo32BitInt(
	_ context.Context,
	responseWriter check.ResponseWriter,
	_ check.Request,
	fieldDescriptor protoreflect.FieldDescriptor,
) error {
	switch fieldDescriptor.Kind() {
	case protoreflect.Int32Kind,
		protoreflect.Uint32Kind,
		protoreflect.Sint32Kind,
		protoreflect.Fixed32Kind,
		protoreflect.Sfixed32Kind:
		responseWriter.AddAnnotation(
			check.WithMessagef(
				"Field %q has 32-bit integer type %s; use int64 instead (整型一律 int64, 接口文档 §12.9).",
				fieldDescriptor.Name(),
				fieldDescriptor.Kind(),
			),
			check.WithDescriptor(fieldDescriptor),
		)
	}
	return nil
}
