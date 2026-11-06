// Package assets 嵌入前端构建产物并经顶层 ServeMux 暴露 /assets/**（§3.13）：
// web/dist 由 pnpm build 构建链尾段入驻 server/assets/dist（根级 *.js /
// *.LICENSE.txt + static/**；html/ 壳层模板源、*.map sourcemap、根级 *.json
// 构建元数据不入驻），go:embed 打进二进制，不依赖外部 web server。正常 /
// setup 两模式恒挂（§3.13 行 484），无鉴权、不进 gin 全局链与 Connect 前缀
// 中间件链。
package assets

import (
	"embed"
	"io/fs"
)

// distFS 嵌入的构建产物子树。all: 前缀把点文件（.gitignore 等）一并嵌入——
// dist 仅含入库占位 .gitignore 的空仓形态下 go build 恒过；缺 dist 目录则
// embed 硬约束直接编译失败（§3.13 行 483 防漏构建）。dist 内容本身不入库
// （.gitignore 条目随实装落地，仅 .gitignore 占位除外）。
//
//go:embed all:dist
var distFS embed.FS

// FS 返回嵌入的 dist 子树（子树根即 dist：文件名扁平直达，如
// login.{hash}.js、static/css/login.{hash}.css，§3.13 行 481 产物布局）。
// 供 NewHandler 映射，也供测试与旁路读取。
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// embed 指令静态保证 dist 子树存在（缺目录即编译失败），此分支
		// 编译期可证伪——失败早炸优于静默降级成空 FS。
		panic("assets: embedded dist subtree missing: " + err.Error())
	}
	return sub
}
