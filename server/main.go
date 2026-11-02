package main

import (
	"log/slog"
	"os"
)

// configPath 配置文件路径（§3.2 行 256 明文 configs/config.yaml，相对
// server/ 工作目录）。文档未规定 flag 覆盖方式，不用 flag——属文档缺口，
// 需可配置时先补 §3.2 再改此处。
const configPath = "configs/config.yaml"

func main() {
	if err := run(configPath); err != nil {
		// fail-fast：装配或运行期致命错误退出非 0。优雅关闭（app.Run /
		// Shutdown，§3.1 行 250）属后续实现，当前无 ErrServerClosed 正常路径。
		slog.Error("authloft exited with error", "err", err)
		os.Exit(1)
	}
}
