package main

import (
	"flag"
	"log/slog"
	"os"
)

// defaultConfigPath 默认配置文件路径：当前工作目录下的 authloft.yaml
//（相对路径按进程 cwd 解析）。--config / -config 可覆盖，读写共用同一路径。
const defaultConfigPath = "authloft.yaml"

func main() {
	configPath := flag.String("config", defaultConfigPath, "path to the config file (relative paths resolve against the working directory)")
	flag.Parse()
	if err := run(*configPath); err != nil {
		// fail-fast：装配或运行期致命错误退出非 0。优雅关闭（app.Run /
		// Shutdown，§3.1 行 250）属后续实现，当前无 ErrServerClosed 正常路径。
		slog.Error("authloft exited with error", "err", err)
		os.Exit(1)
	}
}
