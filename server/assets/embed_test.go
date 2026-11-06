// FS() 冒烟（§3.13 行 483）：all: 前缀把入库占位 .gitkeep 一并嵌入
//——空仓形态下 go build 恒过，子树根直达文件名（入驻真实产物后同一断言
// 即覆盖全量资源）。
package assets

import (
	"io/fs"
	"testing"
)

func TestFSEmbedsGitkeepPlaceholder(t *testing.T) {
	f := FS()
	if _, err := fs.Stat(f, ".gitkeep"); err != nil {
		t.Fatalf("embedded dist must contain in-tree .gitkeep placeholder: %v", err)
	}
}
