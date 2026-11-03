// writer.go config 生成与原子写入（docs/后端架构.md §3.15 职责表）：
// 写临时文件 → rename 覆盖，权限 0600；全新安装随机生成全部 sign_key
//（config.DefaultConfig 单一默认值来源）。密钥与密码不出现在日志与响应。
package setup

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"authloft/internal/config"
)

// InstallInput 全新安装（路径 B）的用户所填项（接口文档 §13.3）。
// Host 为当前请求 Host，用于 root / rp_id 缺省推导（§3.15 实现要点：
// root 缺省取当前请求 Host；rp_id 缺省取 Host 去掉端口，显式填写优先）。
type InstallInput struct {
	DBDSN         string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	Root          string
	RpID          string
	AdminUsername string
	AdminPassword string
	Host          string
}

// BuildInstallConfig 生成全新安装的完整 config（§3.15 路径 B 步骤 ④）：
// 用户所填项 + 随机生成的全部 sign_key + 其余项默认值（config.DefaultConfig，
// 与 config.yaml.example 同源）。
func BuildInstallConfig(in InstallInput) (*config.Config, error) {
	c, err := config.DefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("setup: generate default config: %w", err)
	}
	c.DB.DSN = in.DBDSN
	c.Redis.Addr = in.RedisAddr
	c.Redis.Password = in.RedisPassword
	c.Redis.DB = in.RedisDB
	if in.Root != "" {
		c.Authloft.Root = in.Root
	} else {
		c.Authloft.Root = "https://" + in.Host
	}
	if in.RpID != "" {
		c.Authloft.RpID = in.RpID
	} else {
		c.Authloft.RpID = hostWithoutPort(in.Host)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("setup: generated config invalid: %w", err)
	}
	return c, nil
}

// WriteConfigFile 原子写 config（§3.15）：同目录临时文件 → rename 覆盖，
// 权限 0600（文件含对称密钥，仅属主可读）。写入中断不落半截 config——
// rename 前目标文件不受影响，失败时临时文件被清理。
func WriteConfigFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("setup: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后为 no-op（ENOENT 忽略）
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("setup: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("setup: close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("setup: chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("setup: rename into place: %w", err)
	}
	return nil
}

// marshalConfig 序列化 config（安装路径 B 写盘用）；路径 A 直接写上传原文。
func marshalConfig(c *config.Config) ([]byte, error) {
	out, err := yaml.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("setup: marshal config: %w", err)
	}
	return out, nil
}

// hostWithoutPort 取 Host 去掉端口（§3.15：IP / 内网同样适用）；
// 无端口 / 解析失败时原样返回。
func hostWithoutPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
