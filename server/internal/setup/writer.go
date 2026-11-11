// writer.go config 生成与原子写入（docs/后端架构.md §3.15 职责表）：
// 写临时文件 → rename 覆盖，权限 0600；全新安装随机生成全部 7 把 sign_key
// （session / login / ticket / cookie / sync_payload / webauthn / verification，
// config.DefaultConfig 单一默认值来源）与 oidc.jwt_keys（RSA 2048 位
// PKCS#8，kid="1"）。密钥与密码不出现在日志与响应。
package setup

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"authloft/internal/config"
	"authloft/internal/factor/webauthn"
)

// InstallInput 全新安装（路径 B）的用户所填项（接口文档 §13.3）。
// Root 必填（完整 URL，host 须为域名或 localhost，拒绝 IP——安装
// 不得靠自动推导的 IP 蒙混过关）；RpID 缺省取 Root 的 host
// （去 scheme 与端口），显式填写优先（域名字符串，允许 localhost），
// 不再自动读取请求 Host。RPDisplayName 缺省取
// config.DefaultRPDisplayName，保证生成的 config 一定带非空 RP 展示名
// （go-webauthn 生成注册选项的硬性要求）。
type InstallInput struct {
	DBDSN         string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	Root          string
	RpID          string
	RPDisplayName string
	AdminUsername string
	AdminPassword string
}

// validateInstallInput 路径 B 步骤 ①字段校验（接口文档 §13.3 行 1911 执行
// 顺序①，位于连接性检查之前）：root 必填且为完整 http(s) URL、host 部分
// 为域名或 localhost（拒绝 IP——IP 作 WebAuthn RP ID 会被库校验拒绝）；
// rpId 显式填写必须为域名字符串（允许 localhost），缺省取 root 的 host。
// 域名判定复用 webauthn.ValidRPID（与启动期库校验同一口径：安装期接受的
// rp_id 集合 ⊆ 启动期库接受集合，从源头避免装完即降级）。任一不过 →
// config_invalid。
func validateInstallInput(in InstallInput) error {
	u, err := url.Parse(strings.TrimSpace(in.Root))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return bizErr(CodeConfigInvalid, "root is required and must be a full http(s) URL", nil)
	}
	if !webauthn.ValidRPID(u.Hostname()) {
		return bizErr(CodeConfigInvalid, "root host must be a domain or localhost, not an IP address", nil)
	}
	rpID := strings.TrimSpace(in.RpID)
	if rpID == "" {
		rpID = u.Hostname() // 缺省取 root 的 host（去 scheme 与端口）
	}
	if !webauthn.ValidRPID(rpID) {
		return bizErr(CodeConfigInvalid, "rp_id must be a domain string or localhost", nil)
	}
	return nil
}

// BuildInstallConfig 生成全新安装的完整 config（§3.15 路径 B 步骤 ④）：
// 用户所填项 + 随机生成的全部 sign_key / oidc.jwt_keys + 其余项默认值
// （config.DefaultConfig，与 authloft.yml.example 同源）。root 必填、
// rp_id 缺省取 root 的 host（步骤 ①已校验，见 validateInstallInput），
// rp_display_name 缺省保留 DefaultConfig 的 config.DefaultRPDisplayName。
func BuildInstallConfig(in InstallInput) (*config.Config, error) {
	c, err := config.DefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("setup: generate default config: %w", err)
	}
	c.DB.DSN = in.DBDSN
	c.Redis.Addr = in.RedisAddr
	c.Redis.Password = in.RedisPassword
	c.Redis.DB = in.RedisDB
	c.Authloft.Root = in.Root
	if in.RpID != "" {
		c.Authloft.RpID = in.RpID
	} else if u, err := url.Parse(in.Root); err == nil {
		c.Authloft.RpID = u.Hostname()
	}
	// 留空时保留 DefaultConfig 写入的默认值：安装向导已预填，直接调
	// Install API 不传该字段时也不会生成空 RP 展示名（空值既过不了
	// config.Validate，也会让 go-webauthn 的 BeginRegistration 失败）。
	if v := strings.TrimSpace(in.RPDisplayName); v != "" {
		c.Authloft.RPDisplayName = v
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
