// userref.go 密码失败计数 user_ref 的唯一推导定义（docs/后端架构.md
// §8.1 行 1027）：因子写计数（Verify → Capture）与引擎读计数
// （orchestrator evaluateCaptcha → Count）两侧键口径收敛到本文件的
// lookupIdentifier / UserRefOf，任何一侧漂移都会在真实链路测试中断裂
//（先例：引擎按 username 原文读键、因子按 ip|sha256 写键，计数恒 0，
// 渐进式保护第 1 级全量失效）。
package password

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"gorm.io/gorm"

	"authloft/internal/repo/model"
)

// UserRefResolver identifier → user_ref 的共用解析器：引擎读计数注入本
// 实现（与因子写入侧共用同一 Users / IP 实例，装配方保证）。
type UserRefResolver struct {
	Users Users
	IP    IPResolver
}

// UserRef 解析 identifier：先按 username → phone → email 顺序查用户
// （接口文档 §2.1 行 350），存在 → "{userID}"；不存在 → "{ip}|{sha256}"
// （§8.1 行 1027）。仓储错误向上传递（调用方映射 failed）。
func (r UserRefResolver) UserRef(ctx context.Context, identifier string) (string, error) {
	user, err := lookupIdentifier(ctx, r.Users, identifier)
	if err != nil {
		return "", err
	}
	ip := ""
	if r.IP != nil {
		ip = r.IP.ClientIP(ctx)
	}
	return UserRefOf(identifier, user, ip), nil
}

// UserRefOf user_ref 格式的唯一函数定义：用户存在 → "{userID}"；不存在 →
// "{ip}|{sha256(identifier)}"（ip 空回退 "unknown"：共享桶宁可偏严，也不留
// 空键造成限流旁路）。因子 Verify（写计数）与引擎 evaluateCaptcha（读计数）
// 共用，禁止各自拼装。
func UserRefOf(identifier string, user *model.User, ip string) string {
	if user != nil {
		return strconv.FormatInt(user.ID, 10)
	}
	if ip == "" {
		ip = "unknown"
	}
	sum := sha256.Sum256([]byte(identifier))
	return ip + "|" + hex.EncodeToString(sum[:])
}

// lookupIdentifier 按 username → phone → email 顺序解析登录标识（§2.1
// 行 350）。均不存在返回 (nil, nil)；其它仓储错误向上传递。因子 Verify 与
// UserRefResolver 共用，保证两侧对「用户是否存在」的判定一致。
func lookupIdentifier(ctx context.Context, users Users, identifier string) (*model.User, error) {
	if u, err := users.FindByUsername(ctx, identifier); err == nil {
		return u, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if u, err := users.FindByPhone(ctx, identifier); err == nil {
		return u, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if u, err := users.FindByEmail(ctx, identifier); err == nil {
		return u, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	return nil, nil
}
