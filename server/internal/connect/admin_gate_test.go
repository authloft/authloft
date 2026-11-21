// admin_gate_test.go：admin 域两层门禁的中间件层完整性测试（§3.14 / §4.8
// 完整性测试判据）。判据一「procedure 全集覆盖」：AdminService 注册
// procedure 全集自 proto 描述符枚举（与生成 NewAdminServiceHandler 的注册
// 锚点同源——未来新增 RPC 自动入集，无逐接口开关），逐 procedure 断言其
// 被「session + admin」拦截链覆盖；判据二「非管理员 404 掩护」现行语义
// 固化：会话标记 false 不查库、探针 false 均统一 not_found（文案与普通
// 资源 404 一致），探针故障 fail-closed internal 不回落 404。判据可证伪
// ——摘掉 admin 拦截器挂载，无会话 / 非管理员两分支将穿透到业务层桩返回
// unimplemented，全集断言即红。业务层用 Unimplemented 桩：门禁在位时到
// 不了桩，放行分支落桩即链路自检（501）。
package connect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	adminv1 "authloft/gen/go/api/admin/v1"
	adminv1connect "authloft/gen/go/api/admin/v1/adminv1connect"
)

// gateStubHandler 业务层桩：门禁链在位时任何门禁分支都到不了桩；只有
// 显式放行分支的自检应落桩（返回 unimplemented）。
type gateStubHandler struct {
	adminv1connect.UnimplementedAdminServiceHandler
}

// gateProbeLookup 权限探针记录器（PermissionLookup 注入形，与装配层注入
// 方式同构）；「标记 false 不查库」判据依赖其调用留痕。
type gateProbeLookup struct {
	calls   []int64
	granted map[int64]bool
	err     error
}

func (g *gateProbeLookup) lookup(_ context.Context, uid int64) (bool, error) {
	g.calls = append(g.calls, uid)
	if g.err != nil {
		return false, g.err
	}
	return g.granted[uid], nil
}

// adminProcedureSet 枚举 AdminService 注册 procedure 全集（自 proto 描述符，
// 与生成 handler 内部枚举同一来源），返回完整 procedure 路径。
func adminProcedureSet(t *testing.T) []string {
	t.Helper()
	methods := adminv1.File_api_admin_v1_admin_proto.Services().ByName("AdminService").Methods()
	if methods.Len() == 0 {
		t.Fatal("AdminService 描述符方法集为空，全集枚举锚点失效")
	}
	procs := make([]string, 0, methods.Len())
	for i := 0; i < methods.Len(); i++ {
		procs = append(procs, "/api.admin.v1.AdminService/"+string(methods.Get(i).Name()))
	}
	return procs
}

// newAdminGateServer 按 registerAdmin 装配口径同构挂链（session 外、admin
// 内，HandlerOptions 补错误日志 / 错误包装 / recover），返回测试服务器与
// 会话令牌签发环境。
func newAdminGateServer(t *testing.T, lookup *gateProbeLookup) (*httptest.Server, *sessionEnv) {
	t.Helper()
	env := newSessionEnv(t)
	s := NewServer(0)
	mount, h := adminv1connect.NewAdminServiceHandler(
		gateStubHandler{},
		s.HandlerOptions(
			NewSessionInterceptor(env.verifier, env.renewer, env.cookie, nil),
			NewAdminInterceptor(lookup.lookup),
		)...,
	)
	if mount != "/api.admin.v1.AdminService/" {
		t.Fatalf("mount = %q, want /api.admin.v1.AdminService/", mount)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, env
}

// doAdminGateRPC 对指定 procedure 发一次 JSON 空对象请求（门禁分支只看
// 会话身份与权限标记、不触业务解码，空对象对全部请求消息类型均合法）；
// 返回 HTTP 状态与 connect 错误码。
func doAdminGateRPC(t *testing.T, srv *httptest.Server, procedure, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+procedure, strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("NewRequest %s: %v", procedure, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	if token != "" {
		req.Header.Set("X-Authloft-Token", token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do %s: %v", procedure, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll %s: %v", procedure, err)
	}
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &payload)
	return resp.StatusCode, payload.Code
}

// signGateToken 以标准载荷签发会话令牌（hasPerm 写入 has_any_permission
// 标记——登录签发侧写入、拦截器读 ctx 标记的现行口径）。
func signGateToken(t *testing.T, env *sessionEnv, hasPerm bool) string {
	t.Helper()
	p := env.validPayload()
	p.HasAnyPermission = hasPerm
	return env.sign(t, p)
}

// TestAdminInterceptorCoversAdminProcedureFullSet 中间件层完整性判据：
// AdminService 全部 procedure 均经过身份门禁拦截链。四分支逐 procedure
// 断言：无会话 unauthenticated；标记 false 不查库 404 掩护；探针 false
// 404 掩护（每 procedure 触达一次探针）；探针故障 fail-closed internal；
// 另以放行分支自检链路完整（放行后应穿链落到业务桩）。
func TestAdminInterceptorCoversAdminProcedureFullSet(t *testing.T) {
	procs := adminProcedureSet(t)
	if len(procs) < 20 {
		t.Fatalf("procedure 全集 = %d，数量异常（枚举锚点疑似失效）", len(procs))
	}

	t.Run("无会话全量 unauthenticated", func(t *testing.T) {
		lookup := &gateProbeLookup{}
		srv, _ := newAdminGateServer(t, lookup)
		for _, proc := range procs {
			status, code := doAdminGateRPC(t, srv, proc, "")
			if status != http.StatusUnauthorized || code != "unauthenticated" {
				t.Errorf("%s: (%d, %q), want (401, unauthenticated)", proc, status, code)
			}
		}
	})

	t.Run("非管理员标记 false 全量 404 掩护且不查库", func(t *testing.T) {
		lookup := &gateProbeLookup{}
		srv, env := newAdminGateServer(t, lookup)
		tok := signGateToken(t, env, false)
		for _, proc := range procs {
			status, code := doAdminGateRPC(t, srv, proc, tok)
			if status != http.StatusNotFound || code != "not_found" {
				t.Errorf("%s: (%d, %q), want (404, not_found)", proc, status, code)
			}
		}
		if len(lookup.calls) != 0 {
			t.Errorf("标记 false 应直接 not_found 不查库, 探针调用 = %v", lookup.calls)
		}
	})

	t.Run("标记 true 探针 false 全量 404 掩护", func(t *testing.T) {
		lookup := &gateProbeLookup{granted: map[int64]bool{}}
		srv, env := newAdminGateServer(t, lookup)
		tok := signGateToken(t, env, true)
		for _, proc := range procs {
			status, code := doAdminGateRPC(t, srv, proc, tok)
			if status != http.StatusNotFound || code != "not_found" {
				t.Errorf("%s: (%d, %q), want (404, not_found)", proc, status, code)
			}
		}
		// 每 procedure 各触达一次探针（全集覆盖度的直接留痕）。
		if len(lookup.calls) != len(procs) {
			t.Errorf("探针调用 = %d, want 每 procedure 一次 = %d", len(lookup.calls), len(procs))
		}
	})

	t.Run("探针故障 fail-closed internal 不回落 404", func(t *testing.T) {
		buf := withCapturedLogs(t) // 故障日志不污染测试输出
		lookup := &gateProbeLookup{err: errors.New("perm repo down")}
		srv, env := newAdminGateServer(t, lookup)
		tok := signGateToken(t, env, true)
		for _, proc := range procs {
			status, code := doAdminGateRPC(t, srv, proc, tok)
			if status != http.StatusInternalServerError || code != "internal" {
				t.Errorf("%s: (%d, %q), want (500, internal)", proc, status, code)
			}
		}
		if !strings.Contains(buf.String(), "perm repo down") {
			t.Errorf("fail-closed 根因应留痕日志: %q", buf.String())
		}
	})

	t.Run("放行请求穿链落桩（链路自检）", func(t *testing.T) {
		lookup := &gateProbeLookup{granted: map[int64]bool{42: true}}
		srv, env := newAdminGateServer(t, lookup)
		tok := signGateToken(t, env, true)
		for _, proc := range procs {
			status, code := doAdminGateRPC(t, srv, proc, tok)
			if status != http.StatusNotImplemented || code != "unimplemented" {
				t.Errorf("%s: (%d, %q), want (501, unimplemented)——放行后应落到业务桩", proc, status, code)
			}
		}
	})
}
