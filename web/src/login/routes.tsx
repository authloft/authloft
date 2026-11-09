/**
 * 登录端路由表（混合路由定稿：login 用 BrowserRouter，account /
 * admin 用 hash——§9 第 26 条选型归 entry 顶层，BrowserRouter 在 entry.tsx）：
 * `/sso/login`、`/sso/register`、`/sso/reset`、`/sso/oauth/callback/:provider_key`
 * （§4.1 行 392 / §2.7.3）、`/auth/authorize`（仅服务前端内部跳转，直达由后端
 * 业务端点接管、不下发壳；「OIDC 授权页即登录页」→ LoginPage）+ `path:'*'`
 * 兜底。BindingPage 无独立 URL（binding_required 原地渲染，§1.6 行 234），
 * 不在路由层。
 *
 * 流程状态机（登录因子切换 / mfa 选择 / challenge）保持原样——本层只承载
 * 「哪个页面」的分派；禁手写 pathname 比较 / 正则匹配（§9 第 24 条），
 * 路径参数经 useParams 取（react-router 段解码、非法编码原样透传，与原
 * decodeProviderKey 同口径）。页面刷新即丢失内存态、回到流程第一步
 *（§4.1 行 392）。
 *
 * 文案：错误态 / 兜底文案经 i18n 字典 login.* 键取用（i18n 收口）。
 */
import { Route, Routes, useParams } from '@modern-js/runtime/router';
import { t } from '../shared/i18n';
import type { MethodsSnapshot } from '../shared/types/init';
import { loadLoginBootstrap } from './bootstrap';
import { LoginPage } from './pages/LoginPage';
import { OAuthCallbackPage } from './pages/OAuthCallbackPage';
import { RegisterPage } from './pages/RegisterPage';
import { ResetPage } from './pages/ResetPage';

/** 回调路由壳：路径参数 provider_key 经 useParams 提取（禁手写 pathname 解析）。 */
function OAuthCallbackRoute({ snapshot }: { snapshot: MethodsSnapshot }) {
  const { provider_key: providerKey } = useParams();
  return (
    <OAuthCallbackPage providerKey={providerKey ?? ''} snapshot={snapshot} />
  );
}

/** 登录端应用根：bootstrap 读注入快照 → 路由表分派（§4.1 行 374-376）。 */
export function LoginApp() {
  // §4.1 行 375 / §1.5 行 98：methods 必需，缺失即服务端故障——错误态 +
  // 提示刷新，没有回退接口。
  const boot = loadLoginBootstrap();
  if (!boot.ok) {
    return <p role="alert">{t('login.initMissing')}</p>;
  }
  return (
    <Routes>
      <Route
        path="/sso/login"
        element={<LoginPage snapshot={boot.snapshot} />}
      />
      {/* 注册 / 重置页共用注入快照（flow=register / flow=reset 已按 §2.1 过滤）。 */}
      <Route
        path="/sso/register"
        element={<RegisterPage snapshot={boot.snapshot} />}
      />
      <Route
        path="/sso/reset"
        element={<ResetPage snapshot={boot.snapshot} />}
      />
      <Route
        path="/sso/oauth/callback/:provider_key"
        element={<OAuthCallbackRoute snapshot={boot.snapshot} />}
      />
      {/* /auth/authorize 的已登录直达由后端直接 302 处理（§4.4 行 447），
          前端只渲染无会话空壳（同一 LoginPage）。 */}
      <Route
        path="/auth/authorize"
        element={<LoginPage snapshot={boot.snapshot} />}
      />
      <Route
        path="*"
        element={<p role="status">{t('login.routeNotFound')}</p>}
      />
    </Routes>
  );
}
