/**
 * 登录端路由（docs/前端架构.md §4.1 行 376 / §1.4 行 81；接口文档 §8）：
 * `/sso/login`、`/auth/authorize` → LoginPage——「OIDC 授权页即登录页」；
 * `/auth/authorize` 的已登录直达由后端直接 302 处理（§4.4 行 447），
 * 前端只渲染无会话空壳。`register` / `reset` / `oauth callback` 路由
 * 随后续页面补（本实现不注册，未注册路径渲染兜底提示）。
 *
 * 零第三方路由库（§1.6 行 110：login 无额外依赖）：entry 自挂载
 * （disableMount），极简 pathname 匹配即可；页面刷新即丢失内存态、
 * 回到登录第一步（§4.1 行 376）。
 */
import { loadLoginBootstrap } from './bootstrap';
import { LoginPage } from './pages/LoginPage';

/** 本实现注册的登录端路由（§1.4 行 81 登录端路由清单的已交付子集）。 */
const LOGIN_ROUTES: ReadonlySet<string> = new Set([
  '/sso/login',
  '/auth/authorize',
]);

/** methods 缺失错误态文案——无 i18n 键，最简中文字面量（归后续 i18n 实现）。 */
const INIT_MISSING_TEXT = '初始化数据缺失，请刷新重试';

/** 未注册路由兜底文案——同上。 */
const ROUTE_NOT_FOUND_TEXT = '页面不存在';

/** 登录端应用根：bootstrap 读注入快照 → 路由分派（§4.1 行 374-376）。 */
export function LoginApp() {
  // §4.1 行 375 / §1.5 行 98：methods 必需，缺失即服务端故障——错误态 +
  // 提示刷新，没有回退接口。
  const boot = loadLoginBootstrap();
  if (!boot.ok) {
    return <p role="alert">{INIT_MISSING_TEXT}</p>;
  }
  // 尾斜杠归一（`/sso/login/` 与 `/sso/login` 同页；根路径归一为空串不匹配）。
  const path = window.location.pathname.replace(/\/+$/, '');
  if (!LOGIN_ROUTES.has(path)) {
    return <p role="status">{ROUTE_NOT_FOUND_TEXT}</p>;
  }
  return <LoginPage snapshot={boot.snapshot} />;
}
