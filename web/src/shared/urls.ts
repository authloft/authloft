/**
 * URL 唯一真值（docs/前端架构.md §3 行 168）：跨域路径常量、默认
 * 落点、`loginUrl` / `logoutUrl` / `normalizeAlRoot`、returnTo 拼装与前缀
 * 白名单校验。全部纯函数、只产字符串——**不含 Router 选型**（§9 第 26 条：
 * `BrowserRouter` / `HashRouter` 选择归各 entry 顶层，本模块不出现模式分支）。
 * 收编 account / admin / setup 三份逐字复制实现（原各自 bootstrap.ts）。
 */

/** 登录页路径（接口文档 §8 行 1418）。 */
export const LOGIN_PATH = '/sso/login';

/** 登出路径（接口文档 §8 行 1420：Go 处理，非 SPA）。 */
export const LOGOUT_PATH = '/sso/logout';

/** OAuth 回调路径前缀（接口文档 §2.7.3 行 602：`/sso/oauth/callback/{provider_key}`）。 */
export const OAUTH_CALLBACK_PREFIX = '/sso/oauth/callback/';

/** account 域默认落点（混合路由形态：path 在 hash 内）。 */
export const DEFAULT_ACCOUNT_HOME = '/account#/profile';

/**
 * al_root 归一：string 校验 → trim → 去尾斜杠；缺省回落当前站点源；
 * 非浏览器环境（单测 node）为空串（与 shared/api/http.ts 的 resolveBaseUrl
 * 同口径）。
 */
export function normalizeAlRoot(alRoot: unknown): string {
  const value =
    typeof alRoot === 'string' ? alRoot.trim().replace(/\/+$/, '') : '';
  if (value !== '') {
    return value;
  }
  return typeof location !== 'undefined' ? location.origin : '';
}

/**
 * returnTo 前缀白名单校验（防开放重定向）：仅放行 `/account#` /
 * `/admin#` 前缀的站内值；其余（站外 URL、其他站内路径、空串）一律回落
 * 默认落点。
 */
export function sanitizeReturnTo(value: string): string {
  if (value.startsWith('/account#') || value.startsWith('/admin#')) {
    return value;
  }
  return DEFAULT_ACCOUNT_HOME;
}

/**
 * 登录页地址（§8 行 1418）：`{alRoot}/sso/login`；returnTo 给定则经白名单
 * 校验后拼 `?returnTo=<encoded>`（无效值回落默认落点，见
 * sanitizeReturnTo）。
 */
export function loginUrl(alRoot: string, returnTo?: string): string {
  const base = `${alRoot}${LOGIN_PATH}`;
  if (returnTo === undefined) {
    return base;
  }
  return `${base}?returnTo=${encodeURIComponent(sanitizeReturnTo(returnTo))}`;
}

/** 登出地址（§8 行 1420）：`{alRoot}/sso/logout`。 */
export function logoutUrl(alRoot: string): string {
  return `${alRoot}${LOGOUT_PATH}`;
}
