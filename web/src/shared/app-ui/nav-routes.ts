/**
 * 导航路由项类型与 Nav 派生工具（docs/前端架构.md §3 行 194）：
 * 导航项结构单一来源，account / admin 的 HashRouter 路由表与 Nav 高亮均由
 * 此派生（禁第二份路径字面量）。产出形态对齐 Semi Nav 的 `items`
 * （`{ itemKey, text }`），故落 `app-ui/` 而非 shared 根（§9 第 13 条：
 * login 禁引 Semi——本模块零运行时 Semi import，仅纯结构 + i18n）。
 */
import { ComponentType } from 'react';
import { t, type I18nKey } from '../i18n';

/** 导航路由项（path 为 hash 内路径；textKey 渲染期经 t() 求值）。 */
export interface AppRoute {
  /** 域内路由路径（HashRouter 内路径，如 '/profile'）。 */
  path: string;
  /** 文案键（渲染期经 t() 取文案，防模块级 locale 冻结）。 */
  textKey: I18nKey;
}

/** account 域导航路由表（`/account#/profile` 等三页）。 */
export const ACCOUNT_NAV_ROUTES: AppRoute[] = [
  { path: '/', textKey: 'account.profileTitle' },
  { path: '/security', textKey: 'account.securityTitle' },
  { path: '/audit', textKey: 'account.auditTitle' },
];

/** admin 域导航路由表（§6 行 515-525 页面清单，顺序即侧边栏顺序）。 */
export const ADMIN_NAV_ROUTES: AppRoute[] = [
  { path: '/status', textKey: 'admin.navStatus' },
  { path: '/users', textKey: 'admin.navUsers' },
  { path: '/clients/sso', textKey: 'admin.navSsoClients' },
  { path: '/clients/oidc', textKey: 'admin.navOidcClients' },
  { path: '/providers', textKey: 'admin.navProviders' },
  { path: '/settings', textKey: 'admin.navSettings' },
  { path: '/audit', textKey: 'admin.navAudit' },
  { path: '/decode', textKey: 'admin.navDecode' },
];

/** Semi Nav `items` 的元素形态（结构对齐，零运行时 Semi import）。 */
export interface SemiNavItem {
  itemKey: string;
  text: string;
  icon?: React.ReactNode;
}

/** 由路由表派生 Semi Nav items：itemKey 即路由 path，text 渲染期 t() 求值。 */
export function toNavItems(
  routes: AppRoute[],
  iconMap?: Record<string, React.ReactNode>,
): SemiNavItem[] {
  return routes.map(({ path, textKey }) => ({
    itemKey: path,
    text: t(textKey),
    icon: iconMap?.[path],
  }));
}

/**
 * 高亮匹配：当前 hash 内路径命中的路由 path（精确或前缀段命中，详情页
 * 归列表项高亮，如 '/users/123' → '/users'）；未命中 → ''（不高亮）。
 */
export function matchActivePath(
  routes: AppRoute[],
  currentPath: string,
): string {
  const hit = routes.find(
    ({ path }) => currentPath === path || currentPath.startsWith(`${path}/`),
  );
  return hit?.path ?? '';
}
