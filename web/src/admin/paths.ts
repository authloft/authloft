/**
 * admin 域内路由路径构造（混合路由形态：path 全在 hash 内，
 * 如 `/admin#/providers`）——链接拼装的唯一出口：
 * - 列表页路径单一来源在 shared/app-ui/nav-routes.ts 的 ADMIN_NAV_ROUTES
 *   （Nav 高亮与路由表同源，§9 第 24 条禁第二份字面量），经 adminNavPath
 *   按键取用；
 * - 本模块只提供列表页路径按键取用；详情已改为列表页内 SideSheet，
 *   不再有独立 URL 构造函数。
 */
import { ADMIN_NAV_ROUTES } from '../shared/app-ui/nav-routes';
import type { I18nKey } from '../shared/i18n';

/**
 * 列表页路径（ADMIN_NAV_ROUTES 单一来源；textKey 唯一键，未命中 = 导航表
 * 损坏，落 '' 由路由表 path:'*' 兜底页承接）。
 */
export function adminNavPath(textKey: I18nKey): string {
  return (
    ADMIN_NAV_ROUTES.find((route) => route.textKey === textKey)?.path ?? ''
  );
}
