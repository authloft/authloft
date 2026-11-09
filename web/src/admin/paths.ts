/**
 * admin 域内路由路径构造（混合路由形态：path 全在 hash 内，
 * 如 `/admin#/providers`）——链接拼装的唯一出口：
 * - 列表页路径单一来源在 shared/app-ui/nav-routes.ts 的 ADMIN_NAV_ROUTES
 *   （Nav 高亮与路由表同源，§9 第 24 条禁第二份字面量），经 adminNavPath
 *   按键取用；
 * - 参数页 / 新建页不在导航表内，由本模块常量与构造函数承载；参数段一律
 *   encodeURIComponent（修模板字符串拼接不编码的隐患）。
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

/** 用户详情页路径（§6 行 518）：id 为 int64，十进制数字段无需编码。 */
export function userDetailPath(id: bigint): string {
  return `/users/${id.toString()}`;
}
