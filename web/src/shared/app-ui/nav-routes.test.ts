// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化落地后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import {
  ACCOUNT_NAV_ROUTES,
  ADMIN_NAV_ROUTES,
  matchActivePath,
  toNavItems,
} from './nav-routes';

/**
 * nav-routes.ts 测试：导航项结构单一来源的派生工具——
 * toNavItems（itemKey=path、text 渲染期求值）与 matchActivePath（精确 +
 * 前缀段高亮）。零 Semi 依赖，node 可测。
 */

describe('toNavItems（路由表 → Semi Nav items 派生）', () => {
  test('itemKey 即路由 path，text 经 i18n 求值（默认 zh-CN）', () => {
    expect(toNavItems(ACCOUNT_NAV_ROUTES)).toEqual([
      { itemKey: '/', text: '个人资料' },
      { itemKey: '/security', text: '安全中心' },
      { itemKey: '/audit', text: '登录日志' },
    ]);
  });
});

describe('matchActivePath（高亮匹配：精确 + 前缀段）', () => {
  test('精确命中', () => {
    expect(matchActivePath(ACCOUNT_NAV_ROUTES, '/security')).toBe('/security');
  });

  test('详情页前缀段归列表项（/users/123 → /users）', () => {
    expect(matchActivePath(ADMIN_NAV_ROUTES, '/users/123')).toBe('/users');
    expect(matchActivePath(ADMIN_NAV_ROUTES, '/providers/wechat_mp/edit')).toBe(
      '/providers',
    );
  });

  test('非路径段边界不误命中（/usersx 不算 /users 命中）', () => {
    expect(matchActivePath(ADMIN_NAV_ROUTES, '/usersx')).toBe('');
  });
});
