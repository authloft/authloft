// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, describe, expect, test, rs } from 'rstack/test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from '@modern-js/runtime/router';
import { ManageLayout, type HeaderMenu } from './index';
import {
  ACCOUNT_NAV_ROUTES,
  ADMIN_NAV_ROUTES,
  toNavItems,
} from '../nav-routes';

// classic JSX runtime：测试链 JSX 产物引用全局 React；Sider breakpoint 在
// SSR 下可能探测 matchMedia，补一个最小 stub（effects 不执行，不求交互）。
rs.stubGlobal('React', React);
rs.stubGlobal('window', {
  location: { pathname: '/account' },
  matchMedia: () => ({
    matches: false,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
  }),
});

afterAll(() => {
  rs.unstubAllGlobals();
});

/**
 * 右上 Dropdown 的弹出 menu 走 portal，SSR 不输出浮层 DOM，故仅豁免对
 * 菜单项的 DOM 点击断言；Sider Nav items 的文案是内联静态渲染结果，按
 * 组件渲染断言口径（docs/CODE_GUIDE.md §5.2）仍须对其输出做断言。
 */
const menu: HeaderMenu = [{ node: 'item', name: '登出', onClick: () => {} }];

function render(props: {
  navHeader: string;
  headerLabel: React.ReactNode;
  navItems: ReturnType<typeof toNavItems>;
  baseNavRoutes: typeof ACCOUNT_NAV_ROUTES;
  breadcrumb: string[];
}): string {
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={['/']}>
      <ManageLayout
        breadcrumb={props.breadcrumb}
        navItems={props.navItems}
        baseNavRoutes={props.baseNavRoutes}
        navHeader={props.navHeader}
        headerLabel={props.headerLabel}
        headerMenu={menu}
      >
        <div id="content-marker">页面内容</div>
      </ManageLayout>
    </MemoryRouter>,
  );
}

describe('ManageLayout 双端共用基础布局壳（SSR 静态渲染）', () => {
  test('account 端：navHeader / headerLabel / navItems / 内容 / 右上 Dropdown 容器各自渲染', () => {
    const html = render({
      navHeader: 'Authloft 用户中心',
      headerLabel: <span id="trigger-account">个人中心</span>,
      navItems: toNavItems(ACCOUNT_NAV_ROUTES),
      baseNavRoutes: ACCOUNT_NAV_ROUTES,
      breadcrumb: ['个人中心', '个人资料'],
    });
    expect(html).toContain('Authloft 用户中心');
    expect(html).toContain('id="trigger-account"');
    expect(html).toContain('个人资料');
    expect(html).toContain('页面内容');
    // Dropdown 容器恒渲染：Semi 给 trigger 注入 aria-haspopup（浮层走 portal，SSR 不输出）。
    expect(html).toContain('aria-haspopup="true"');
    // Nav 独有文案不与 breadcrumb / navHeader / headerLabel / children 重叠：
    // 正向断言本端 items 已渲染，交叉反向断言未串到另一端菜单。
    expect(html).toContain('安全中心');
    expect(html).toContain('登录日志');
    expect(html).not.toContain('提供商');
    expect(html).not.toContain('监控');
  });

  test('admin 端：另一组 navHeader / headerLabel / navItems 各自渲染，不串 account 文案', () => {
    const html = render({
      navHeader: 'Authloft 管理',
      headerLabel: <span id="trigger-admin">管理员</span>,
      navItems: toNavItems(ADMIN_NAV_ROUTES),
      baseNavRoutes: ADMIN_NAV_ROUTES,
      breadcrumb: ['管理后台', '用户'],
    });
    expect(html).toContain('Authloft 管理');
    expect(html).toContain('id="trigger-admin"');
    expect(html).toContain('用户');
    expect(html).toContain('页面内容');
    // Dropdown 容器恒渲染：Semi 给 trigger 注入 aria-haspopup（浮层走 portal，SSR 不输出）。
    expect(html).toContain('aria-haspopup="true"');
    expect(html).not.toContain('Authloft 用户中心');
    expect(html).not.toContain('id="trigger-account"');
    // 同 account：Nav 独有文案正向 + 交叉反向。
    expect(html).toContain('提供商');
    expect(html).toContain('监控');
    expect(html).not.toContain('安全中心');
    expect(html).not.toContain('登录日志');
  });
});
