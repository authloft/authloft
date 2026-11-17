/**
 * account / admin 共用基础布局壳（docs/前端架构.md §3.3）：Sider(Nav) +
 * Header(面包屑 + 右上 Dropdown 容器) + Content。Nav 项、Nav 标题、
 * Dropdown 菜单与 trigger 全部经 props 注入；本壳自身不发请求、不构造
 * 业务菜单、不 import 任何 entry（CODE_GUIDE §4.1 第 13 条）。GetMe 数据门
 * 与 404 掩护留在 admin 包装层，跨端入口可见性所需权限点由 account
 * 包装层注入；本壳只负责结构、高亮、折叠与 hash 内路由导航。
 */
import { useState, type ComponentProps, type ReactNode } from 'react';
import { Breadcrumb, Dropdown, Layout, Nav } from '@douyinfe/semi-ui';
// NavItems 类型导入例外：大包入口（lib/es/index.d.ts）仅转出组件值，
// 未转出该类型——经官方 exports 白名单内的 navigation 子路径做纯类型导入
// （import type，编译期擦除、零运行时痕迹；CODE_GUIDE §4.1 第 21 条）。
import type { NavItems } from '@douyinfe/semi-ui/lib/es/navigation';
import { useLocation, useNavigate } from '@modern-js/runtime/router';
import { type AppRoute, matchActivePath } from '../nav-routes';
import styles from './index.module.less';

const { Sider, Header, Content } = Layout;

/** 右上 Dropdown 菜单项数组（形态对齐 Semi Dropdown 的 menu 入参）。 */
export type HeaderMenu = NonNullable<ComponentProps<typeof Dropdown>['menu']>;

/** 双端共用布局壳：菜单与标题均由调用方经 props 决定，本壳不产业务文案。 */
export function ManageLayout(props: {
  /** 顶栏面包屑层级（当前页标题链）。 */
  breadcrumb: string[];
  /** 右上 Dropdown 菜单项（由各端包装层构造）。 */
  headerMenu: HeaderMenu;
  /** 右上 Dropdown trigger 显示内容。 */
  headerLabel: ReactNode;
  /** Sider Nav 标题（各端域标题经 props 注入）。 */
  navHeader: string;
  navItems: NavItems;
  baseNavRoutes: AppRoute[];
  children: ReactNode;
}) {
  // 窄屏侧栏折叠：用 Semi 自带响应式能力——Sider breakpoint 注册
  // matchMedia，onBreakpoint 驱动 Nav isCollapsed；不自写断点体系。
  const [navCollapsed, setNavCollapsed] = useState(false);
  // 高亮与导航经 router——location.pathname 为 hash 内路径。
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <Layout className={styles.shell}>
      <Sider
        breakpoint={['xs']}
        onBreakpoint={(_screen, matches) => setNavCollapsed(matches)}
      >
        <Nav
          className={styles.nav}
          isCollapsed={navCollapsed}
          items={props.navItems}
          selectedKeys={[
            matchActivePath(props.baseNavRoutes, location.pathname),
          ]}
          onClick={({ itemKey }) => {
            if (typeof itemKey === 'string') {
              // itemKey 即 hash 内路由路径：SPA 导航（不整页跳转）。
              navigate(itemKey);
            }
          }}
          header={{ text: props.navHeader }}
        />
      </Sider>
      <Layout>
        <Header className={styles.header}>
          <Breadcrumb compact={false} routes={[...props.breadcrumb]} />
          <Dropdown menu={props.headerMenu} position="bottomRight">
            {props.headerLabel}
          </Dropdown>
        </Header>
        <Content className={styles.content}>
          <div className={styles.contentInner}>{props.children}</div>
        </Content>
      </Layout>
    </Layout>
  );
}
