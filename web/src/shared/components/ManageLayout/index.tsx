import { useState, type ReactNode } from 'react';
import { Breadcrumb, Layout, Nav } from '@douyinfe/semi-ui';
import { NavItems } from '@douyinfe/semi-ui/lib/es/navigation';
import { useLocation, useNavigate } from '@modern-js/runtime/router';
import { AppRoute, matchActivePath } from '../../app-ui/nav-routes';
import { t } from '../../i18n';
import styles from './index.module.less';

const { Sider, Header, Content } = Layout;

/** account 布局壳（§5 行 480）：Sider(Nav) + Header(面包屑 + 登出) + Content。 */
export function ManageLayout(props: {
  /** 归一后 al_root（登出跳转前缀，见 ./bootstrap）。 */
  alRoot: string;
  /** 顶栏面包屑层级（当前页标题链）。 */
  breadcrumb: string[];
  headerExtra?: ReactNode;
  children: ReactNode;
  navItems: NavItems;
  baseNavRoutes: AppRoute[];
}) {
  // 窄屏侧栏折叠（评审 P0-4(c)）：用 Semi 自带响应式能力——Sider
  // breakpoint 注册 matchMedia（xs = max-width 575px，Semi 内置断点表），
  // onBreakpoint 驱动 Nav isCollapsed；不自写断点体系。初始窄屏由
  // registerMediaQuery 的 callInInit 立即回调覆盖，state 初值即正确。
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
          header={{ text: t('account.appTitle') }}
        />
      </Sider>
      <Layout>
        <Header className={styles.header}>
          <Breadcrumb routes={[...props.breadcrumb]} />
          <div>{props.headerExtra}</div>
        </Header>
        <Content className={styles.content}>{props.children}</Content>
      </Layout>
    </Layout>
  );
}
