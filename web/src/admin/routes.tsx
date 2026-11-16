/**
 * admin 路由（docs/前端架构.md §6 行 501/505；接口文档 §8 行 1422 `/admin`）：
 * 混合路由形态——`HashRouter` 挂 entry 顶层，本模块只产
 * `RouteObject[]` 路由表，取代原「路径常量 + 手写 pathname 正则」的分派
 *（改造后禁止手写 pathname 正则匹配）。
 *
 * 路由表（path 全在 hash 内，如 `/admin#/providers`）：
 * - 列表八页：路径取自 ADMIN_NAV_ROUTES 单一来源（adminNavPath 按键取用，
 *   与侧边栏 Nav 高亮同源，§9 第 24 条）；
 * - 参数页：`/providers/:key/edit`（ProviderEditPage，useParams 取 key——
 *   react-router 参数已解码，等价原 decodeURIComponent）；用户详情已改为
 *   列表页内 SideSheet，不再有独立 URL；
 * - 新建页 `/providers/new`（PROVIDER_NEW_PATH，paths.ts 唯一常量）；
 * - `path:'*'` 兜底：带布局 Semi Empty + 返回首页 Link
 *   （SPA 内跳转，不再整页刷新）。
 *
 * 401 链路：读路径经 `requestOptions` 集中 `onError` 跳登录；
 * Modal 写路径与 `DecodePage` 保留内联 `location.replace(loginUrl(...))`。
 * bootstrap 无 methods 必需校验（§8：methods 仅 login 必填），路由层不发请求。
 */
import { Empty } from '@douyinfe/semi-ui';
import {
  Link,
  Outlet,
  useRoutes,
  type RouteObject,
} from '@modern-js/runtime/router';
import type { ReactNode } from 'react';
import { t } from '../shared/i18n';
import { loadAdminBootstrap } from './bootstrap';
import { AdminLayout } from './layout/AdminLayout';
import { AuditPage } from './pages/AuditPage';
import { DecodePage } from './pages/DecodePage';
import { OidcClientsPage } from './pages/OidcClientsPage';
import { ProvidersPage } from './pages/ProvidersPage';
import { SettingsPage } from './pages/SettingsPage';
import { SsoClientsPage } from './pages/SsoClientsPage';
import { StatusPage } from './pages/StatusPage';
import { TemplatesPage } from './pages/TemplatesPage';
import { UsersPage } from './pages/UsersPage';
import { adminNavPath } from './paths';

/** 兜底页：Semi Empty + 返回管理首页（SPA 内 Link）。 */
function NotFoundPage(): ReactNode {
  return (
    <Empty description={t('admin.routeNotFound')}>
      <Link to={adminNavPath('admin.navProviders')}>
        {t('admin.backToHome')}
      </Link>
    </Empty>
  );
}

/** admin 应用根：bootstrap 读注入变量（al_root / static_base）→ 路由表分派。 */
export function AdminApp(): ReactNode {
  const boot = loadAdminBootstrap();
  const alRoot = boot.alRoot;
  const rootTitle = t('admin.rootTitle');
  // 列表页面包屑二级（SSO/OIDC 客户端三级，中间层 admin.navClients 沿用原口径）。
  // 子路由只声明页面 + handle.breadcrumb；布局只在下方父路由声明一次。
  // 非 data router 下 useMatches 不可用：把子路由表交给布局按 location 读
  // handle.breadcrumb；getRoutes 延迟求值，规避路由表构造期引用自身的 TDZ。
  const getRoutes = () => routes;
  const routes: RouteObject[] = [
    {
      element: (
        <AdminLayout alRoot={alRoot} getRoutes={getRoutes}>
          <Outlet />
        </AdminLayout>
      ),
      children: [
        {
          path: adminNavPath('admin.navProviders'),
          element: <ProvidersPage alRoot={alRoot} />,
          handle: { breadcrumb: [rootTitle, t('admin.navProviders')] },
        },
        {
          path: adminNavPath('admin.navUsers'),
          element: <UsersPage alRoot={alRoot} />,
          handle: { breadcrumb: [rootTitle, t('admin.navUsers')] },
        },
        {
          path: adminNavPath('admin.navSsoClients'),
          element: <SsoClientsPage alRoot={alRoot} />,
          handle: {
            breadcrumb: [
              rootTitle,
              t('admin.navClients'),
              t('admin.navSsoClients'),
            ],
          },
        },
        {
          path: adminNavPath('admin.navOidcClients'),
          element: <OidcClientsPage alRoot={alRoot} />,
          handle: {
            breadcrumb: [
              rootTitle,
              t('admin.navClients'),
              t('admin.navOidcClients'),
            ],
          },
        },
        {
          path: adminNavPath('admin.navTemplates'),
          element: <TemplatesPage alRoot={alRoot} />,
          handle: { breadcrumb: [rootTitle, t('admin.navTemplates')] },
        },
        {
          path: adminNavPath('admin.navSettings'),
          element: <SettingsPage alRoot={alRoot} />,
          handle: { breadcrumb: [rootTitle, t('admin.navSettings')] },
        },
        {
          path: adminNavPath('admin.navAudit'),
          element: <AuditPage alRoot={alRoot} />,
          handle: { breadcrumb: [rootTitle, t('admin.navAudit')] },
        },
        {
          path: adminNavPath('admin.navStatus'),
          element: <StatusPage alRoot={alRoot} />,
          handle: { breadcrumb: [rootTitle, t('admin.navStatus')] },
        },
        {
          path: adminNavPath('admin.navDecode'),
          element: <DecodePage alRoot={alRoot} />,
          handle: { breadcrumb: [rootTitle, t('admin.navDecode')] },
        },
        // path:'*' 兜底（带布局的不存在页）。
        {
          path: '*',
          element: <NotFoundPage />,
          handle: { breadcrumb: [rootTitle] },
        },
      ],
    },
  ];
  return useRoutes(routes);
}
