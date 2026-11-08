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
 *   react-router 参数已解码，等价原 decodeURIComponent）、`/users/:id`
 *   （UserDetailPage，id 为 int64，段内限定十进制数字，非数字落兜底）；
 * - 新建页 `/providers/new`（PROVIDER_NEW_PATH，paths.ts 唯一常量）；
 * - `path:'*'` 兜底：带布局 Semi Empty + 返回首页 Link
 *   （SPA 内跳转，不再整页刷新）。
 *
 * 401 链路：读路径经 `requestOptions` 集中 `onError` 跳登录；
 * Modal 写路径与 `DecodePage` 保留内联 `location.replace(loginUrl(...))`。
 * bootstrap 无 methods 必需校验（§8：methods 仅 login 必填），路由层不发请求。
 */
import type { ReactNode } from 'react';
import { Empty } from '@douyinfe/semi-ui';
import { Link, useParams, useRoutes, type RouteObject } from '@modern-js/runtime/router';
import { t } from '../shared/i18n';
import { loadAdminBootstrap } from './bootstrap';
import { AdminLayout } from './layout/AdminLayout';
import { AuditPage } from './pages/AuditPage';
import { DecodePage } from './pages/DecodePage';
import { OidcClientsPage } from './pages/OidcClientsPage';
import { ProviderEditPage } from './pages/ProviderEditPage';
import { ProvidersPage } from './pages/ProvidersPage';
import { SsoClientsPage } from './pages/SsoClientsPage';
import { SettingsPage } from './pages/SettingsPage';
import { StatusPage } from './pages/StatusPage';
import { UserDetailPage } from './pages/UserDetailPage';
import { UsersPage } from './pages/UsersPage';
import { PROVIDER_NEW_PATH, adminNavPath } from './paths';

/** 用户详情路由模式（§6 行 518；段内数字校验在 UserDetailRoute，见下）。 */
const USER_DETAIL_ROUTE = '/users/:id';

/** 提供商编辑路由模式（§6 行 516：provider_key 单段）。 */
const PROVIDER_EDIT_ROUTE = '/providers/:key/edit';

/** 兜底页：Semi Empty + 返回管理首页（SPA 内 Link）。 */
function NotFoundPage(): ReactNode {
  return (
    <Empty description={t('admin.routeNotFound')}>
      <Link to={adminNavPath('admin.navProviders')}>{t('admin.backToHome')}</Link>
    </Empty>
  );
}

/** 提供商新建 / 编辑路由（useParams 取 key；缺省 = 新建）。 */
function ProviderEditRoute(props: { readonly alRoot: string }): ReactNode {
  const { key } = useParams();
  return (
    <AdminLayout
      alRoot={props.alRoot}
      breadcrumb={[
        t('admin.rootTitle'),
        t('admin.navProviders'),
        t(key === undefined ? 'admin.newAction' : 'admin.editAction'),
      ]}
    >
      <ProviderEditPage alRoot={props.alRoot} providerKey={key} />
    </AdminLayout>
  );
}

/** 用户详情路由（useParams 取 id；非十进制数字段落兜底页——原 \d+ 正则口径）。 */
function UserDetailRoute(props: { readonly alRoot: string }): ReactNode {
  const { id } = useParams();
  if (id === undefined || !/^\d+$/.test(id)) {
    return (
      <AdminLayout alRoot={props.alRoot} breadcrumb={[t('admin.rootTitle')]}>
        <NotFoundPage />
      </AdminLayout>
    );
  }
  return (
    <AdminLayout
      alRoot={props.alRoot}
      breadcrumb={[t('admin.rootTitle'), t('admin.navUsers'), t('admin.userDetailTitle')]}
    >
      <UserDetailPage alRoot={props.alRoot} userId={BigInt(id)} />
    </AdminLayout>
  );
}

/** admin 应用根：bootstrap 读注入变量（al_root / static_base）→ 路由表分派。 */
export function AdminApp(): ReactNode {
  const boot = loadAdminBootstrap();
  const alRoot = boot.alRoot;
  const rootTitle = t('admin.rootTitle');
  // 列表页面包屑二级（SSO/OIDC 客户端三级，中间层 admin.navClients 沿用原口径）。
  const routes: RouteObject[] = [
    {
      path: adminNavPath('admin.navProviders'),
      element: (
        <AdminLayout alRoot={alRoot} breadcrumb={[rootTitle, t('admin.navProviders')]}>
          <ProvidersPage alRoot={alRoot} />
        </AdminLayout>
      ),
    },
    { path: PROVIDER_NEW_PATH, element: <ProviderEditRoute alRoot={alRoot} /> },
    { path: PROVIDER_EDIT_ROUTE, element: <ProviderEditRoute alRoot={alRoot} /> },
    {
      path: adminNavPath('admin.navUsers'),
      element: (
        <AdminLayout alRoot={alRoot} breadcrumb={[rootTitle, t('admin.navUsers')]}>
          <UsersPage alRoot={alRoot} />
        </AdminLayout>
      ),
    },
    { path: USER_DETAIL_ROUTE, element: <UserDetailRoute alRoot={alRoot} /> },
    {
      path: adminNavPath('admin.navSsoClients'),
      element: (
        <AdminLayout
          alRoot={alRoot}
          breadcrumb={[rootTitle, t('admin.navClients'), t('admin.navSsoClients')]}
        >
          <SsoClientsPage alRoot={alRoot} />
        </AdminLayout>
      ),
    },
    {
      path: adminNavPath('admin.navOidcClients'),
      element: (
        <AdminLayout
          alRoot={alRoot}
          breadcrumb={[rootTitle, t('admin.navClients'), t('admin.navOidcClients')]}
        >
          <OidcClientsPage alRoot={alRoot} />
        </AdminLayout>
      ),
    },
    {
      path: adminNavPath('admin.navSettings'),
      element: (
        <AdminLayout alRoot={alRoot} breadcrumb={[rootTitle, t('admin.navSettings')]}>
          <SettingsPage alRoot={alRoot} />
        </AdminLayout>
      ),
    },
    {
      path: adminNavPath('admin.navAudit'),
      element: (
        <AdminLayout alRoot={alRoot} breadcrumb={[rootTitle, t('admin.navAudit')]}>
          <AuditPage alRoot={alRoot} />
        </AdminLayout>
      ),
    },
    {
      path: adminNavPath('admin.navStatus'),
      element: (
        <AdminLayout alRoot={alRoot} breadcrumb={[rootTitle, t('admin.navStatus')]}>
          <StatusPage alRoot={alRoot} />
        </AdminLayout>
      ),
    },
    {
      path: adminNavPath('admin.navDecode'),
      element: (
        <AdminLayout alRoot={alRoot} breadcrumb={[rootTitle, t('admin.navDecode')]}>
          <DecodePage alRoot={alRoot} />
        </AdminLayout>
      ),
    },
    // path:'*' 兜底（带布局的不存在页）。
    {
      path: '*',
      element: (
        <AdminLayout alRoot={alRoot} breadcrumb={[rootTitle]}>
          <NotFoundPage />
        </AdminLayout>
      ),
    },
  ];
  return useRoutes(routes);
}
