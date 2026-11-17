/**
 * account 路由（docs/前端架构.md §5）：HashRouter 路由表——
 * 布局作为无 path 父路由只声明一次，子路由只放页面内容：
 * `/`（index）→ ProfilePage、`/security` → SecurityPage、
 * `/audit` → AuditPage、`path:'*'` → 兜底不存在页
 *（形态直迁：Semi Empty + 返回链接，链接改为 hash 内 `#/`）。
 * 面包屑由子路由 handle.breadcrumb 声明，布局经 matchRoutes 读取。
 *
 * HashRouter 挂在 entry 顶层（框架挂载点；测试以 MemoryRouter 注入
 * 初始路径，模式无关）；禁手写 pathname 比较 / 正则匹配（§9 第 24 条），
 * Nav 项与高亮由 ACCOUNT_NAV_ROUTES 派生（shared/app-ui/nav-routes.ts，
 * 禁第二份路径字面量）；bootstrap 读注入变量（al_root / static_base）。
 * 文案经 shared/i18n（account.* 域键）。
 */
import { Empty } from '@douyinfe/semi-ui';
import {
  Outlet,
  Route,
  Routes,
  createRoutesFromChildren,
  type RouteObject,
} from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { requestOptions } from '../shared/hooks/requestOptions';
import { t } from '../shared/i18n';
import { getMyPermissions } from './api';
import { loadAccountBootstrap } from './bootstrap';
import { AppLayout } from './layout/AppLayout';
import { AuditPage } from './pages/AuditPage';
import { ProfilePage } from './pages/ProfilePage';
import { SecurityPage } from './pages/SecurityPage';

/** account 应用根：bootstrap 读注入变量 → 取自身权限点 → 路由表渲染（HashRouter 在 entry）。 */
export function AccountApp() {
  const boot = loadAccountBootstrap();
  // 自身权限点只决定右上跨端入口可见性（接口文档 §3.9）；401 由集中
  // onError 跳登录，不在此另写分流（前端架构 §5）。
  const { data } = useRequest(
    getMyPermissions,
    requestOptions({ toast: false }),
  );
  const permissions = data?.permissions;
  // 子路由只声明页面 + 面包屑 handle（文案渲染期求值，CODE_GUIDE §4.6）；
  // 布局只在下方父路由声明一次，子页面不再各自重复包裹 AppLayout。
  const childRoutes = (
    <>
      <Route
        index
        handle={{
          breadcrumb: [t('account.personalCenter'), t('account.profileTitle')],
        }}
        element={<ProfilePage />}
      />
      <Route
        path="/security"
        handle={{
          breadcrumb: [t('account.personalCenter'), t('account.securityTitle')],
        }}
        element={<SecurityPage />}
      />
      <Route
        path="/audit"
        handle={{
          breadcrumb: [t('account.personalCenter'), t('account.auditTitle')],
        }}
        element={<AuditPage />}
      />
      <Route
        path="*"
        handle={{ breadcrumb: [t('account.personalCenter')] }}
        element={
          <Empty description={t('account.routeNotFound')}>
            <a href="#/">{t('account.backToHome')}</a>
          </Empty>
        }
      />
    </>
  );
  // 非 data router 下 useMatches 不可用：把子路由表交给布局，由布局按
  // 当前 location 经 matchRoutes 读取命中子路由的 handle.breadcrumb。
  const routes = createRoutesFromChildren(childRoutes) as RouteObject[];
  return (
    <Routes>
      <Route
        element={
          <AppLayout
            alRoot={boot.alRoot}
            permissions={permissions}
            routes={routes}
          >
            <Outlet />
          </AppLayout>
        }
      >
        {childRoutes}
      </Route>
    </Routes>
  );
}
