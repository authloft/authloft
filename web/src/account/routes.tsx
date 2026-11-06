/**
 * account 路由（docs/前端架构.md §5 行 504）：HashRouter 路由表——
 * `/account#/profile` → AppLayout 包 ProfilePage；`/account#/security` →
 * SecurityPage；`/account#/audit` → AuditPage；`path:'*'` → 兜底不存在页
 *（形态直迁：Semi Empty + 返回链接，链接改为 hash 内 `#/profile`）。
 *
 * HashRouter 挂在 entry 顶层（框架挂载点；测试以 MemoryRouter 注入
 * 初始路径，模式无关）；禁手写 pathname 比较 / 正则匹配（§9 第 24 条），
 * Nav 项与高亮由 ACCOUNT_NAV_ROUTES 派生（shared/app-ui/nav-routes.ts，
 * 禁第二份路径字面量）；bootstrap 读注入变量（al_root / static_base）。
 * 文案经 shared/i18n（account.* 域键）。
 */
import { Empty } from '@douyinfe/semi-ui-19';
import { Route, Routes } from '@modern-js/runtime/router';
import { t } from '../shared/i18n';
import { loadAccountBootstrap } from './bootstrap';
import { AppLayout } from './layout/AppLayout';
import { AuditPage } from './pages/AuditPage';
import { ProfilePage } from './pages/ProfilePage';
import { SecurityPage } from './pages/SecurityPage';

/** account 应用根：bootstrap 读注入变量 → 路由表渲染（HashRouter 在 entry）。 */
export function AccountApp() {
  const boot = loadAccountBootstrap();
  return (
    <Routes>
      <Route
        path="/profile"
        element={
          <AppLayout
            alRoot={boot.alRoot}
            breadcrumb={[t('account.personalCenter'), t('account.profileTitle')]}
          >
            <ProfilePage />
          </AppLayout>
        }
      />
      <Route
        path="/security"
        element={
          <AppLayout
            alRoot={boot.alRoot}
            breadcrumb={[t('account.personalCenter'), t('account.securityTitle')]}
          >
            <SecurityPage />
          </AppLayout>
        }
      />
      <Route
        path="/audit"
        element={
          <AppLayout
            alRoot={boot.alRoot}
            breadcrumb={[t('account.personalCenter'), t('account.auditTitle')]}
          >
            <AuditPage />
          </AppLayout>
        }
      />
      {/* path:'*' 兜底：带布局的不存在页，返回链接走 hash
          内路径（SPA 导航，不整页刷新）。 */}
      <Route
        path="*"
        element={
          <AppLayout alRoot={boot.alRoot} breadcrumb={[t('account.personalCenter')]}>
            <Empty description={t('account.routeNotFound')}>
              <a href="#/profile">{t('account.backToHome')}</a>
            </Empty>
          </AppLayout>
        }
      />
    </Routes>
  );
}
