/**
 * account 路由（docs/前端架构.md §5 行 478；接口文档 §8 行 1421 `/account/**`）：
 * `/account/profile` → AppLayout 包 ProfilePage；`/account/security` →
 * AppLayout 包 SecurityPage；`/account/audit` → AppLayout 包
 * AuditPage。
 *
 * 沿 login/routes.tsx 模式：零第三方路由库（§1.6 行 110），
 * disableMount 自挂载，极简 pathname 匹配；bootstrap 无 methods 必需校验
 * （§8：methods 仅 login 必填），故无登录端的错误态分支。
 */
import { loadAccountBootstrap } from './bootstrap';
import { AppLayout } from './layout/AppLayout';
import { AuditPage } from './pages/AuditPage';
import { ProfilePage } from './pages/ProfilePage';
import { SecurityPage } from './pages/SecurityPage';

/** 个人资料路由（§5 行 478）。 */
const PROFILE_PATH = '/account/profile';

/** 安全中心路由（§5 行 478）。 */
const SECURITY_PATH = '/account/security';

/** 登录日志路由（§5 行 478）。 */
const AUDIT_PATH = '/account/audit';

/** 未注册路由兜底文案——无 i18n 键，最简中文字面量（归后续 i18n 实现）。 */
const ROUTE_NOT_FOUND_TEXT = '页面不存在';

/** account 应用根：bootstrap 读注入变量（al_root / static_base）→ 路由分派。 */
export function AccountApp() {
  const boot = loadAccountBootstrap();
  // 尾斜杠归一（`/account/profile/` 与 `/account/profile` 同页；根路径归一为空串不匹配）。
  const path = window.location.pathname.replace(/\/+$/, '');
  if (path === PROFILE_PATH) {
    return (
      <AppLayout
        alRoot={boot.alRoot}
        activeKey={PROFILE_PATH}
        breadcrumb={['个人中心', '个人资料']}
      >
        <ProfilePage />
      </AppLayout>
    );
  }
  if (path === SECURITY_PATH) {
    return (
      <AppLayout
        alRoot={boot.alRoot}
        activeKey={SECURITY_PATH}
        breadcrumb={['个人中心', '安全中心']}
      >
        <SecurityPage />
      </AppLayout>
    );
  }
  if (path === AUDIT_PATH) {
    return (
      <AppLayout
        alRoot={boot.alRoot}
        activeKey={AUDIT_PATH}
        breadcrumb={['个人中心', '登录日志']}
      >
        <AuditPage />
      </AppLayout>
    );
  }
  return <p role="status">{ROUTE_NOT_FOUND_TEXT}</p>;
}
