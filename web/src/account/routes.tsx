/**
 * account 路由（docs/前端架构.md §5 行 478；接口文档 §8 行 1421 `/account/**`）：
 * `/account/profile` → AppLayout 包 ProfilePage；`/account/security` /
 * `/account/audit` 已规划未交付，点入走兜底提示，
 * 交付后逐项长入 NAV_ITEMS（AppLayout）与本路由表。
 *
 * 沿 login/routes.tsx 模式：零第三方路由库（§1.6 行 110），
 * disableMount 自挂载，极简 pathname 匹配；bootstrap 无 methods 必需校验
 * （§8：methods 仅 login 必填），故无登录端的错误态分支。
 */
import { loadAccountBootstrap } from './bootstrap';
import { AppLayout } from './layout/AppLayout';
import { ProfilePage } from './pages/ProfilePage';

/** 个人资料路由（§5 行 478）。 */
const PROFILE_PATH = '/account/profile';

/** 未注册路由兜底文案——无 i18n 键，最简中文字面量（归 i18n 收口卡）。 */
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
  return <p role="status">{ROUTE_NOT_FOUND_TEXT}</p>;
}
