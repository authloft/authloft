/**
 * admin 路由（docs/前端架构.md §6 行 501/505；接口文档 §8 行 1422 `/admin/**`）：
 * 极简 pathname 匹配——ProvidersPage 长入 /admin/providers（§6 行 515）；
 * ProviderEditPage 长入 /admin/providers/new 新建 +
 * /admin/providers/{provider_key}/edit 编辑（§6 行 516）；UsersPage 长入
 * /admin/users（§6 行 517）+ UserDetailPage 长入 /admin/users/{id}
 * （§6 行 518——id 为 int64，路径段限定十进制数字）；SsoClientsPage 长入
 * /admin/clients/sso + OidcClientsPage 长入 /admin/clients/oidc（§6 行 519）；
 * SettingsPage 长入 /admin/settings（§6 行 520）；工具三页长入——AuditPage
 * （/admin/audit，§6 行 523）+ StatusPage（/admin/status，§6 行 524）
 * + DecodePage（/admin/decode，§6 行 525）；其余 `/admin/**` 一律 AdminLayout
 * 包裹占位页，不匹配前缀 → 页面不存在。
 *
 * 沿 account/routes.tsx 模式：零第三方路由库（§1.6 行 110），
 * disableMount 自挂载，极简 pathname 匹配；bootstrap 无 methods 必需校验
 * （§8：methods 仅 login 必填）。401/404 分流在 AdminLayout（GetMe 失败时
 * 处理），路由层不发请求。
 */
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

/** /admin 前缀（接口文档 §8 行 1422：管理端 SPA 空壳）。 */
const ADMIN_PREFIX = '/admin';

/** 提供方列表页路径（§6 行 515；侧边栏 NAV_ITEMS 同约定 itemKey 即路径）。 */
const PROVIDERS_PATH = '/admin/providers';

/** 提供方新建页路径（§6 行 516）。 */
const PROVIDER_NEW_PATH = '/admin/providers/new';

/** 提供方编辑页路径模式（§6 行 516：provider_key 单段，URL 编码段安全）。 */
const PROVIDER_EDIT_PATTERN = /^\/admin\/providers\/([^/]+)\/edit$/;

/** 用户列表页路径（§6 行 517；NAV_ITEMS itemKey 同约定）。 */
const USERS_PATH = '/admin/users';

/** 用户详情页路径模式（§6 行 518：id 为 int64，路径段限定十进制数字）。 */
const USER_DETAIL_PATTERN = /^\/admin\/users\/(\d+)$/;

/** SSO 客户端列表页路径（§6 行 519；侧边栏 NAV_ITEMS itemKey 同约定）。 */
const SSO_CLIENTS_PATH = '/admin/clients/sso';

/** OIDC 客户端列表页路径（§6 行 519）。 */
const OIDC_CLIENTS_PATH = '/admin/clients/oidc';

/** 系统设置页路径（§6 行 520；NAV_ITEMS itemKey 同约定 itemKey 即路径）。 */
const SETTINGS_PATH = '/admin/settings';

/** 事件日志页路径（§6 行 523；NAV_ITEMS itemKey 同约定）。 */
const AUDIT_PATH = '/admin/audit';

/** 监控页路径（§6 行 524；NAV_ITEMS itemKey 同约定）。 */
const STATUS_PATH = '/admin/status';

/** 解码工具页路径（§6 行 525；NAV_ITEMS itemKey 同约定）。 */
const DECODE_PATH = '/admin/decode';

/** 未注册路由兜底文案——无 i18n 键，最简中文字面量（归后续 i18n 实现）。 */
const ROUTE_NOT_FOUND_TEXT = '页面不存在';

/** 占位页文案（业务页面归后续实现逐项长入）。 */
const PLACEHOLDER_TEXT = '管理后台';

/** admin 应用根：bootstrap 读注入变量（al_root / static_base）→ 路由分派。 */
export function AdminApp() {
  const boot = loadAdminBootstrap();
  // 尾斜杠归一（`/admin/` 与 `/admin` 同页；根路径归一为空串不匹配前缀）。
  const path = window.location.pathname.replace(/\/+$/, '');
  if (path === PROVIDERS_PATH) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={PROVIDERS_PATH}
        breadcrumb={['管理后台', '提供方']}
      >
        <ProvidersPage alRoot={boot.alRoot} />
      </AdminLayout>
    );
  }
  if (path === PROVIDER_NEW_PATH) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={PROVIDERS_PATH}
        breadcrumb={['管理后台', '提供方', '新建']}
      >
        <ProviderEditPage alRoot={boot.alRoot} />
      </AdminLayout>
    );
  }
  const editMatch = PROVIDER_EDIT_PATTERN.exec(path);
  if (editMatch !== null) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={PROVIDERS_PATH}
        breadcrumb={['管理后台', '提供方', '编辑']}
      >
        <ProviderEditPage
          alRoot={boot.alRoot}
          providerKey={decodeURIComponent(editMatch[1])}
        />
      </AdminLayout>
    );
  }
  if (path === USERS_PATH) {
    return (
      <AdminLayout alRoot={boot.alRoot} activeKey={USERS_PATH} breadcrumb={['管理后台', '用户']}>
        <UsersPage alRoot={boot.alRoot} />
      </AdminLayout>
    );
  }
  const userMatch = USER_DETAIL_PATTERN.exec(path);
  if (userMatch !== null) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={USERS_PATH}
        breadcrumb={['管理后台', '用户', '用户详情']}
      >
        <UserDetailPage alRoot={boot.alRoot} userId={BigInt(userMatch[1])} />
      </AdminLayout>
    );
  }
  if (path === SSO_CLIENTS_PATH) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={SSO_CLIENTS_PATH}
        breadcrumb={['管理后台', '客户端', 'SSO 客户端']}
      >
        <SsoClientsPage alRoot={boot.alRoot} />
      </AdminLayout>
    );
  }
  if (path === OIDC_CLIENTS_PATH) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={OIDC_CLIENTS_PATH}
        breadcrumb={['管理后台', '客户端', 'OIDC 客户端']}
      >
        <OidcClientsPage alRoot={boot.alRoot} />
      </AdminLayout>
    );
  }
  if (path === SETTINGS_PATH) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={SETTINGS_PATH}
        breadcrumb={['管理后台', '设置']}
      >
        <SettingsPage alRoot={boot.alRoot} />
      </AdminLayout>
    );
  }
  if (path === AUDIT_PATH) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={AUDIT_PATH}
        breadcrumb={['管理后台', '事件日志']}
      >
        <AuditPage alRoot={boot.alRoot} />
      </AdminLayout>
    );
  }
  if (path === STATUS_PATH) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={STATUS_PATH}
        breadcrumb={['管理后台', '监控']}
      >
        <StatusPage alRoot={boot.alRoot} />
      </AdminLayout>
    );
  }
  if (path === DECODE_PATH) {
    return (
      <AdminLayout
        alRoot={boot.alRoot}
        activeKey={DECODE_PATH}
        breadcrumb={['管理后台', '解码工具']}
      >
        <DecodePage alRoot={boot.alRoot} />
      </AdminLayout>
    );
  }
  if (path.startsWith(ADMIN_PREFIX)) {
    return (
      <AdminLayout alRoot={boot.alRoot} activeKey={path} breadcrumb={['管理后台']}>
        <p role="status">{PLACEHOLDER_TEXT}</p>
      </AdminLayout>
    );
  }
  return <p role="status">{ROUTE_NOT_FOUND_TEXT}</p>;
}
