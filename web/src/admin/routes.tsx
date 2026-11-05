/**
 * admin 路由（docs/前端架构.md §6 行 501/505；接口文档 §8 行 1422 `/admin/**`）：
 * 极简 pathname 匹配——ProvidersPage 长入 /admin/providers（§6 行 515）；
 * ProviderEditPage 长入 /admin/providers/new 新建 +
 * /admin/providers/{provider_key}/edit 编辑（§6 行 516）；其余 `/admin/**`
 * 一律 AdminLayout 包裹占位页（归后续实现逐项长入），不匹配前缀 →
 * 页面不存在。
 *
 * 沿 account/routes.tsx 模式：零第三方路由库（§1.6 行 110），
 * disableMount 自挂载，极简 pathname 匹配；bootstrap 无 methods 必需校验
 * （§8：methods 仅 login 必填）。401/404 分流在 AdminLayout（GetMe 失败时
 * 处理），路由层不发请求。
 */
import { loadAdminBootstrap } from './bootstrap';
import { AdminLayout } from './layout/AdminLayout';
import { ProviderEditPage } from './pages/ProviderEditPage';
import { ProvidersPage } from './pages/ProvidersPage';

/** /admin 前缀（接口文档 §8 行 1422：管理端 SPA 空壳）。 */
const ADMIN_PREFIX = '/admin';

/** 提供方列表页路径（§6 行 515；侧边栏 NAV_ITEMS 同约定 itemKey 即路径）。 */
const PROVIDERS_PATH = '/admin/providers';

/** 提供方新建页路径（§6 行 516）。 */
const PROVIDER_NEW_PATH = '/admin/providers/new';

/** 提供方编辑页路径模式（§6 行 516：provider_key 单段，URL 编码段安全）。 */
const PROVIDER_EDIT_PATTERN = /^\/admin\/providers\/([^/]+)\/edit$/;

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
  if (path.startsWith(ADMIN_PREFIX)) {
    return (
      <AdminLayout alRoot={boot.alRoot} activeKey={path} breadcrumb={['管理后台']}>
        <p role="status">{PLACEHOLDER_TEXT}</p>
      </AdminLayout>
    );
  }
  return <p role="status">{ROUTE_NOT_FOUND_TEXT}</p>;
}
