/**
 * admin 路由（docs/前端架构.md §6 行 501/505；接口文档 §8 行 1422 `/admin/**`）：
 * 本次先建极简前缀匹配结构——`/admin/**` 一律 AdminLayout 包裹占位页；
 * 具体页面路由（Provider / 用户 / 客户端 / Settings / 工具页，§6 行 515-523）
 * 归后续实现逐项长入。
 *
 * 沿 account/routes.tsx 模式：零第三方路由库（§1.6 行 110），
 * disableMount 自挂载，极简 pathname 匹配；bootstrap 无 methods 必需校验
 * （§8：methods 仅 login 必填）。401/404 分流在 AdminLayout（GetMe 失败时
 * 处理），路由层不发请求。
 */
import { loadAdminBootstrap } from './bootstrap';
import { AdminLayout } from './layout/AdminLayout';

/** /admin 前缀（接口文档 §8 行 1422：管理端 SPA 空壳）。 */
const ADMIN_PREFIX = '/admin';

/** 未注册路由兜底文案——无 i18n 键，最简中文字面量（归后续 i18n 实现）。 */
const ROUTE_NOT_FOUND_TEXT = '页面不存在';

/** 占位页文案（业务页面归后续实现逐项长入）。 */
const PLACEHOLDER_TEXT = '管理后台';

/** admin 应用根：bootstrap 读注入变量（al_root / static_base）→ 路由分派。 */
export function AdminApp() {
  const boot = loadAdminBootstrap();
  // 尾斜杠归一（`/admin/` 与 `/admin` 同页；根路径归一为空串不匹配前缀）。
  const path = window.location.pathname.replace(/\/+$/, '');
  if (path.startsWith(ADMIN_PREFIX)) {
    return (
      <AdminLayout alRoot={boot.alRoot} breadcrumb={['管理后台']}>
        <p role="status">{PLACEHOLDER_TEXT}</p>
      </AdminLayout>
    );
  }
  return <p role="status">{ROUTE_NOT_FOUND_TEXT}</p>;
}
