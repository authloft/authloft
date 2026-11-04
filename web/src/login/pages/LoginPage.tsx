/**
 * 登录页外壳（docs/前端架构.md §4.4 行 447）：组装 LoginContainer——
 * 「MethodTabs + LoginContainer」的组装关系由容器视图 LoginFlowView
 * 内嵌 MethodTabs 满足（既有交付结构），此处不重复渲染防双份。
 *
 * - `/auth/authorize` 的已登录直达由后端 302 处理（§4.4），前端只渲染
 *   无会话空壳；登录成功后的终点跳转（syncCookieUrl / redirectTo）在
 *   LoginContainer 内处理；
 * - 「忘记密码」「注册」入口可见性取注入快照 `methods.flags`（接口文档
 *   §2.1 行 374-377：镜像 allow_password_reset / allow_registration），
 *   不另发请求；注册 / 重置页随后续实现交付，入口按 flags 渲染为禁用占位、
 *   不实现点击跳转。
 */
import { LoginContainer } from '../LoginContainer';
import type { MethodsSnapshot } from '../../shared/types/init';

export interface LoginPageProps {
  /** 注入快照（§2.1；bootstrap 读取后传入，§4.1 行 375）。 */
  readonly snapshot: MethodsSnapshot;
}

/** 页面标题——无 i18n 键，最简中文字面量（归后续 i18n 实现）。 */
const TITLE_TEXT = '登录';
/** 入口文案——同上。 */
const FORGOT_PASSWORD_TEXT = '忘记密码';
/** 入口文案——同上。 */
const REGISTER_TEXT = '注册';

export function LoginPage({ snapshot }: LoginPageProps) {
  // §2.1 行 407：flags 只用于隐藏登录页的「忘记密码」「注册」入口；
  // 零值兜底——undefined / 缺省不渲染。
  const flags = snapshot.flags;
  const showForgot = flags?.passwordReset === true;
  const showRegister = flags?.registration === true;
  return (
    <main>
      <h1>{TITLE_TEXT}</h1>
      <LoginContainer snapshot={snapshot} />
      {(showForgot || showRegister) && (
        <nav>
          {showForgot && (
            <button type="button" disabled>
              {FORGOT_PASSWORD_TEXT}
            </button>
          )}
          {showRegister && (
            <button type="button" disabled>
              {REGISTER_TEXT}
            </button>
          )}
        </nav>
      )}
    </main>
  );
}
