/**
 * 登录端路由（docs/前端架构.md §4.1 行 392；接口文档 §8）：
 * `/sso/login`、`/auth/authorize` → LoginPage——「OIDC 授权页即登录页」；
 * `/sso/register` → RegisterPage、`/sso/reset` → ResetPage。
 * `/auth/authorize` 的已登录直达由后端直接 302 处理（§4.4 行 447），
 * 前端只渲染无会话空壳；`/sso/oauth/callback/:provider_key` 已注册
 * （§4.1 行 392）：前缀匹配提取路径参数 → OAuthCallbackPage 空壳页（无业务
 * 逻辑，分派归页面，接口文档 §2.7.3）。
 *
 * 零第三方路由库（§1.6 行 110：login 无额外依赖）：entry 自挂载
 * （disableMount），极简 pathname 匹配即可；页面刷新即丢失内存态、
 * 回到流程第一步（§4.1 行 392）。
 *
 * 文案：错误态 / 兜底文案经 i18n 字典 login.* 键取用（i18n 收口）。
 */
import { t } from '../shared/i18n';
import { loadLoginBootstrap } from './bootstrap';
import { LoginPage } from './pages/LoginPage';
import { OAuthCallbackPage } from './pages/OAuthCallbackPage';
import { RegisterPage } from './pages/RegisterPage';
import { ResetPage } from './pages/ResetPage';

/** 本实现注册的登录端路由（§1.4 行 81 登录端路由清单的已交付子集）。 */
const LOGIN_ROUTES: ReadonlySet<string> = new Set([
  '/sso/login',
  '/sso/register',
  '/sso/reset',
  '/auth/authorize',
]);

/** OAuth 回调路由前缀（§4.1 行 392 / §2.7.3：`/sso/oauth/callback/:provider_key`）。 */
const CALLBACK_PREFIX = '/sso/oauth/callback/';

/** 提取路径参数 provider_key：URL 编码段解码，非法编码原样透传（后端按未知 provider 处理）。 */
function decodeProviderKey(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}


/** 登录端应用根：bootstrap 读注入快照 → 路由分派（§4.1 行 374-376）。 */
export function LoginApp() {
  // §4.1 行 375 / §1.5 行 98：methods 必需，缺失即服务端故障——错误态 +
  // 提示刷新，没有回退接口。
  const boot = loadLoginBootstrap();
  if (!boot.ok) {
    return <p role="alert">{t('login.initMissing')}</p>;
  }
  // 尾斜杠归一（`/sso/login/` 与 `/sso/login` 同页；根路径归一为空串不匹配）。
  const path = window.location.pathname.replace(/\/+$/, '');
  if (!LOGIN_ROUTES.has(path)) {
    // 回调路由带路径参数，不走精确 Set：前缀 + 单段非空 key 才匹配（§2.7.3）；
    // 其余（含缺 key / 多段）走兜底提示。
    const rest = path.startsWith(CALLBACK_PREFIX)
      ? path.slice(CALLBACK_PREFIX.length)
      : '';
    if (rest !== '' && !rest.includes('/')) {
      return (
        <OAuthCallbackPage
          providerKey={decodeProviderKey(rest)}
          snapshot={boot.snapshot}
        />
      );
    }
    return <p role="status">{t('login.routeNotFound')}</p>;
  }
  // 注册 / 重置页共用注入快照（flow=register / flow=reset 已按 §2.1 过滤）。
  if (path === '/sso/register') {
    return <RegisterPage snapshot={boot.snapshot} />;
  }
  if (path === '/sso/reset') {
    return <ResetPage snapshot={boot.snapshot} />;
  }
  return <LoginPage snapshot={boot.snapshot} />;
}
