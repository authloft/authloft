/**
 * OIDC 上下文跨重定向存活（docs/前端架构.md §4.1 行 379；docs/接口文档.md
 * §2.7.2 行 599-600）：三方跳转会丢弃前端内存态，跳转前把 __AUTHLOFT_INIT__.oidc
 * 写入 localStorage（键 al_oidc_ctx），回调后读出、随 SsoService/LoginOauth 的
 * 请求体 oidc 字段回传（§2.7.4 行 629），读完即清。登录端允许落盘的数据只有
 * oidc（al_oidc_ctx 一个键）；login_token / session_token 严格内存态，绝不写入
 * 本键（§2.7.2 行 600）。
 */
import type { OidcContext } from '../shared/types/init';

/** localStorage 键（§2.7.2 行 600 唯一定义）。 */
const OIDC_CTX_KEY = 'al_oidc_ctx';

/** 落盘 OIDC 上下文（跳转第三方前调用）；只写 al_oidc_ctx 一个键。非浏览器环境无操作。 */
export function saveOidcContext(ctx: OidcContext): void {
  if (typeof window === 'undefined') {
    return;
  }
  window.localStorage.setItem(OIDC_CTX_KEY, JSON.stringify(ctx));
}

/**
 * 读出 OIDC 上下文并立即清除（§2.7.2 行 600「读完即清」）。
 * 无值 / 非法 JSON / 缺必需字段（client_id、redirect_uri）→ undefined；
 * 可选字段只还原 string 值，其余丢弃（不透出脏数据）。
 */
export function loadOidcContext(): OidcContext | undefined {
  if (typeof window === 'undefined') {
    return undefined;
  }
  const raw = window.localStorage.getItem(OIDC_CTX_KEY);
  if (raw === null) {
    return undefined;
  }
  clearOidcContext();
  let parsed: Partial<OidcContext>;
  try {
    parsed = JSON.parse(raw) as Partial<OidcContext>;
  } catch {
    return undefined; // 非法载荷视同无值，不透出（键已清）
  }
  if (
    typeof parsed.client_id !== 'string' ||
    typeof parsed.redirect_uri !== 'string'
  ) {
    return undefined;
  }
  return {
    client_id: parsed.client_id,
    redirect_uri: parsed.redirect_uri,
    scope: pickString(parsed.scope),
    state: pickString(parsed.state),
    nonce: pickString(parsed.nonce),
    code_challenge: pickString(parsed.code_challenge),
    code_challenge_method: pickString(parsed.code_challenge_method),
  };
}

/** 可选字段只还原 string 值，其余（undefined / 脏类型）丢弃。 */
function pickString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** 清除落盘的 OIDC 上下文。 */
export function clearOidcContext(): void {
  if (typeof window === 'undefined') {
    return;
  }
  window.localStorage.removeItem(OIDC_CTX_KEY);
}
