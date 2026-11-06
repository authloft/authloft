/**
 * 厂商脚本动态加载器（docs/前端架构.md §3.5 行 391「懒加载厂商 JS SDK」）：
 * 无感验证码三家（Turnstile / reCAPTCHA / hCaptcha）的 SDK
 * 脚本一律运行期 createElement('script') 按需注入——不打包进产物、不在壳层
 * 模板写死 <script> 标签（写死违反 CSP nonce / strict-dynamic 基线，
 * docs/前端架构.md §8 节）。厂商 wrapper 只经本入口取脚本，不自行碰 DOM。
 *
 * - 幂等去重：同 src 并发 / 重复调用复用同一 Promise，页面内不重复注入；
 * - 失败可重试：onerror / 超时后清缓存，下次调用重新注入；
 * - 超时：默认 10s 未 onload 即判失败（移除标签、reject）。
 *
 * document 可注入（node 测试环境无 DOM，沿 Image adapter 的替身注入惯例）。
 */

/** 默认加载超时（ms）。 */
export const VENDOR_SCRIPT_TIMEOUT_MS = 10_000;

/** 进行中 / 已成功的加载（同 src 复用；失败项被清除以允许重试）。 */
const inflight = new Map<string, Promise<void>>();

export interface LoadVendorScriptOptions {
  /** DOM 文档（缺省全局 document；node 测试环境注入桩）。 */
  document?: Document;
  /** 超时毫秒（缺省 VENDOR_SCRIPT_TIMEOUT_MS；测试可注短值）。 */
  timeoutMs?: number;
}

/**
 * 动态加载厂商脚本：resolve = onload；reject = onerror / 超时。
 * 同 src 并发 / 重复调用共享同一 Promise（幂等）；失败后缓存清除，可重试。
 */
export function loadVendorScript(
  src: string,
  options: LoadVendorScriptOptions = {},
): Promise<void> {
  const existing = inflight.get(src);
  if (existing !== undefined) {
    return existing;
  }
  const doc = options.document ?? document;
  const timeoutMs = options.timeoutMs ?? VENDOR_SCRIPT_TIMEOUT_MS;
  const attempt = new Promise<void>((resolve, reject) => {
    const script = doc.createElement('script');
    script.src = src;
    script.async = true;
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      script.onload = null;
      script.onerror = null;
      script.remove();
      reject(new Error(`vendor script load timeout: ${src}`));
    }, timeoutMs);
    script.onload = () => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      script.onerror = null;
      resolve();
      // 成功：标签留在文档、缓存保留 → 同 src 后续调用直接 resolve（幂等）。
    };
    script.onerror = () => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      script.onload = null;
      script.remove();
      reject(new Error(`vendor script load failed: ${src}`));
    };
    doc.head.appendChild(script);
  });
  inflight.set(src, attempt);
  // 失败（含超时）→ 清缓存：下次调用重新注入（重试路径）。
  void attempt.catch(() => {
    if (inflight.get(src) === attempt) {
      inflight.delete(src);
    }
  });
  return attempt;
}
