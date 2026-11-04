/**
 * login_token 内存仓（docs/前端架构.md §4.1 行 378、行 397-403 五条不可打折；
 * 传递规则唯一定义在 docs/接口文档.md §1.8 / §1.3 行 145）：
 *
 * 1. 模块级变量保存，前端不解析其内容，只做「收到就替换、请求就带上」；
 * 2. 每次响应含 login_token 无条件覆盖（后端每次重签，旧值立即作废）；
 * 3. status=success 时清空（api.ts 响应后处理调用）；
 * 4. 禁止写入 localStorage / sessionStorage / Cookie——本模块不触碰任何存储；
 * 5. 页面刷新 → 模块变量丢失 → 回到登录第一步并提示（bootstrap/entry 职责，归后续实现）。
 *
 * subscribe 语义最简：Set<回调> + 通知，不做框架级状态库。
 */

/** login_token 变更监听器；入参为最新值（clear 后为 ''）。 */
export type LoginTokenListener = (token: string) => void;

let current = '';

const listeners = new Set<LoginTokenListener>();

/** 当前 login_token；'' 表示无（首次请求 / 已完成 / 已失效）。 */
export function getLoginToken(): string {
  return current;
}

/** 无条件覆盖内存变量（五条之 2）并通知订阅者。 */
export function setLoginToken(token: string): void {
  current = token;
  for (const listener of listeners) {
    listener(token);
  }
}

/** 清空（五条之 3：status=success；§1.6 token 类回到第一步）并通知订阅者。 */
export function clearLoginToken(): void {
  setLoginToken('');
}

/** 订阅变更；返回取消订阅函数。 */
export function subscribeLoginToken(
  listener: LoginTokenListener,
): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
