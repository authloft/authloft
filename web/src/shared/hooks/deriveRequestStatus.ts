/**
 * 请求状态派生（docs/前端架构.md §3.2 useRequest 段；定稿
 * review/frontend-request-layer.md §5.3）：ahooks useRequest 只给
 * loading / error / data 三个原语，四态 status 由本纯函数派生——
 * success 空态需 `!loading && !error && data !== undefined` 三条件组合，
 * 调用点逐处手写易漂移（漏 `!error` 错误态闪空态、漏 `!loading` 首帧闪
 * 空态），故收敛于此，空态判定一律走它、禁止手写三条件。
 * `RequestStatus` 类型同驻本文件：5 个文件的组件 props 签名在引用，
 * 自研 useRequest 删除后类型去处即此处。纯函数、无请求逻辑、
 * 无 React 依赖，node 可测（真值表见同目录测试）。
 */
export type RequestStatus = 'idle' | 'loading' | 'success' | 'error';

/**
 * loading / error / data → 四态：loading 优先（在途即加载中），次 error
 * （失败覆盖），data 已落地为 success，三者皆空为 idle（尚未发起）。
 */
export function deriveRequestStatus(
  loading: boolean,
  error: unknown,
  data: unknown,
): RequestStatus {
  return loading
    ? 'loading'
    : error !== undefined
      ? 'error'
      : data !== undefined
        ? 'success'
        : 'idle';
}
