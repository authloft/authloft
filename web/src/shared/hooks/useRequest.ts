/**
 * 请求状态封装（docs/前端架构.md §3.2 useRequest 行 304）：idle / loading /
 * success / error + 竞态丢弃（旧响应到达时丢弃——「禁止并发提交同一 step」的
 * 兜底口径，正常路径由组件按 loading 禁用提交按钮）+ 手动 reset。
 *
 * 本仓 rstest 默认 node 环境（无 DOM），hook 壳不做渲染测试；状态机与竞态
 * 核心抽为可独立测试的纯逻辑（requestReducer / createRaceGuard），沿
 * setup/RestartingPage 的依赖注入测试模式。
 */
import { useCallback, useReducer, useRef, type Reducer } from 'react';

export type RequestStatus = 'idle' | 'loading' | 'success' | 'error';

export interface RequestState<T> {
  readonly status: RequestStatus;
  readonly data: T | undefined;
  readonly error: unknown;
}

/** 初始态（idle，无 data / error）。 */
export const INITIAL_REQUEST_STATE: RequestState<never> = {
  status: 'idle',
  data: undefined,
  error: undefined,
};

export type RequestEvent<T> =
  | { readonly type: 'start' }
  | { readonly type: 'success'; readonly data: T }
  | { readonly type: 'failure'; readonly error: unknown }
  | { readonly type: 'reset' };

/**
 * 请求状态机（纯函数）：start → loading；success / failure 存结果（互斥覆盖）；
 * reset → idle 并清空。被丢弃的旧响应不会派发事件，故不产生状态迁移。
 */
export function requestReducer<T>(
  state: RequestState<T>,
  event: RequestEvent<T>,
): RequestState<T> {
  switch (event.type) {
    case 'start':
      return { status: 'loading', data: undefined, error: undefined };
    case 'success':
      return { status: 'success', data: event.data, error: undefined };
    case 'failure':
      return { status: 'error', data: undefined, error: event.error };
    case 'reset':
      return INITIAL_REQUEST_STATE;
  }
}

/**
 * 竞态令牌（纯逻辑）：每次 begin 递增，isCurrent 仅对最新一次为真——
 * 旧响应到达即丢弃（本卡切片契约：旧响应到达时丢弃，被丢弃的失败不抛出）。
 */
export function createRaceGuard(): {
  begin(): number;
  isCurrent(token: number): boolean;
} {
  let latest = 0;
  return {
    begin: () => {
      latest += 1;
      return latest;
    },
    isCurrent: (token: number) => token === latest,
  };
}

export interface UseRequestResult<TArgs extends unknown[], TResult> {
  readonly status: RequestStatus;
  readonly data: TResult | undefined;
  readonly error: unknown;
  /**
   * 发起请求：最新一次调用的结果落地（成功 resolve data、失败 reject error）；
   * 返回 undefined 表示本次响应已被更新的调用 / reset 取代（竞态丢弃，静默）。
   */
  readonly run: (...args: TArgs) => Promise<TResult | undefined>;
  /** 手动回到 idle（清空 data / error），并使在途请求落地时被丢弃。 */
  readonly reset: () => void;
}

/**
 * 用法：const { status, run, reset } = useRequest((args) => client.method(args))；
 * 提交按钮按 status === 'loading' 禁用（§3.2）。
 */
export function useRequest<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => Promise<TResult>,
): UseRequestResult<TArgs, TResult> {
  const [state, dispatch] = useReducer(
    requestReducer as Reducer<RequestState<TResult>, RequestEvent<TResult>>,
    INITIAL_REQUEST_STATE as RequestState<TResult>,
  );
  const guardRef = useRef(createRaceGuard());
  // fn 每轮 render 都可能是新闭包（捕获最新表单值），经 ref 取最新（useEvent 模式）。
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(
    async (...args: TArgs): Promise<TResult | undefined> => {
      const token = guardRef.current.begin();
      dispatch({ type: 'start' });
      try {
        const data = await fnRef.current(...args);
        if (!guardRef.current.isCurrent(token)) {
          return undefined;
        }
        dispatch({ type: 'success', data });
        return data;
      } catch (error) {
        if (!guardRef.current.isCurrent(token)) {
          return undefined;
        }
        dispatch({ type: 'failure', error });
        throw error;
      }
    },
    [],
  );

  const reset = useCallback(() => {
    // 使在途请求的响应 / 失败落地时被丢弃，不污染 reset 后的 idle 态。
    guardRef.current.begin();
    dispatch({ type: 'reset' });
  }, []);

  return { status: state.status, data: state.data, error: state.error, run, reset };
}
