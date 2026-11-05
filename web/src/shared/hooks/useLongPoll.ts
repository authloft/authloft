/**
 * 长轮询（docs/前端架构.md §3.2 useLongPoll 行 318）：单次最长等待、超时
 * 立即重连、指数退避、页面 / 组件卸载中断（unmount 时 abort，关键约束）、
 * 错误上限后停止并回调；被 QRCodeStep 与 ticket 完成登录复用（§4.2）。
 *
 * poll 最长等待秒数的业务上限（15，接口文档 §2.8 行 714）由调用方 props
 * 决定并换算成客户端单次超时（见 QRCodePanel.pollTimeoutMsOf），本 hook
 * 不硬编码业务上限。
 *
 * 轮询控制器（createLongPollController）不依赖 React，可独立测试（沿
 * useCopy 的 createCopyController 模式）；hook 壳只做启动绑定与卸载清理
 * （unmount → stop：在途请求 abort 且不再发起，§8.2 行 591）。
 */
import { useCallback, useEffect, useRef, useState } from 'react';

/** 连续错误上限默认值（达到即停止并回调 onMaxErrors）。 */
export const DEFAULT_MAX_POLL_ERRORS = 5;
/** 指数退避基数（ms）。 */
export const DEFAULT_POLL_BACKOFF_BASE_MS = 500;
/** 指数退避封顶（ms）。 */
export const DEFAULT_POLL_BACKOFF_MAX_MS = 8000;

export interface LongPollConfig<T> {
  /**
   * 单次轮询调用：signal 在单次超时 / stop 时 abort——调用方应把 signal
   * 传给传输层（http.ts 的中断注入），实现请求级中断。
   */
  poll(signal: AbortSignal): Promise<T>;
  /** 终态判定（true → onSettled 后停止）；false → 立即发起下一轮。 */
  isSettled(result: T): boolean;
  /** 非终态结果回调（pending / scanned → UI 更新），返回后立即重连。 */
  onPoll?(result: T): void;
  /** 终态回调（此后轮询停止；重新开始需再次 start）。 */
  onSettled(result: T): void;
  /** 连续错误达到上限后的回调（轮询停止）。 */
  onMaxErrors?(error: unknown): void;
  /** 单次最长等待（ms，客户端超时保护：到点 abort 该次并立即重连）。 */
  pollTimeoutMs: number;
  /** 连续错误上限（默认 DEFAULT_MAX_POLL_ERRORS）。 */
  maxErrors?: number;
  /** 指数退避基数 ms（默认 DEFAULT_POLL_BACKOFF_BASE_MS）。 */
  baseDelayMs?: number;
  /** 指数退避封顶 ms（默认 DEFAULT_POLL_BACKOFF_MAX_MS）。 */
  maxDelayMs?: number;
}

export interface LongPollController {
  /** 开始 / 重新开始轮询（进行中忽略）。 */
  start(): void;
  /** 中断在途轮询并停止后续发起（可再次 start 重新开始，如 expired 重拉新码）。 */
  stop(): void;
  isRunning(): boolean;
}

/**
 * 轮询控制器（纯闭包）：成功返回未终态 → 立即重连（§3.2 行 318「超时立即
 * 重连」——服务端按 poll 秒 hold 后返回未就绪是常态）；单次超时（pollTimeoutMs
 * 到点）→ abort 该次并立即重连，不计入错误；poll 抛错 → 指数退避
 * （base * 2^(n-1)，封顶 maxDelayMs）后重试，连续错误达上限 → 停止并回调
 * onMaxErrors（成功一轮即回血重计）。stop() 中断在途请求、清理退避计时并
 * 停止循环。
 *
 * @param getConfig 每轮取最新配置（回调闭包不陈旧；hook 壳经 ref 桥接）。
 */
export function createLongPollController<T>(
  getConfig: () => LongPollConfig<T>,
): LongPollController {
  let running = false;
  let currentAbort: AbortController | undefined;
  let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
  let cancelSleep: (() => void) | undefined;

  const clearTimeoutTimer = () => {
    if (timeoutTimer !== undefined) {
      clearTimeout(timeoutTimer);
      timeoutTimer = undefined;
    }
  };

  /** 可中断等待（stop 时立即 resolve，循环靠 running 检查退出）。 */
  const sleep = (ms: number): Promise<void> =>
    new Promise((resolve) => {
      const timer = setTimeout(() => {
        cancelSleep = undefined;
        resolve();
      }, ms);
      cancelSleep = () => {
        clearTimeout(timer);
        cancelSleep = undefined;
        resolve();
      };
    });

  const run = async (): Promise<void> => {
    let consecutiveErrors = 0;
    while (running) {
      const cfg = getConfig();
      const attempt = new AbortController();
      currentAbort = attempt;
      let timedOut = false;
      clearTimeoutTimer();
      timeoutTimer = setTimeout(() => {
        timedOut = true;
        attempt.abort();
      }, cfg.pollTimeoutMs);
      let result: T;
      try {
        result = await cfg.poll(attempt.signal);
      } catch (error) {
        clearTimeoutTimer();
        currentAbort = undefined;
        if (!running) {
          // stop 触发的 abort：静默退出，不落地。
          return;
        }
        if (timedOut) {
          // 单次最长等待到点：立即重连，不计入错误（长轮询常态）。
          continue;
        }
        consecutiveErrors += 1;
        const errorCfg = getConfig();
        const maxErrors = errorCfg.maxErrors ?? DEFAULT_MAX_POLL_ERRORS;
        if (consecutiveErrors >= maxErrors) {
          running = false;
          errorCfg.onMaxErrors?.(error);
          return;
        }
        const base = errorCfg.baseDelayMs ?? DEFAULT_POLL_BACKOFF_BASE_MS;
        const cap = errorCfg.maxDelayMs ?? DEFAULT_POLL_BACKOFF_MAX_MS;
        await sleep(Math.min(base * Math.pow(2, consecutiveErrors - 1), cap));
        continue;
      }
      clearTimeoutTimer();
      currentAbort = undefined;
      if (!running) {
        return;
      }
      const settledCfg = getConfig();
      if (settledCfg.isSettled(result)) {
        running = false;
        settledCfg.onSettled(result);
        return;
      }
      // 成功一轮（未终态）→ 连续错误计数回血（指数退避按连续失败计）。
      consecutiveErrors = 0;
      settledCfg.onPoll?.(result);
      // 未就绪（含服务端按 poll 秒 hold 后返回）：立即发起下一轮。
    }
  };

  return {
    start: () => {
      if (running) {
        return;
      }
      running = true;
      void run();
    },
    stop: () => {
      running = false;
      cancelSleep?.();
      clearTimeoutTimer();
      currentAbort?.abort();
      currentAbort = undefined;
    },
    isRunning: () => running,
  };
}

export interface UseLongPollResult {
  /** 开始 / 重新开始轮询；unmount 后调用为 no-op（不再发起，§8.2 行 591）。 */
  start(): void;
  /** 中断在途轮询并停止（expired 重拉新码等场景）。 */
  stop(): void;
}

/**
 * 用法：const { start, stop } = useLongPoll({ poll: (signal) =>
 * client.getLoginTicket({ ticket, poll }, { signal }), isSettled, onSettled,
 * pollTimeoutMs })；unmount 自动 stop（页面卸载由浏览器断开在途请求，
 * 组件卸载经 effect cleanup 显式 abort）。
 */
export function useLongPoll<T>(config: LongPollConfig<T>): UseLongPollResult {
  const configRef = useRef(config);
  configRef.current = config;
  const [controller] = useState(() =>
    createLongPollController<T>(() => configRef.current),
  );
  const disposedRef = useRef(false);

  useEffect(() => {
    disposedRef.current = false;
    return () => {
      disposedRef.current = true;
      controller.stop();
    };
  }, [controller]);

  const start = useCallback(() => {
    if (!disposedRef.current) {
      controller.start();
    }
  }, [controller]);
  const stop = useCallback(() => controller.stop(), [controller]);

  return { start, stop };
}
