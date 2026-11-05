/**
 * 重启中页（docs/前端架构.md §6b / 接口文档 §13.4）：两条安装路径
 * （上传配置 / 全新安装）成功后共用本页——同一文案 + 同一轮询。
 * 轮询口径：**2s 间隔 / 120s 超时 /
 * GetStatus 404 视为完成**（重启后正常模式下 setup 路由不注册 → 404 即完成）。
 */
import { useEffect, useState } from 'react';
import { fetchSetupStatus, type SetupStatusResult } from '../api';
import { redirectToLogin } from '../bootstrap';
import styles from './RestartingPage.module.less';

/** §13.4：以 2 秒间隔轮询。 */
export const RESTART_POLL_INTERVAL_MS = 2_000;
/** §13.4：轮询超过 120 秒仍未恢复 → 提示超时，不自动重试安装。 */
export const RESTART_POLL_TIMEOUT_MS = 120_000;

/** §13.4 两条路径共用的重启提示文案（逐字取自契约）。 */
export const RESTARTING_NOTICE =
  '程序已退出，请手动重新运行；如使用 Docker 或 systemd，会自动重启';
export const RESTART_TIMEOUT_NOTICE = '重启超时，请检查服务状态';

export type RestartPollResult =
  /** status 404：setup 路由消失，已进入正常模式。 */
  | 'restarted'
  /** 超过 120 秒仍未恢复。 */
  | 'timeout'
  /** 调用方 cancel（页面卸载等）。 */
  | 'cancelled';

export interface RestartPollOptions {
  /** 探测 SetupService/GetStatus（§13.1）并分类；实现不得 reject。 */
  check: () => Promise<SetupStatusResult>;
  intervalMs?: number;
  timeoutMs?: number;
  /** 定时器 / 时钟注入点（单测 mock 定时器用）；缺省 setTimeout / Date.now。 */
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export interface RestartPollHandle {
  readonly done: Promise<RestartPollResult>;
  /** 中断轮询：done 以 'cancelled' 结束，之后不再发探测（编码约束 §9 第 7 条）。 */
  cancel(): void;
}

/**
 * §13.4 重启轮询核心：立即发起首次探测，此后每 intervalMs 一次；
 * 仅 status 404（`kind:'gone'`）视为重启完成，连接被拒 / 超时 / 其他响应
 * 一律继续轮询；到 deadline（默认 120s）仍未恢复 → 'timeout'，不自动重试。
 * 恰好在 deadline 时刻恢复（"未超过"边界）按完成处理。
 */
export function pollRestart(options: RestartPollOptions): RestartPollHandle {
  const intervalMs = options.intervalMs ?? RESTART_POLL_INTERVAL_MS;
  const timeoutMs = options.timeoutMs ?? RESTART_POLL_TIMEOUT_MS;
  const sleep = options.sleep ?? defaultSleep;
  const now = options.now ?? Date.now;
  let cancelled = false;
  const done = (async (): Promise<RestartPollResult> => {
    const deadline = now() + timeoutMs;
    for (;;) {
      if (cancelled) {
        return 'cancelled';
      }
      const result = await options.check();
      if (cancelled) {
        return 'cancelled';
      }
      if (result.kind === 'gone') {
        return 'restarted';
      }
      if (now() >= deadline) {
        return 'timeout';
      }
      await sleep(intervalMs);
    }
  })();
  return {
    done,
    cancel(): void {
      cancelled = true;
    },
  };
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/** 两条路径共用的重启页：文案 + 轮询；完成跳 /sso/login，超时只提示。 */
export default function RestartingPage({ alRoot }: { alRoot: string }) {
  const [timedOut, setTimedOut] = useState(false);

  useEffect(() => {
    const handle = pollRestart({ check: fetchSetupStatus });
    let unmounted = false;
    handle.done.then((result) => {
      if (unmounted) {
        return;
      }
      if (result === 'restarted') {
        // §13.4：服务恢复（status 404）后跳 /sso/login。
        redirectToLogin(alRoot);
      } else if (result === 'timeout') {
        // §6b：超时只提示检查服务状态，不自动重试安装。
        setTimedOut(true);
      }
    });
    return () => {
      unmounted = true;
      handle.cancel();
    };
  }, [alRoot]);

  return (
    <section className={styles.page}>
      <h1>重启中</h1>
      <p>{RESTARTING_NOTICE}</p>
      <p role="status">
        {timedOut ? RESTART_TIMEOUT_NOTICE : '等待服务重启…'}
      </p>
    </section>
  );
}
