/**
 * 扫码四态面板唯一实现（docs/前端架构.md §3.3 行 345）：拉码 → 展示码图 →
 * 长轮询 → pending / scanned / success / expired；failed 按信封顶层 status
 * 出文案（§1.6 分层；接口文档 §2.8 行 728-729「结论在信封 status」）。
 * 业务语义全部由 props 注入（requestQR / pollUrl / onResult），组件不感知
 * 是登录还是绑定：登录组 = CreateQrcode + GetLoginTicket（§2.8），绑定组 =
 * CreateQrcode scene=bind + GetThirdpartyTicket（§3.7.1 B），两条 RPC 的
 * 响应都复用登录流程信封（§1.3 行 152-154），success 时整个信封交 onResult
 * （登录读 .login、绑定读 .bind）。expired 重拉需 captcha——每次拉码都要
 * 新的（§2.8 行 703），由调用方的 requestQR 携带，本组件只负责再次调用；
 * 卸载中断轮询（useLongPoll 的 unmount abort，§8.2 行 606）。
 *
 * 面板控制器（createQRPanelController）组合 createLongPollController，
 * 不依赖 React 可独立测试；QRCodePanelView 为纯展示（四态 + failed，
 * SSR 可测）；组件自身不发任何业务请求（拉码 / 轮询都由 props 决定）。
 */
import { useEffect, useRef, useState } from 'react';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CreateQrcodeResponse } from '../../gen/proto/api/sso/v1/ticket_pb';
import {
  createLongPollController,
  DEFAULT_MAX_POLL_ERRORS,
  type LongPollController,
} from '../hooks/useLongPoll';
import { ApiError, resolveCode, resolveFlowStatus } from '../api/errors';
import { t } from '../i18n';
import { errorText } from './ErrorBanner';
import styles from './QRCodePanel.module.less';

// ---------------------------------------------------------------------------
// 纯函数层（node 环境测试覆盖，§8.2 B「交互边界在纯函数层」）
// ---------------------------------------------------------------------------

/** poll 秒数的网络缓冲（服务端 hold 满 poll 秒后才返回，客户端超时保护放宽）。 */
export const POLL_TIMEOUT_BUFFER_S = 5;
/** poll 秒数默认值 = 上限（接口文档 §2.8 行 714，全文档唯一定义处）。 */
export const MAX_POLL_SECONDS = 15;

/**
 * poll 秒数（调用方 props）→ 客户端单次超时 ms（useLongPoll.pollTimeoutMs）：
 * undefined / 非正 / 超上限一律按上限 15 兜底（零值兜底 + §2.8 上限）。
 * 请求侧的 poll 参数由调用方在 pollUrl 里使用同一 props 值。
 */
export function pollTimeoutMsOf(pollSeconds: number | undefined): number {
  const seconds =
    pollSeconds === undefined || pollSeconds <= 0 || pollSeconds > MAX_POLL_SECONDS
      ? MAX_POLL_SECONDS
      : pollSeconds;
  return (seconds + POLL_TIMEOUT_BUFFER_S) * 1000;
}

/** 票据五态（§2.8 行 717：ticket.status 取值；「四态面板」+ failed 文案态）。 */
export type QRTicketPhase =
  | 'pending'
  | 'scanned'
  | 'success'
  | 'expired'
  | 'failed';

/**
 * 信封 → 票据五态（§2.8 行 717、721-729）：ticket.status 优先（未知取值 →
 * pending 继续轮询，可能是服务端新增中间态）；ticket 缺失（零值兜底）按顶层
 * status 映射，失败类 / 未知顶层 → failed（保守停止，避免无限轮询）。
 */
export function ticketPhaseOf(envelope: LoginFlowResponse): QRTicketPhase {
  const ticketStatus = envelope.ticket?.status;
  if (ticketStatus !== undefined && ticketStatus !== '') {
    if (
      ticketStatus === 'scanned' ||
      ticketStatus === 'success' ||
      ticketStatus === 'expired' ||
      ticketStatus === 'failed'
    ) {
      return ticketStatus;
    }
    return 'pending';
  }
  const top = envelope.status;
  if (top === 'scanned' || top === 'success' || top === 'expired') {
    return top;
  }
  if (top === 'pending' || top === '') {
    return 'pending';
  }
  return 'failed';
}

/**
 * failed 文案（§2.8 行 728-729）：结论在信封顶层 status → i18n 优先
 * （§1.5 行 202），error.message 只作兜底；未知 status 走兜底不暴露内部信息。
 */
export function qrFailureText(envelope: LoginFlowResponse): string {
  return errorText(
    resolveFlowStatus(envelope.status).i18nKey,
    envelope.error?.message,
  );
}

/** 拉码失败文案：ApiError 走位置二解析（§1.6 两个位置），其余 unknown 兜底。 */
export function fetchFailureText(error: unknown): string {
  if (error instanceof ApiError) {
    return errorText(resolveCode(error).i18nKey, error.message);
  }
  return errorText('errors.status.unknown');
}

// ---------------------------------------------------------------------------
// 面板状态与控制器
// ---------------------------------------------------------------------------

export type QRPanelPhase =
  | { readonly kind: 'fetching' }
  | {
      readonly kind: 'active';
      readonly qrcodeUrl: string;
      readonly ticketStatus: 'pending' | 'scanned';
    }
  | { readonly kind: 'success' }
  | { readonly kind: 'expired' }
  | { readonly kind: 'failed'; readonly message: string };

export interface QRPanelControllerOptions {
  /** 拉码（调用方包装 CreateQrcode——含 captcha；expired 重拉同样走这里）。 */
  requestQR(signal: AbortSignal): Promise<CreateQrcodeResponse>;
  /**
   * 轮询调用（调用方包装 GetLoginTicket / GetThirdpartyTicket；请求侧 poll
   * 秒数由调用方使用 pollSeconds 同一值，§2.8 行 714 上限 15）。
   */
  pollUrl(ticket: string, signal: AbortSignal): Promise<LoginFlowResponse>;
  /** 结果就绪（success）：整个信封交给调用方（登录读 .login、绑定读 .bind）。 */
  onResult(envelope: LoginFlowResponse): void;
  /** 面板状态变化通知（组件壳绑 setState）。 */
  onPhase(phase: QRPanelPhase): void;
  /** 轮询单次最长等待秒数（默认 15；面板生命周期内取创建时值）。 */
  pollSeconds?: number;
  /** 连续轮询错误上限（默认 useLongPoll 的 DEFAULT_MAX_POLL_ERRORS）。 */
  maxPollErrors?: number;
}

export interface QRPanelController {
  /** 拉码并开始轮询（expired / failed 后重拉 = 再次调用；新 captcha 由 requestQR 调用方处理）。 */
  refresh(): void;
  /** 中断轮询与在途拉码，且不再发起（unmount；§3.3 行 345「卸载中断轮询」）。 */
  dispose(): void;
}

export function createQRPanelController(
  options: QRPanelControllerOptions,
): QRPanelController {
  let disposed = false;
  let ticket = '';
  let currentQRUrl = '';
  let fetchAbort: AbortController | undefined;
  // 活动态去重：ticketStatus 未变（拉码即 pending，首轮轮询又 pending）不重复通知。
  let lastTicketStatus: 'pending' | 'scanned' | undefined;

  const activePhase = (ticketStatus: QRTicketPhase): QRPanelPhase => ({
    kind: 'active',
    qrcodeUrl: currentQRUrl,
    ticketStatus: ticketStatus === 'scanned' ? 'scanned' : 'pending',
  });

  const longPoll: LongPollController = createLongPollController<LoginFlowResponse>(
    () => ({
      poll: (signal) => options.pollUrl(ticket, signal),
      isSettled: (envelope) => {
        const phase = ticketPhaseOf(envelope);
        return phase !== 'pending' && phase !== 'scanned';
      },
      onPoll: (envelope) => {
        const ticketStatus =
          ticketPhaseOf(envelope) === 'scanned' ? 'scanned' : 'pending';
        if (ticketStatus !== lastTicketStatus) {
          lastTicketStatus = ticketStatus;
          options.onPhase(activePhase(ticketStatus));
        }
      },
      onSettled: (envelope) => {
        const phase = ticketPhaseOf(envelope);
        if (phase === 'success') {
          options.onPhase({ kind: 'success' });
          options.onResult(envelope);
        } else if (phase === 'expired') {
          options.onPhase({ kind: 'expired' });
        } else {
          options.onPhase({ kind: 'failed', message: qrFailureText(envelope) });
        }
      },
      onMaxErrors: () => {
        options.onPhase({ kind: 'failed', message: t('errors.status.unknown') });
      },
      pollTimeoutMs: pollTimeoutMsOf(options.pollSeconds),
      maxErrors: options.maxPollErrors ?? DEFAULT_MAX_POLL_ERRORS,
    }),
  );

  return {
    refresh: () => {
      if (disposed) {
        return;
      }
      longPoll.stop();
      fetchAbort?.abort();
      const attempt = new AbortController();
      fetchAbort = attempt;
      ticket = '';
      currentQRUrl = '';
      // 拉码成功即 active(pending)。
      lastTicketStatus = 'pending';
      options.onPhase({ kind: 'fetching' });
      void options.requestQR(attempt.signal).then(
        (qr) => {
          if (disposed || attempt.signal.aborted) {
            return;
          }
          fetchAbort = undefined;
          ticket = qr.ticket;
          currentQRUrl = qr.qrcodeUrl;
          options.onPhase({
            kind: 'active',
            qrcodeUrl: qr.qrcodeUrl,
            ticketStatus: 'pending',
          });
          longPoll.start();
        },
        (error) => {
          if (disposed || attempt.signal.aborted) {
            return;
          }
          fetchAbort = undefined;
          options.onPhase({ kind: 'failed', message: fetchFailureText(error) });
        },
      );
    },
    dispose: () => {
      disposed = true;
      longPoll.stop();
      fetchAbort?.abort();
      fetchAbort = undefined;
    },
  };
}

// ---------------------------------------------------------------------------
// 展示层 + 组件壳
// ---------------------------------------------------------------------------

export interface QRCodePanelViewProps {
  phase: QRPanelPhase;
  /** expired 重拉动作（绑 controller.refresh；新 captcha 由 requestQR 调用方携带）。 */
  onRefresh(): void;
}

/** 纯展示（四态 + failed；SSR 可测，§8.2 B 渲染断言模式）。 */
export function QRCodePanelView({ phase, onRefresh }: QRCodePanelViewProps) {
  return (
    <div className={styles.panel}>
      {phase.kind === 'fetching' && (
        <p className={styles.hint} role="status">
          {t('common.qrFetching')}
        </p>
      )}
      {phase.kind === 'active' && (
        <>
          <img className={styles.qrcode} src={phase.qrcodeUrl} alt={t('common.qrCodeAlt')} />
          <p className={styles.hint} role="status">
            {phase.ticketStatus === 'scanned'
              ? t('errors.status.scanned')
              : t('common.qrScanPrompt')}
          </p>
        </>
      )}
      {phase.kind === 'success' && (
        <p className={styles.success} role="status">
          {t('errors.status.success')}
        </p>
      )}
      {phase.kind === 'expired' && (
        <div className={styles.actionBox}>
          <p className={styles.hint}>{t('errors.status.expired')}</p>
          <button type="button" className={styles.refreshButton} onClick={onRefresh}>
            {t('common.retry')}
          </button>
        </div>
      )}
      {phase.kind === 'failed' && (
        <div role="alert" className={styles.actionBox}>
          <p className={styles.errorText}>{phase.message}</p>
        </div>
      )}
    </div>
  );
}

export interface QRCodePanelProps {
  /** 拉码（调用方包装 CreateQrcode——含 captcha，每次拉码都要新的，§2.8 行 703）。 */
  requestQR(signal: AbortSignal): Promise<CreateQrcodeResponse>;
  /** 轮询调用（调用方包装 GetLoginTicket / GetThirdpartyTicket，poll 秒数同 pollSeconds）。 */
  pollUrl(ticket: string, signal: AbortSignal): Promise<LoginFlowResponse>;
  /** 结果就绪（success）：整个信封交给调用方（登录读 .login、绑定读 .bind）。 */
  onResult(envelope: LoginFlowResponse): void;
  /** 轮询单次最长等待秒数（上限 15，§2.8 行 714；默认 15）。 */
  pollSeconds?: number;
  /** 连续轮询错误上限（默认 useLongPoll 的 DEFAULT_MAX_POLL_ERRORS）。 */
  maxPollErrors?: number;
}

export function QRCodePanel(props: QRCodePanelProps) {
  const [phase, setPhase] = useState<QRPanelPhase>({ kind: 'fetching' });
  const propsRef = useRef(props);
  propsRef.current = props;
  const [controller] = useState(() =>
    createQRPanelController({
      requestQR: (signal) => propsRef.current.requestQR(signal),
      pollUrl: (ticket, signal) => propsRef.current.pollUrl(ticket, signal),
      onResult: (envelope) => propsRef.current.onResult(envelope),
      onPhase: setPhase,
      pollSeconds: propsRef.current.pollSeconds,
      maxPollErrors: propsRef.current.maxPollErrors,
    }),
  );

  // 挂载即拉码；卸载中断轮询与在途拉码（§3.3 行 345）。
  useEffect(() => {
    controller.refresh();
    return () => controller.dispose();
  }, [controller]);

  return (
    <QRCodePanelView
      phase={phase}
      onRefresh={() => controller.refresh()}
    />
  );
}
