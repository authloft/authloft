/**
 * 通用扫码弹窗：login 第三方扫码（channel=qrcode）与 account 扫码绑定共用的
 * 窗体壳——内部组合 createQRPanelController + QRCodePanelView，四态面板机与
 * 纯展示仍是 QRCodePanel 的唯一实现（docs/前端架构.md §3.3）。窗体由调用方按
 * domain 注入 ModalRenderer（契约见 ./modal，CaptchaDialog / StepUpDialog 同
 * 法注入）：本壳 visible 恒 true——挂载即开窗、卸载即关窗，弹窗自身不自动
 * 消失；关窗三路径（右上关闭 / Esc / 底部「关闭」按钮）统一上抛 onClose，
 * 取消与 success 后是否关窗都归调用方决定。
 *
 * footer 用契约能力实现单按钮（hasCancel=false + okText=common.close +
 * onOk=onClose），不做 okButtonProps 样式 hack。captcha 门控不内置：
 * requestQR 语义 = 已包装凭据的拉码函数，expired 重拉的新凭据同样由调用方
 * 携带（每次拉码都要新的 captcha，§2.8）。
 *
 * 【failed 帧文案】控制器把落定 failed 的信封文案固定为通用字典
 * （qrFailureText）；绑定等语境需按信封定制（如 target_taken 的联系方式
 * 语境差异）。本壳经 onPhase 拦截替换：pollUrl 包装器保存最近一次轮询信封，
 * failed 帧用 resolveFailureText(envelope)（缺省 qrFailureText）重写
 * message。但只有「本轮落定 failed」的信封才有资格替换——拉码失败 / 连续
 * 轮询超错没有本轮信封，复用旧信封会把陈旧结论盖在新错误上，故 fetching
 * 即作废旧信封、替换前再以 ticketPhaseOf 守卫。
 *
 * 【可测缝】本仓 rstest 为 node 环境（无 DOM，SSR 不跑 effect），组件壳的
 * 生命周期、轮询接线与文案拦截抽成纯缝导出（qrPanelLifecycle /
 * createQRDialogController / qrDialogPhase）供测试直驱；组件体只剩
 * useState / useEffect 胶水（propsRef 桥接最新 props）。
 */
import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CreateQrcodeResponse } from '../../gen/proto/api/sso/v1/ticket_pb';
import { t } from '../i18n';
import {
  createQRPanelController,
  qrFailureText,
  ticketPhaseOf,
  QRCodePanelView,
  type QRPanelController,
  type QRPanelPhase,
} from './QRCodePanel';
import type { ModalRenderer } from './modal';

export interface QRCodeDialogProps {
  /** domain 窗体实现（契约见 shared/components/modal）。 */
  modal: ModalRenderer;
  /** 同 Semi Modal.title，透传窗体（缺省由 domain Modal 决定）。 */
  title?: ReactNode;
  /** 拉码（调用方包装 CreateQrcode——含 captcha；expired 重拉同样走这里）。 */
  requestQR(signal: AbortSignal): Promise<CreateQrcodeResponse>;
  /** 轮询调用（调用方包装 GetLoginTicket / GetThirdpartyTicket，poll 秒数同 pollSeconds）。 */
  pollUrl(ticket: string, signal: AbortSignal): Promise<LoginFlowResponse>;
  /** 结果就绪（success）：整个信封交给调用方（登录读 .login、绑定读 .bind）。 */
  onResult(envelope: LoginFlowResponse): void;
  /** failed 帧文案解析（缺省 qrFailureText：信封顶层 status → errors.status.*）。 */
  resolveFailureText?(envelope: LoginFlowResponse): string;
  /** 轮询单次最长等待秒数（上限 15，§2.8；默认 15）。 */
  pollSeconds?: number;
  /** 连续轮询错误上限（默认 useLongPoll 的 DEFAULT_MAX_POLL_ERRORS）。 */
  maxPollErrors?: number;
  /** 关窗动作（右上关闭 / Esc / 底部「关闭」按钮统一上抛）；取消语义归调用方。 */
  onClose?: () => void;
  /** 面板视图之后的附加内容（如绑定语境的提示行、内嵌 captcha 弹窗）。 */
  children?: ReactNode;
}

/**
 * failed 帧文案拦截（qrFailureText 缺省；account 绑定语境的 bindFailureText
 * 即经本缝注入）：仅当存在「本轮落定 failed」的信封才重写 message——
 * 信封态守卫挡掉两类陈旧替换：连续轮询超错前的最后成功信封（pending /
 * scanned）与上一轮的 expired；无信封（拉码失败 / 首轮超错）原样保留面板
 * 文案。其余帧一律透传。
 */
export function qrDialogPhase(
  next: QRPanelPhase,
  lastPollEnvelope: LoginFlowResponse | undefined,
  resolveFailureText: ((envelope: LoginFlowResponse) => string) | undefined,
): QRPanelPhase {
  if (
    next.kind !== 'failed' ||
    lastPollEnvelope === undefined ||
    ticketPhaseOf(lastPollEnvelope) !== 'failed'
  ) {
    return next;
  }
  return {
    kind: 'failed',
    message: (resolveFailureText ?? qrFailureText)(lastPollEnvelope),
  };
}

/**
 * 控制器装配（组件壳与测试共用的接线缝）：闭包内读最新 props（propsRef
 * 桥接）；pollUrl 包装器顺路保存落定前的信封供
 * failed 帧文案解析，fetching 帧先作废上一轮信封（重拉后拉码失败不得复用
 * 旧结论）。pollSeconds / maxPollErrors 按控制器约定取创建时值。
 */
export function createQRDialogController(
  read: () => QRCodeDialogProps,
  setPhase: (phase: QRPanelPhase) => void,
): QRPanelController {
  const lastPollRef: { current: LoginFlowResponse | undefined } = {
    current: undefined,
  };
  return createQRPanelController({
    requestQR: (signal) => read().requestQR(signal),
    pollUrl: async (ticket, signal) => {
      const envelope = await read().pollUrl(ticket, signal);
      lastPollRef.current = envelope;
      return envelope;
    },
    onResult: (envelope) => read().onResult(envelope),
    onPhase: (next) => {
      if (next.kind === 'fetching') {
        lastPollRef.current = undefined;
      }
      setPhase(
        qrDialogPhase(next, lastPollRef.current, read().resolveFailureText),
      );
    },
    pollSeconds: read().pollSeconds,
    maxPollErrors: read().maxPollErrors,
  });
}

/**
 * 挂载 / 卸载生命周期契约：挂载即拉码，卸载清理即中断轮询与在途拉码
 * （§3.3「卸载中断轮询」）。组件壳 useEffect 与测试共用此函数——node 测试
 * 环境跑不了 effect，契约本身在此单测钉死。
 */
export function qrPanelLifecycle(controller: QRPanelController): () => void {
  controller.refresh();
  return () => controller.dispose();
}

export function QRCodeDialog(props: QRCodeDialogProps): ReactNode {
  const [phase, setPhase] = useState<QRPanelPhase>({ kind: 'fetching' });
  const propsRef = useRef(props);
  propsRef.current = props;
  const [controller] = useState<QRPanelController>(() =>
    createQRDialogController(() => propsRef.current, setPhase),
  );

  // 挂载即拉码；卸载中断轮询与在途拉码（§3.3，生命周期契约在 qrPanelLifecycle）。
  useEffect(() => qrPanelLifecycle(controller), [controller]);

  const Modal = props.modal;
  return (
    <Modal
      visible
      title={props.title}
      hasCancel={false}
      okText={t('common.close')}
      closable
      closeOnEsc
      maskClosable={false}
      onOk={props.onClose}
      onCancel={props.onClose}
    >
      <QRCodePanelView phase={phase} onRefresh={() => controller.refresh()} />
      {props.children}
    </Modal>
  );
}
