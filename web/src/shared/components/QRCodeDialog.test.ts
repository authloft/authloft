// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, describe, expect, test, rs } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM、SSR 不跑 effect）：渲染断言走
// renderToStaticMarkup（沿 components.test.ts 口径）；组件壳的挂载 / 卸载
// 生命周期、轮询接线与 failed 文案拦截抽在 QRCodeDialog 的纯缝导出上直驱
// （替身控制器 / 替身 props 观察），不依赖真实 Semi / login Modal。
import { renderToStaticMarkup } from 'react-dom/server';
import { create, type MessageInitShape } from '@bufbuild/protobuf';
import {
  LoginFlowResponseSchema,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import {
  CreateQrcodeResponseSchema,
  type CreateQrcodeResponse,
} from '../../gen/proto/api/sso/v1/ticket_pb';
import type { ModalProps } from './modal';
import {
  createQRDialogController,
  qrDialogPhase,
  QRCodeDialog,
  qrPanelLifecycle,
  type QRCodeDialogProps,
} from './QRCodeDialog';
import {
  qrFailureText,
  type QRPanelController,
  type QRPanelPhase,
} from './QRCodePanel';

const { createElement } = React;
rs.stubGlobal('React', React);

afterAll(() => {
  rs.unstubAllGlobals();
});

afterEach(() => {
  rs.useRealTimers();
});

const noop = () => {};

/** 生成物消息构造（报文类型只从 gen 引用，禁止手写 interface 重复描述）。 */
function envelope(
  init: MessageInitShape<typeof LoginFlowResponseSchema> = {},
): LoginFlowResponse {
  return create(LoginFlowResponseSchema, init);
}

function qrcodeResponse(
  seq: number,
  init: MessageInitShape<typeof CreateQrcodeResponseSchema> = {},
): CreateQrcodeResponse {
  return create(CreateQrcodeResponseSchema, {
    ticket: `tk-${seq}`,
    ticketId: `id-${seq}`,
    qrcodeUrl: `https://cdn.example/q${seq}.jpg`,
    expiresIn: BigInt(600),
    ...init,
  });
}

/** 记录本轮注入 Modal 实际收到的 props，并把内容渲染进静态 markup。 */
let lastProps: ModalProps | undefined;
function ProbeModal(props: ModalProps) {
  lastProps = props;
  return createElement(
    'section',
    { 'data-visible': String(props.visible) },
    props.title,
    props.children,
  );
}

type DialogPropsOverride = Partial<QRCodeDialogProps>;

function renderDialog(props: DialogPropsOverride = {}) {
  lastProps = undefined;
  return renderToStaticMarkup(
    createElement(QRCodeDialog, {
      modal: ProbeModal,
      requestQR: () => Promise.resolve(qrcodeResponse(1)),
      pollUrl: () => new Promise<LoginFlowResponse>(() => {}),
      onResult: noop,
      ...props,
    }),
  );
}

/** url 模式 active 态（其余码源字段零值），缩短非 failed 帧透传用例的构造。 */
function activePending(): QRPanelPhase {
  return {
    kind: 'active',
    mode: 'url',
    qrcodeUrl: 'https://cdn.example/q1.jpg',
    qrcodeContent: '',
    qrcodeBase64: '',
    tipHtml: '',
    ticketStatus: 'pending',
  };
}

describe('qrDialogPhase（failed 帧文案拦截，域内 bindFailureText 经此缝注入）', () => {
  const settledFailed = envelope({
    status: 'target_taken',
    ticket: { status: 'failed', ticketId: 'id-1' },
    error: { message: '该账号已被其他账号绑定' },
  });

  test('failed 帧 + 本轮落定信封：resolveFailureText 覆盖面板 message', () => {
    expect(
      qrDialogPhase(
        { kind: 'failed', message: '该手机号/邮箱已被占用' },
        settledFailed,
        () => '该账号已被其他账号绑定',
      ),
    ).toEqual({ kind: 'failed', message: '该账号已被其他账号绑定' });
  });

  test('resolver 缺省 → 走 qrFailureText（信封顶层 status → errors.status.*）', () => {
    const out = qrDialogPhase(
      { kind: 'failed', message: '占位' },
      settledFailed,
      undefined,
    );
    expect(out).toEqual({
      kind: 'failed',
      message: qrFailureText(settledFailed),
    });
    expect((out as { message: string }).message).toBe('该手机号/邮箱已被占用');
  });

  test('非 failed 帧一律透传（fetching / active / expired / success）', () => {
    expect(
      qrDialogPhase({ kind: 'fetching' }, settledFailed, () => 'x'),
    ).toEqual({ kind: 'fetching' });
    expect(qrDialogPhase(activePending(), settledFailed, () => 'x')).toEqual(
      activePending(),
    );
    expect(
      qrDialogPhase({ kind: 'expired' }, settledFailed, () => 'x'),
    ).toEqual({
      kind: 'expired',
    });
    expect(
      qrDialogPhase({ kind: 'success' }, settledFailed, () => 'x'),
    ).toEqual({
      kind: 'success',
    });
  });

  test('failed 帧 + 无信封（拉码失败 / 首轮连续超错）：保持面板文案，不空解', () => {
    const frame: QRPanelPhase = { kind: 'failed', message: '该登录渠道未启用' };
    expect(qrDialogPhase(frame, undefined, () => 'x')).toBe(frame);
  });

  test('failed 帧 + 信封非 failed：守卫挡掉陈旧替换（连续超错前最后成功信封为 pending；上一轮 expired）', () => {
    const pendingEnvelope = envelope({
      status: 'pending',
      ticket: { status: 'pending', ticketId: 'id-1' },
    });
    const expiredEnvelope = envelope({
      status: 'expired',
      ticket: { status: 'expired', ticketId: 'id-1' },
    });
    const frame: QRPanelPhase = {
      kind: 'failed',
      message: '操作失败，请稍后重试',
    };
    expect(qrDialogPhase(frame, pendingEnvelope, () => 'x')).toBe(frame);
    expect(qrDialogPhase(frame, expiredEnvelope, () => 'x')).toBe(frame);
  });
});

describe('createQRDialogController（装配缝：接线透传 + failed 拦截端到端）', () => {
  /** 组件壳同形的读 props 缝：每断言一帧。 */
  function harness(
    props: DialogPropsOverride,
    setPhase: (p: QRPanelPhase) => void,
  ) {
    return createQRDialogController(
      () => ({
        modal: ProbeModal,
        requestQR: () => Promise.resolve(qrcodeResponse(1)),
        pollUrl: () => new Promise<LoginFlowResponse>(() => {}),
        onResult: noop,
        ...props,
      }),
      setPhase,
    );
  }

  test('onResult 透传整个信封（登录读 .login、绑定读 .bind 都拿全量；引用同一信封）', async () => {
    rs.useFakeTimers();
    const results: LoginFlowResponse[] = [];
    const success = envelope({
      status: 'success',
      ticket: { status: 'success', ticketId: 'id-1' },
      login: envelope({ status: 'success' }),
    });
    const controller = harness(
      {
        pollUrl: () => Promise.resolve(success),
        onResult: (e) => results.push(e),
      },
      () => {},
    );
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(results).toHaveLength(1);
    expect(results[0]).toBe(success);
    controller.dispose();
  });

  test('onResult 仅 success 落定触发；pending / scanned / expired 不触发且帧透传', async () => {
    rs.useFakeTimers();
    const results: LoginFlowResponse[] = [];
    const phases: QRPanelPhase[] = [];
    const seq = [
      envelope({
        status: 'pending',
        ticket: { status: 'pending', ticketId: 'id-1' },
      }),
      envelope({
        status: 'scanned',
        ticket: { status: 'scanned', ticketId: 'id-1' },
      }),
      envelope({
        status: 'expired',
        ticket: { status: 'expired', ticketId: 'id-1' },
      }),
    ];
    let calls = 0;
    const controller = createQRDialogController(
      () => ({
        modal: ProbeModal,
        requestQR: () => Promise.resolve(qrcodeResponse(1)),
        pollUrl: () => {
          const index = calls;
          calls += 1;
          return index < seq.length
            ? Promise.resolve(seq[index]!)
            : new Promise<LoginFlowResponse>(() => {});
        },
        onResult: (e) => results.push(e),
      }),
      (p) => phases.push(p),
    );
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(results).toHaveLength(0);
    expect(phases[phases.length - 1]).toEqual({ kind: 'expired' });
    controller.dispose();
  });

  test('接线：requestQR 收中断 signal；pollUrl 收码 ticket + signal', async () => {
    rs.useFakeTimers();
    const qrSignals: AbortSignal[] = [];
    const pollTickets: string[] = [];
    const pollSignals: AbortSignal[] = [];
    const controller = createQRDialogController(
      () => ({
        modal: ProbeModal,
        requestQR: (signal) => {
          qrSignals.push(signal);
          return Promise.resolve(qrcodeResponse(1));
        },
        pollUrl: (ticket, signal) => {
          pollTickets.push(ticket);
          pollSignals.push(signal);
          return new Promise<LoginFlowResponse>(() => {});
        },
        onResult: noop,
      }),
      () => {},
    );
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(qrSignals).toHaveLength(1);
    expect(qrSignals[0]).toBeInstanceOf(AbortSignal);
    expect(pollTickets).toEqual(['tk-1']);
    expect(pollSignals[0]).toBeInstanceOf(AbortSignal);
    controller.dispose();
  });

  test('failed 落定：resolveFailureText 覆盖端到端；缺省走 qrFailureText', async () => {
    rs.useFakeTimers();
    const targetTaken = envelope({
      status: 'target_taken',
      ticket: { status: 'failed', ticketId: 'id-1' },
      error: { message: '该账号已被其他账号绑定' },
    });
    const custom: QRPanelPhase[] = [];
    const controller = createQRDialogController(
      () => ({
        modal: ProbeModal,
        requestQR: () => Promise.resolve(qrcodeResponse(1)),
        pollUrl: () => Promise.resolve(targetTaken),
        onResult: noop,
        resolveFailureText: () => '该账号已被其他账号绑定',
      }),
      (p) => custom.push(p),
    );
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(custom[custom.length - 1]).toEqual({
      kind: 'failed',
      message: '该账号已被其他账号绑定',
    });
    controller.dispose();

    const fallback: QRPanelPhase[] = [];
    const controller2 = createQRDialogController(
      () => ({
        modal: ProbeModal,
        requestQR: () => Promise.resolve(qrcodeResponse(1)),
        pollUrl: () => Promise.resolve(targetTaken),
        onResult: noop,
      }),
      (p) => fallback.push(p),
    );
    controller2.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(fallback[fallback.length - 1]).toEqual({
      kind: 'failed',
      message: qrFailureText(targetTaken),
    });
    controller2.dispose();
  });

  test('重拉后拉码失败不复用上一轮信封文案（fetching 作废旧信封）', async () => {
    rs.useFakeTimers();
    const phases: QRPanelPhase[] = [];
    let qrRound = 0;
    let pollRound = 0;
    const controller = createQRDialogController(
      () => ({
        modal: ProbeModal,
        requestQR: () => {
          qrRound += 1;
          if (qrRound >= 2) {
            return Promise.reject(new Error('network down'));
          }
          return Promise.resolve(qrcodeResponse(qrRound));
        },
        pollUrl: () => {
          pollRound += 1;
          if (pollRound === 1) {
            return Promise.resolve(
              envelope({
                status: 'target_taken',
                ticket: { status: 'failed', ticketId: 'id-1' },
              }),
            );
          }
          return new Promise<LoginFlowResponse>(() => {});
        },
        onResult: noop,
        resolveFailureText: () => '该账号已被其他账号绑定',
      }),
      (p) => phases.push(p),
    );
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(phases[phases.length - 1]).toEqual({
      kind: 'failed',
      message: '该账号已被其他账号绑定',
    });
    // 第二轮拉码失败：信封已在 fetching 作废，文案回到面板拉码失败兜底。
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(phases[phases.length - 1]).toEqual({
      kind: 'failed',
      message: '操作失败，请稍后重试',
    });
    controller.dispose();
  });
});

describe('qrPanelLifecycle（挂载即 refresh / 卸载即 dispose 契约）', () => {
  test('替身控制器：绑定即 refresh，清理即 dispose', () => {
    const calls: string[] = [];
    const controller: QRPanelController = {
      refresh: () => {
        calls.push('refresh');
      },
      dispose: () => {
        calls.push('dispose');
      },
    };
    const cleanup = qrPanelLifecycle(controller);
    expect(calls).toEqual(['refresh']);
    cleanup();
    expect(calls).toEqual(['refresh', 'dispose']);
  });

  test('真控制器：绑定即拉码，dispose 后 refresh 为 no-op（不再拉码）', async () => {
    rs.useFakeTimers();
    let qrCalls = 0;
    const controller = createQRDialogController(
      () => ({
        modal: ProbeModal,
        requestQR: () => {
          qrCalls += 1;
          return Promise.resolve(qrcodeResponse(1));
        },
        pollUrl: () => new Promise<LoginFlowResponse>(() => {}),
        onResult: noop,
      }),
      () => {},
    );
    const cleanup = qrPanelLifecycle(controller);
    await rs.advanceTimersByTimeAsync(0);
    expect(qrCalls).toBe(1);
    cleanup();
    controller.refresh(); // dispose 后刷新为 no-op（disposed 检查）
    await rs.advanceTimersByTimeAsync(0);
    expect(qrCalls).toBe(1);
    controller.dispose();
  });
});

describe('QRCodeDialog 壳 → 注入窗体（Semi 风格 props 透传）', () => {
  test('开窗即渲染：visible / 标题 / 拉码中初始帧；footer 单按钮（hasCancel=false + okText=关闭）', () => {
    const markup = renderDialog({ title: '扫码登录' });
    expect(markup).toContain('data-visible="true"');
    expect(markup).toContain('扫码登录');
    expect(markup).toContain('正在获取二维码');
    expect(lastProps).toMatchObject({
      visible: true,
      title: '扫码登录',
      hasCancel: false,
      okText: '关闭',
      closable: true,
      closeOnEsc: true,
      maskClosable: false,
    });
  });

  test('SSR 不发请求（拉码 / 轮询由客户端挂载 effect 发起，窗体壳同构约束）', () => {
    let qrCalls = 0;
    let pollCalls = 0;
    renderDialog({
      requestQR: () => {
        qrCalls += 1;
        return Promise.resolve(qrcodeResponse(1));
      },
      pollUrl: () => {
        pollCalls += 1;
        return new Promise<LoginFlowResponse>(() => {});
      },
    });
    expect(qrCalls).toBe(0);
    expect(pollCalls).toBe(0);
  });

  test('children 渲染在面板视图之后', () => {
    const markup = renderDialog({
      children: createElement('p', { 'data-marker': 'extra' }, '附加内容'),
    });
    const panelAt = markup.indexOf('正在获取二维码');
    const extraAt = markup.indexOf('附加内容');
    expect(panelAt).toBeGreaterThan(-1);
    expect(extraAt).toBeGreaterThan(panelAt);
    expect(markup).toContain('data-marker="extra"');
  });

  test('关窗动作统一上抛 onClose：onOk / onCancel / 底部按钮同源（弹窗自身不消失）', () => {
    let closed = 0;
    renderDialog({
      onClose: () => {
        closed += 1;
      },
    });
    expect(lastProps?.onOk).toBeDefined();
    expect(lastProps?.onOk).toBe(lastProps?.onCancel);
    lastProps?.onOk?.({} as React.SyntheticEvent);
    lastProps?.onCancel?.({} as React.SyntheticEvent);
    expect(closed).toBe(2);
  });
});
