/**
 * captcha 弹窗 hook：把 captchaGate 的纯编排接到 React 状态上。
 *
 * 持开窗态（配置 / 第几次询问 / 在途 / 错误位）与一个待兑现的 Promise：
 * gate 每次询问 → 开窗并挂起，用户确认 → 取凭据兑现、gate 继续重提原请求，
 * 用户取消 → 兑现 undefined、gate 终止。终局（成功 / 逃逸 / 错误）一律关窗。
 *
 * 弹窗保持打开跨越 captcha_invalid 循环——确认后置 submitting，请求在途时
 * 禁用两个按钮防重复消费凭据；gate 再次询问才解禁并换新凭据。
 *
 * 消费方把 dialogProps 铺给 <CaptchaDialog />，并按 domain 注入窗体实现
 * （login 传 login/components/Modal，account / admin 传 shared/app-ui/Modal）；
 * 窗体自己脱体到 body，此处只要求节点挂在调用方根级。窗体 props 沿用 Semi
 * Modal 同名字段，在途禁动由 CaptchaDialog 用 confirmLoading / closeOnEsc 等
 * 显式表达（契约见 shared/components/modal）。
 */
import { useCallback, useRef, useState } from 'react';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import type { ModalRenderer } from '../components/modal';
import type { CaptchaDialogProps, CaptchaDialogSession } from './CaptchaDialog';
import {
  runCaptchaGate,
  type CaptchaGateOptions,
  type CaptchaGateResult,
  type CaptchaPrompt,
} from './captchaGate';

/** run 的入参：弹窗询问由本 hook 提供，调用方只给请求与判读。 */
export type CaptchaGateRunOptions<T> = Omit<CaptchaGateOptions<T>, 'prompt'>;

export interface CaptchaGate {
  dialogProps: CaptchaDialogProps;
  run<T>(options: CaptchaGateRunOptions<T>): Promise<CaptchaGateResult<T>>;
}

/** modal 为 domain 窗体实现（契约见 shared/components/modal），烘进 dialogProps。 */
export function useCaptchaGate(modal: ModalRenderer): CaptchaGate {
  const [session, setSession] = useState<CaptchaDialogSession | undefined>(
    undefined,
  );
  const resolverRef = useRef<
    ((token: CaptchaPayload | undefined) => void) | undefined
  >(undefined);

  const prompt = useCallback(
    (next: CaptchaPrompt) =>
      new Promise<CaptchaPayload | undefined>((resolve) => {
        resolverRef.current = resolve;
        setSession({
          config: next.config,
          attempt: next.attempt,
          submitting: false,
          errorKey: next.invalid ? 'errors.status.captcha_invalid' : undefined,
        });
      }),
    [],
  );

  /** 兑现当前询问并清空 resolver（确认与取消共用；重复调用无副作用）。 */
  const settle = useCallback((token: CaptchaPayload | undefined) => {
    const resolve = resolverRef.current;
    resolverRef.current = undefined;
    resolve?.(token);
  }, []);

  const onConfirm = useCallback(
    (token: CaptchaPayload) => {
      setSession((prev) =>
        prev === undefined
          ? prev
          : { ...prev, submitting: true, errorKey: undefined },
      );
      settle(token);
    },
    [settle],
  );

  const onNotReady = useCallback(() => {
    setSession((prev) =>
      prev === undefined
        ? prev
        : { ...prev, errorKey: 'errors.status.captcha_required' },
    );
  }, []);

  const onCancel = useCallback(() => {
    setSession(undefined);
    settle(undefined);
  }, [settle]);

  const run = useCallback(
    async <T>(
      options: CaptchaGateRunOptions<T>,
    ): Promise<CaptchaGateResult<T>> => {
      try {
        return await runCaptchaGate<T>({ ...options, prompt });
      } finally {
        // 终局关窗：成功 / 逃逸给状态机 / 错误三条路径都不留残窗。
        resolverRef.current = undefined;
        setSession(undefined);
      }
    },
    [prompt],
  );

  return {
    dialogProps: { modal, session, onConfirm, onNotReady, onCancel },
    run,
  };
}
