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
 * 消费方把 dialogProps 铺给 <CaptchaDialog />，渲染位置须在任何滚动 /
 * transform 祖先之外（壳已脱体到 body，此处只要求节点挂在调用方根级）。
 */
import { useCallback, useRef, useState } from 'react';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
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

export function useCaptchaGate(): CaptchaGate {
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
    dialogProps: { session, onConfirm, onNotReady, onCancel },
    run,
  };
}
