/**
 * 绑定 / 换绑手机号与邮箱表单（docs/前端架构.md §5 行 482；docs/接口文档.md
 * §3.4 行 865-882 / §10.9 时序）：两步同端点——challenge{target, captcha} →
 * verify{target, code}；captcha 配置由调用方从 GetConfig 注入（§5 行 482：
 * account entry 不从注入快照取）；verify 回传与 challenge 相同的 target
 * （行 881-882：服务端按 target 拼键取码并校验码内 uid 归属）。
 *
 * 状态机：challenge（发码）→ verify（验码）→ done（成功帧）；「重新发送」
 * 回 challenge 并 reset captcha（上一次已被消费，§3.4 行 880）。
 * 请求构造纯逻辑在 ./api（node 可测；Semi 渲染测试 blocker 见
 * account.test.tsx 头注）；target_taken（新号码被占用）/ invalid_code（码
 * 归属校验）等服务端错误经 apiErrorText → shared/i18n 字典出文案。
 * 文案无 i18n 键：中文字面量 + 注释声明，扩键归后续 i18n 实现。
 */
import { useRef, useState, type ReactNode, type Ref } from 'react';
// 子路径 import（同 ProfilePage 口径：避免全量入口，测试链 / 产物见其注释）。
import Button from '@douyinfe/semi-ui/lib/es/button';
import Input from '@douyinfe/semi-ui/lib/es/input';
import type { OkResponse } from '../../gen/proto/api/account/v1/profile_pb';
import type {
  BindEmailRequest,
  BindPhoneRequest,
} from '../../gen/proto/api/account/v1/security_pb';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import { CaptchaWidget, type CaptchaWidgetHandle } from '../../shared/captcha/CaptchaWidget';
import { CodeInput, DEFAULT_CODE_LENGTH } from '../../shared/components/CodeInput';
import { useRequest, type RequestStatus } from '../../shared/hooks/useRequest';
import {
  apiErrorText,
  bindEmail,
  bindPhone,
  buildBindChallengeRequest,
  buildBindVerifyRequest,
  type ContactBindChallengeError,
  type ContactBindKind,
} from '../api';
import styles from './ContactBindForm.module.less';

/** 三步状态机（§3.4 两步 + 成功帧）。 */
export type ContactBindStep = 'challenge' | 'verify' | 'done';

/** 本地校验文案（i18n 无键，中文字面量，归后续 i18n 实现）。 */
function inputErrorText(
  kind: ContactBindKind,
  error: ContactBindChallengeError | 'invalid_code',
): string {
  switch (error) {
    case 'invalid_target':
      return kind === 'phone' ? '请输入正确的手机号' : '请输入正确的邮箱';
    case 'captcha_missing':
      return '请完成人机校验';
    case 'invalid_code':
      return `请输入 ${DEFAULT_CODE_LENGTH} 位数字验证码`;
  }
}

/**
 * 绑定帧视图（纯渲染，无请求）：challenge（目标 + captcha）→ verify
 * （分段验证码 + 重新发送）→ done（成功 + 继续）。
 */
export function ContactBindFormView(props: {
  readonly kind: ContactBindKind;
  readonly captcha: CaptchaConfig;
  /** CaptchaWidget 句柄（getToken / reset，§3.5 行 351 生命周期归调用方）。 */
  readonly captchaRef: Ref<CaptchaWidgetHandle>;
  readonly step: ContactBindStep;
  readonly target: string;
  readonly code: string;
  readonly challengeStatus: RequestStatus;
  readonly verifyStatus: RequestStatus;
  readonly inputError: ContactBindChallengeError | 'invalid_code' | undefined;
  readonly challengeError: unknown;
  readonly verifyError: unknown;
  readonly onTargetChange: (value: string) => void;
  readonly onCodeChange: (value: string) => void;
  readonly onChallenge: () => void;
  readonly onVerify: () => void;
  readonly onResend: () => void;
  readonly onRestart: () => void;
}): ReactNode {
  const kindLabel = props.kind === 'phone' ? '手机号' : '邮箱';

  if (props.step === 'done') {
    return (
      <div role="status" className={styles.done}>
        <p className={styles.doneText}>{kindLabel}绑定成功</p>
        <Button onClick={props.onRestart}>继续绑定 / 换绑</Button>
      </div>
    );
  }

  if (props.step === 'verify') {
    const verifying = props.verifyStatus === 'loading';
    return (
      <form
        className={styles.form}
        onSubmit={(event) => {
          event.preventDefault();
          props.onVerify();
        }}
      >
        <p className={styles.targetLine}>
          验证码已发送至 <span className={styles.target}>{props.target}</span>
        </p>
        <CodeInput
          value={props.code}
          onChange={props.onCodeChange}
          length={DEFAULT_CODE_LENGTH}
          ariaLabel={`${kindLabel}绑定验证码`}
          disabled={verifying}
        />
        {props.inputError !== undefined ? (
          <p role="alert" className={styles.error}>
            {inputErrorText(props.kind, props.inputError)}
          </p>
        ) : null}
        {props.verifyStatus === 'error' ? (
          <p role="alert" className={styles.error}>
            {apiErrorText(props.verifyError)}
          </p>
        ) : null}
        <div className={styles.actions}>
          <Button
            theme="solid"
            htmlType="submit"
            loading={verifying}
            disabled={verifying}
          >
            确认绑定
          </Button>
          <Button type="tertiary" onClick={props.onResend} disabled={verifying}>
            重新发送
          </Button>
        </div>
      </form>
    );
  }

  const challenging = props.challengeStatus === 'loading';
  return (
    <form
      className={styles.form}
      onSubmit={(event) => {
        event.preventDefault();
        props.onChallenge();
      }}
    >
      <div className={styles.field}>
        <label className={styles.label} htmlFor={`account-bind-${props.kind}-target`}>
          {kindLabel}
        </label>
        <Input
          id={`account-bind-${props.kind}-target`}
          value={props.target}
          onChange={props.onTargetChange}
          placeholder={props.kind === 'phone' ? '请输入手机号' : '请输入邮箱'}
          disabled={challenging}
        />
      </div>
      {/* captcha 必过（§3.4 行 880）：提交前 getToken，未就绪不发包。 */}
      <CaptchaWidget captcha={props.captcha} ref={props.captchaRef} />
      {props.inputError !== undefined ? (
        <p role="alert" className={styles.error}>
          {inputErrorText(props.kind, props.inputError)}
        </p>
      ) : null}
      {props.challengeStatus === 'error' ? (
        <p role="alert" className={styles.error}>
          {apiErrorText(props.challengeError)}
        </p>
      ) : null}
      <Button
        theme="solid"
        htmlType="submit"
        loading={challenging}
        disabled={challenging}
      >
        发送验证码
      </Button>
    </form>
  );
}

/** 绑定状态壳：challenge / verify 两步请求 + 三步状态机。 */
export function ContactBindForm(props: {
  /** 绑定目标类型（§3.4：phone 走 BindPhone，email 走 BindEmail）。 */
  readonly kind: ContactBindKind;
  /** captcha 配置（§5 行 482：调用方从 GetConfig 注入，account 不读注入快照）。 */
  readonly captcha: CaptchaConfig;
  /** verify 成功回调（目标已绑定，调用方可刷新资料展示）。 */
  readonly onBound?: (target: string) => void;
}): ReactNode {
  const { kind, captcha, onBound } = props;
  const [step, setStep] = useState<ContactBindStep>('challenge');
  const [target, setTarget] = useState('');
  const [code, setCode] = useState('');
  const [inputError, setInputError] = useState<
    ContactBindChallengeError | 'invalid_code' | undefined
  >(undefined);
  const captchaRef = useRef<CaptchaWidgetHandle>(null);
  // kind 固定于表单实例，但请求构造返回 Bind 系联合类型——经 $typeName 判别
  // 收窄到具体端点（gen Message 的判别式属性，§9 第 15 条）。
  const call = (request: BindPhoneRequest | BindEmailRequest): Promise<OkResponse> =>
    request.$typeName === 'api.account.v1.BindPhoneRequest'
      ? bindPhone(request)
      : bindEmail(request);
  const challenge = useRequest(call);
  const verify = useRequest(call);

  const submitChallenge = () => {
    const built = buildBindChallengeRequest(kind, target, captchaRef.current?.getToken());
    if (!built.ok) {
      setInputError(built.error);
      return;
    }
    setInputError(undefined);
    challenge
      .run(built.request)
      .then((result) => {
        if (result !== undefined) {
          setStep('verify');
        }
      })
      .catch(() => {
        // 本次 captcha 已被消费（§3.4 行 880 challenge 必过），重置供重试。
        captchaRef.current?.reset();
      });
  };

  const submitVerify = () => {
    const built = buildBindVerifyRequest(kind, target, code);
    if (!built.ok) {
      setInputError(built.error);
      return;
    }
    setInputError(undefined);
    verify
      .run(built.request)
      .then((result) => {
        if (result !== undefined) {
          setStep('done');
          onBound?.(target);
        }
      })
      .catch(() => {});
  };

  const resend = () => {
    setStep('challenge');
    setCode('');
    setInputError(undefined);
    captchaRef.current?.reset();
  };

  const restart = () => {
    setStep('challenge');
    setTarget('');
    setCode('');
    setInputError(undefined);
    captchaRef.current?.reset();
  };

  return (
    <ContactBindFormView
      kind={kind}
      captcha={captcha}
      captchaRef={captchaRef}
      step={step}
      target={target}
      code={code}
      challengeStatus={challenge.status}
      verifyStatus={verify.status}
      inputError={inputError}
      challengeError={challenge.error}
      verifyError={verify.error}
      onTargetChange={setTarget}
      onCodeChange={setCode}
      onChallenge={submitChallenge}
      onVerify={submitVerify}
      onResend={resend}
      onRestart={restart}
    />
  );
}
