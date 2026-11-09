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
 * 文案经 shared/i18n（account.* 域键 + errors.status.captcha_required /
 * channels.email 复用）。
 */
import { useRef, useState, type ReactNode, type Ref } from 'react';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { Button, Input } from '@douyinfe/semi-ui';
import type { OkResponse } from '../../../gen/proto/api/account/v1/profile_pb';
import type {
  BindEmailRequest,
  BindPhoneRequest,
} from '../../../gen/proto/api/account/v1/security_pb';
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import {
  CaptchaWidget,
  type CaptchaWidgetHandle,
} from '../../../shared/captcha/CaptchaWidget';
import {
  CodeInput,
  DEFAULT_CODE_LENGTH,
} from '../../../shared/components/CodeInput';
import {
  deriveRequestStatus,
  type RequestStatus,
} from '../../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../../shared/hooks/requestOptions';
import { useCountdown } from '../../../shared/hooks/useCountdown';
import { t } from '../../../shared/i18n';
import {
  accountReturnTo,
  apiErrorText,
  bindEmail,
  bindPhone,
  buildBindChallengeRequest,
  buildBindVerifyRequest,
  getProfile,
  type ContactBindChallengeError,
  type ContactBindKind,
} from '../../api';
import styles from './ContactBindForm.module.less';

/** 三步状态机（§3.4 两步 + 成功帧）。 */
export type ContactBindStep = 'challenge' | 'verify' | 'done';

/** 重发冷却秒数（A-2：发码成功后倒计时，期间禁用重发；login OTPForm 同款口径）。 */
const RESEND_COOLDOWN_SECONDS = BigInt(60);

/** 本地校验文案（shared/i18n 域键；「请完成人机校验」复用 errors.status.captcha_required）。 */
function inputErrorText(
  kind: ContactBindKind,
  error: ContactBindChallengeError | 'invalid_code',
): string {
  switch (error) {
    case 'invalid_target':
      return t(
        kind === 'phone'
          ? 'account.bindInvalidPhone'
          : 'account.bindInvalidEmail',
      );
    case 'captcha_missing':
      return t('errors.status.captcha_required');
    case 'invalid_code':
      return t('account.bindCodeInvalid', { count: DEFAULT_CODE_LENGTH });
  }
}

/**
 * 绑定帧视图（纯渲染，无请求）：challenge（目标 + captcha）→ verify
 * （分段验证码 + 重新发送）→ done（成功 + 继续）。
 */
export function ContactBindFormView(props: {
  kind: ContactBindKind;
  captcha: CaptchaConfig;
  /** CaptchaWidget 句柄（getToken / reset，§3.5 行 351 生命周期归调用方）。 */
  captchaRef: Ref<CaptchaWidgetHandle>;
  step: ContactBindStep;
  target: string;
  code: string;
  /** 当前已绑定值（GetProfile 服务端脱敏字段，A-2 回显；未绑定 / 未加载 → undefined 不渲染）。 */
  currentValue: string | undefined;
  /** 当前绑定值已验证（phoneVerified / emailVerified 非 0）。 */
  currentVerified: boolean;
  /** 重发倒计时剩余秒（A-2）；expired=false 期间禁用重发。 */
  resendSeconds: number;
  resendExpired: boolean;
  challengeStatus: RequestStatus;
  verifyStatus: RequestStatus;
  inputError: ContactBindChallengeError | 'invalid_code' | undefined;
  challengeError: unknown;
  verifyError: unknown;
  onTargetChange: (value: string) => void;
  onCodeChange: (value: string) => void;
  onChallenge: () => void;
  onVerify: () => void;
  onResend: () => void;
  onRestart: () => void;
}): ReactNode {
  const kindLabel =
    props.kind === 'phone' ? t('account.phoneLabel') : t('channels.email');

  if (props.step === 'done') {
    return (
      <div role="status" className={styles.done}>
        <p className={styles.doneText}>
          {t('account.bindDone', { kind: kindLabel })}
        </p>
        <Button onClick={props.onRestart}>{t('account.bindContinue')}</Button>
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
          {t('account.bindCodeSentToPrefix')}{' '}
          <span className={styles.target}>{props.target}</span>
        </p>
        <CodeInput
          value={props.code}
          onChange={props.onCodeChange}
          length={DEFAULT_CODE_LENGTH}
          ariaLabel={t('account.bindCodeAria', { kind: kindLabel })}
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
            {t('account.bindConfirmAction')}
          </Button>
          {/* A-2：发码后重发冷却倒计时，期间禁用并显示剩余秒数。 */}
          <Button
            type="tertiary"
            onClick={props.onResend}
            disabled={verifying || !props.resendExpired}
          >
            {props.resendExpired
              ? t('account.bindResendAction')
              : t('account.bindResendCountdown', {
                  seconds: props.resendSeconds,
                })}
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
      {/* A-2：回显当前已绑定值（GetProfile 服务端脱敏），让用户知道换掉的是什么。 */}
      {props.currentValue !== undefined && props.currentValue !== '' ? (
        <p className={styles.targetLine}>
          {props.currentVerified
            ? t('account.bindCurrentVerified', { value: props.currentValue })
            : t('account.bindCurrentValue', { value: props.currentValue })}
        </p>
      ) : null}
      <div className={styles.field}>
        <label
          className={styles.label}
          htmlFor={`account-bind-${props.kind}-target`}
        >
          {kindLabel}
        </label>
        <Input
          id={`account-bind-${props.kind}-target`}
          value={props.target}
          onChange={props.onTargetChange}
          placeholder={
            props.kind === 'phone'
              ? t('account.phonePlaceholder')
              : t('account.emailPlaceholder')
          }
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
        {t('account.sendCodeAction')}
      </Button>
    </form>
  );
}

/** 绑定状态壳：challenge / verify 两步请求 + 三步状态机。 */
export function ContactBindForm(props: {
  /** 绑定目标类型（§3.4：phone 走 BindPhone，email 走 BindEmail）。 */
  kind: ContactBindKind;
  /** captcha 配置（§5 行 482：调用方从 GetConfig 注入，account 不读注入快照）。 */
  captcha: CaptchaConfig;
  /** verify 成功回调（目标已绑定，调用方可刷新资料展示）。 */
  onBound?: (target: string) => void;
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
  const call = (
    request: BindPhoneRequest | BindEmailRequest,
  ): Promise<OkResponse> =>
    request.$typeName === 'api.account.v1.BindPhoneRequest'
      ? bindPhone(request)
      : bindEmail(request);
  const location = useLocation();
  const returnTo = () => accountReturnTo(location.pathname, location.search);
  // challenge（手动）：错误行内呈现（toast:false）。竞态说明（§5.2/R3）：
  // 同实例并发提交不可达——发送按钮按 loading 禁用，challenge / verify 各持
  // 独立实例，旧响应落地仅影响本实例 state。
  const challenge = useRequest(call, {
    manual: true,
    ...requestOptions({ toast: false, returnTo }),
  });
  // verify（手动）：错误行内呈现；成功链走 onSuccess——done 帧 + 上抛 +
  // 重取资料刷新「当前」回显行。
  const verify = useRequest(call, {
    manual: true,
    ...requestOptions({ toast: false, returnTo }),
    onSuccess: () => {
      setStep('done');
      onBound?.(target);
      refreshProfile();
    },
  });
  // A-2：当前已绑定值回显（GetProfile 服务端脱敏字段；不改 SecurityPage 传参，
  // 组件自取）——自动请求（挂载即取），绑定成功后 refresh 刷新。
  const { data: profile, refresh: refreshProfile } = useRequest(
    getProfile,
    requestOptions({ toast: false, returnTo }),
  );
  const currentValue = kind === 'phone' ? profile?.phone : profile?.email;
  const currentVerified =
    (kind === 'phone' ? profile?.phoneVerified : profile?.emailVerified) !==
      undefined &&
    (kind === 'phone' ? profile?.phoneVerified : profile?.emailVerified) !==
      BigInt(0);
  // A-2：重发冷却倒计时——challenge 步 undefined（无倒计时），进 verify（发码
  // 成功）起 60s；重发回 challenge 再进 verify 时 undefined↔60 切换重启倒计时。
  const cooldown = useCountdown(
    step === 'verify' ? RESEND_COOLDOWN_SECONDS : undefined,
  );

  const submitChallenge = () => {
    const built = buildBindChallengeRequest(
      kind,
      target,
      captchaRef.current?.getToken(),
    );
    if (!built.ok) {
      setInputError(built.error);
      return;
    }
    setInputError(undefined);
    // §5.4-#1（固定 runAsync）：challenge 失败须重置 captcha（本次
    // token 已被消费，§3.4 行 880）——调用方降级处理错误，runAsync 正当
    // 场景③；集中 onError 同时静默（toast:false，行内错误帧呈现）。
    challenge
      .runAsync(built.request)
      .then(() => {
        setStep('verify');
      })
      .catch(() => {
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
    // 成功链在 onSuccess；错误进集中 onError（静默，行内 apiErrorText 呈现）。
    verify.run(built.request);
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
      currentValue={currentValue}
      currentVerified={currentVerified}
      resendSeconds={cooldown.seconds}
      resendExpired={cooldown.expired}
      challengeStatus={deriveRequestStatus(
        challenge.loading,
        challenge.error,
        challenge.data,
      )}
      verifyStatus={deriveRequestStatus(
        verify.loading,
        verify.error,
        verify.data,
      )}
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
