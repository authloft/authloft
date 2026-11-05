/**
 * 重置密码页（docs/前端架构.md §4.4 行 465；docs/接口文档.md §2.4 / §10.4）：
 * - challenge → verify → set_password，最后一步只提交 password（§10.4 行 1532）；
 *   challenge 目标必须是已绑定且已验证的邮箱 / 手机号（未满足 →
 *   status=user_not_found，表单保留可换目标重试，§1.6 行 254）；
 * - methods 为空数组（flow=reset 只保留 otp_sms / otp_email，§2.1 行 412）或
 *   flags.passwordReset=false → 整页提示「找回密码未开放」；直访本页或任一
 *   step 收到 status=reset_disabled 时同文案提示并停止流程（§4.4 行 465）；
 * - set_password 步渲染 PasswordStrengthMeter（§5.6 同源规则，服务端权威）；
 *   成功后全部会话与令牌失效（§2.4 行 469），提示用新密码登录并给登录页
 *   链接（不自动跳转：文档未规定跳转目标）。
 *
 * 结构沿 LoginContainer / LoginFlowView 模式：ResetPageView 为纯状态帧视图
 * （renderToStaticMarkup 可测任意 status 帧），ResetPage 为状态壳。
 * 共用编排纯函数复用 RegisterPage 的导出（页族共用落点声明见该文件头）；
 * challenge 段复用 factors/OTPForm；verify 段自建（CodeInput + useCountdown，
 * 与 RegisterPage 同因：OTPForm verify 段提交按钮是 login 域文案「登录」）。
 *
 * 文案：重置页专属（标题 / 步骤按钮 / 成功提示）经 i18n 字典 login.* 键取用；
 * 关闭态提示复用 errors.status.reset_disabled。
 */
import { useEffect, useRef, useState, type FormEvent, type Ref } from 'react';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import { resolveFlowStatus } from '../../shared/api/errors';
import {
  CaptchaWidget,
  type CaptchaWidgetHandle,
} from '../../shared/captcha/CaptchaWidget';
import { CodeInput, ErrorBanner } from '../../shared/components';
import { PasswordStrengthMeter } from '../../shared/components/PasswordStrengthMeter';
import { useCountdown } from '../../shared/hooks/useCountdown';
import { t } from '../../shared/i18n';
import { toDisplay } from '../../shared/utils/int';
import type {
  LoginMethodEntry,
  MethodsSnapshot,
} from '../../shared/types/init';
import { resetPassword, type ResetPasswordInput } from '../api';
import { OTPForm } from '../factors/OTPForm';
import {
  advanceAfterStep,
  isFlowErrorStatus,
  RESTART_STATUSES,
  runFlowStep,
  snapshotFields,
  ssoPath,
  type FlowStep,
} from './RegisterPage';
import styles from './ResetPage.module.less';

/** 重置可用方式白名单（§2.1 行 412：flow=reset 只保留 otp_sms / otp_email，快照已过滤，此处防御性收窄）。 */
export function resetOptionsFor(
  snapshot: MethodsSnapshot,
): readonly LoginMethodEntry[] {
  return snapshot.methods.filter(
    (m) => m.method === 'otp_sms' || m.method === 'otp_email',
  );
}

/** ResetPayload 的 init 形状（login/api.ts 的 ResetPasswordInput.payload）。 */
type ResetPayloadInit = NonNullable<ResetPasswordInput['payload']>;

/**
 * 重置各 step 的 payload 组装（§2.4 行 462-466 字段表）：
 * challenge {email|phone, captcha} / verify {code} / set_password {password}
 * （最后一步只提交 password，§10.4 行 1532）。
 */
export function resetPayloadFor(
  step: FlowStep,
  values: Readonly<Record<string, string>>,
  captcha?: CaptchaPayload,
): ResetPayloadInit {
  if (step === 'challenge') {
    return {
      email: values.email ?? '',
      phone: values.phone ?? '',
      ...(captcha !== undefined ? { captcha } : {}),
    };
  }
  if (step === 'verify') {
    return { code: values.code ?? '' };
  }
  return { password: values.password ?? '' };
}

/** 验证码分段数（快照 codeLength，§2.1 行 391；缺失 / 非法兜底 6）。 */
function codeLengthOf(entry: LoginMethodEntry | undefined): number {
  const parsed = Number.parseInt(entry?.codeLength ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 6;
}

// ---------------------------------------------------------------------------
// 视图（纯状态帧渲染；renderToStaticMarkup 下不执行副作用）
// ---------------------------------------------------------------------------

/**
 * 重置方式 tab 文案键（快照 method → 重置语境名；i18n factors.* 是登录语境；
 * 未知 method 走 t() 键回显，与原字面量兜底同款）。
 */
const RESET_METHOD_NAME_KEYS: Readonly<Record<string, string>> = {
  otp_sms: 'login.resetMethodOtpSms',
  otp_email: 'login.resetMethodOtpEmail',
};

export interface ResetPageViewProps {
  /** 注入快照（§2.1，flow=reset）。 */
  readonly snapshot: MethodsSnapshot;
  /** 最近一次响应 status（初始 'idle'）。 */
  readonly status: string;
  /** 最近一次响应信封（失败态 ErrorBanner 字段来源）。 */
  readonly envelope: LoginFlowResponse | undefined;
  /** restart / 传输失败的一次性提示（i18nKey）。 */
  readonly notice?: string;
  /** 当前重置方式（快照 method）。 */
  readonly method: string;
  /** 当前请求侧 step。 */
  readonly step: FlowStep;
  /** 请求在途（提交按钮禁用，§3.2）。 */
  readonly loading: boolean;
  /** verify 段已输码（容器持值防实例重建丢失，同款语义）。 */
  readonly otpCode: string;
  /** set_password 段新密码（受控）。 */
  readonly password: string;
  onSelectMethod: (method: string) => void;
  /** 提交（challenge 段上抛目标 values；verify 段 {code}；set_password 段 {}）。 */
  onSubmit: (values: Readonly<Record<string, string>>) => void;
  onOtpCodeChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  /** verify 段重发（回到 challenge 段重走）。 */
  onResend: () => void;
  captchaRef?: Ref<CaptchaWidgetHandle>;
}

export function ResetPageView({
  snapshot,
  status,
  envelope,
  notice,
  method,
  step,
  loading,
  otpCode,
  password,
  onSelectMethod,
  onSubmit,
  onOtpCodeChange,
  onPasswordChange,
  onResend,
  captchaRef,
}: ResetPageViewProps) {
  const options = resetOptionsFor(snapshot);
  // verify 段重发倒计时（nextStep.retryAfter / error.retryAfter，§1.3 行 115/150）。
  const countdown = useCountdown(
    envelope?.nextStep?.retryAfter ?? envelope?.error?.retryAfter,
  );
  const entry = options.find((m) => m.method === method);

  // §4.4 行 465：methods 为空数组或 flags.passwordReset=false → 整页提示关闭。
  if (snapshot.flags?.passwordReset !== true || options.length === 0) {
    return (
      <main className={styles.page}>
        <h1 className={styles.title}>{t('login.reset')}</h1>
        <p role="status">{t('errors.status.reset_disabled')}</p>
      </main>
    );
  }
  // 任一 step 收到 reset_disabled → 提示并停止流程（§4.4 行 465 / §2.4 行 471）。
  if (status === 'reset_disabled') {
    return (
      <main className={styles.page}>
        <h1 className={styles.title}>{t('login.reset')}</h1>
        <p role="status">{t('errors.status.reset_disabled')}</p>
      </main>
    );
  }
  if (status === 'success') {
    return (
      <main className={styles.page}>
        <h1 className={styles.title}>{t('login.reset')}</h1>
        <p role="status">{t('login.resetSuccess')}</p>
        <a className={styles.loginLink} href={ssoPath('/sso/login')}>
          {t('login.goLogin')}
        </a>
      </main>
    );
  }

  const resolution = isFlowErrorStatus(status)
    ? resolveFlowStatus(status)
    : undefined;
  // §1.6「可重试 = 否」的失败态禁用提交（表单保留原地，不隐藏）。
  const submitDisabled = resolution !== undefined && !resolution.retryable;
  const error = envelope?.error;
  // captcha 渲染位置（§2.5 行 528：注册 / 重置的下发必须）：challenge 段渲染；
  // verify / set_password 的 payload 不含 captcha（§2.4 行 465-466），不渲染。
  const showCaptcha = step === 'challenge';
  // 权威 captcha 对象（§2.5 行 518）：响应顶层 captcha 优先，缺省回落快照首屏。
  const captchaConfig = envelope?.captcha ?? snapshot.captcha;

  const submitVerify = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!loading && !submitDisabled) {
      onSubmit({ code: otpCode });
    }
  };

  const submitSetPassword = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!loading && !submitDisabled) {
      onSubmit({});
    }
  };

  return (
    <main className={styles.page}>
      <h1 className={styles.title}>{t('login.reset')}</h1>
      {notice !== undefined && <ErrorBanner i18nKey={notice} />}
      {resolution !== undefined && (
        <ErrorBanner
          i18nKey={resolution.i18nKey}
          fallbackMessage={error?.message}
          retryAfter={error?.retryAfter}
          attemptsLeft={error?.attemptsLeft}
          retryable={resolution.retryable}
        />
      )}
      {options.length > 1 && (
        <nav>
          <ul className={styles.methodList}>
            {options.map((option) => (
              <li key={option.method}>
                <button
                  type="button"
                  className={
                    option.method === method
                      ? styles.methodTabActive
                      : styles.methodTab
                  }
                  aria-current={option.method === method ? 'true' : undefined}
                  onClick={() => onSelectMethod(option.method)}
                >
                  {t(RESET_METHOD_NAME_KEYS[option.method] ?? option.method)}
                </button>
              </li>
            ))}
          </ul>
        </nav>
      )}
      {step === 'challenge' && (
        <div className={styles.section}>
          <OTPForm
            fields={snapshotFields(entry?.challengeFields)}
            loading={loading}
            disabled={submitDisabled}
            onSubmit={onSubmit}
          />
          {showCaptcha && captchaConfig !== undefined && (
            <CaptchaWidget captcha={captchaConfig} ref={captchaRef} />
          )}
        </div>
      )}
      {step === 'verify' && (
        <form onSubmit={submitVerify} className={styles.section}>
          <label className={styles.label}>{t('login.codeLabel')}</label>
          <CodeInput
            value={otpCode}
            onChange={onOtpCodeChange}
            length={codeLengthOf(entry)}
            ariaLabel={t('login.codeLabel')}
            disabled={loading || submitDisabled}
          />
          {error?.attemptsLeft !== undefined && (
            <p role="status" className={styles.status}>
              {t('login.attemptsLeft', {
                count: toDisplay(error.attemptsLeft),
              })}
            </p>
          )}
          <button
            type="button"
            disabled={loading || !countdown.expired}
            onClick={onResend}
            className={styles.resend}
          >
            {countdown.expired
              ? t('login.resend')
              : t('login.resendCountdown', { seconds: countdown.seconds })}
          </button>
          <button
            type="submit"
            disabled={loading || submitDisabled}
            className={styles.submit}
          >
            {t('login.nextStep')}
          </button>
        </form>
      )}
      {step === 'set_password' && (
        <form onSubmit={submitSetPassword} className={styles.section}>
          <div className={styles.field}>
            <label className={styles.label}>{t('login.newPasswordLabel')}</label>
            <input
              className={styles.input}
              name="password"
              type="password"
              value={password}
              autoComplete="new-password"
              onChange={(e) => onPasswordChange(e.target.value)}
            />
          </div>
          <PasswordStrengthMeter password={password} />
          <button
            type="submit"
            disabled={loading || submitDisabled}
            className={styles.submit}
          >
            {t('login.reset')}
          </button>
        </form>
      )}
    </main>
  );
}

// ---------------------------------------------------------------------------
// 页面壳（状态 + 提交编排 / 副作用）
// ---------------------------------------------------------------------------

export interface ResetPageProps {
  /** 注入快照（§2.1；bootstrap 读取后由 routes 传入，flow=reset）。 */
  readonly snapshot: MethodsSnapshot;
}

export function ResetPage({ snapshot }: ResetPageProps) {
  const options = resetOptionsFor(snapshot);
  const [method, setMethod] = useState(options[0]?.method ?? '');
  const [step, setStep] = useState<FlowStep>('challenge');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('idle');
  const [envelope, setEnvelope] = useState<LoginFlowResponse | undefined>(
    undefined,
  );
  const [notice, setNotice] = useState<string | undefined>(undefined);
  const [otpCode, setOtpCode] = useState('');
  const [password, setPassword] = useState('');
  const captchaRef = useRef<CaptchaWidgetHandle>(null);

  // captcha_invalid → reset widget 后重试（§1.6 行 241）。
  useEffect(() => {
    if (status === 'captcha_invalid') {
      captchaRef.current?.reset();
    }
  }, [status, envelope]);

  /** 回到 challenge 第一步（restart 类 / 传输失败；§1.6「回到第一步」）。 */
  const restartFlow = () => {
    setStep('challenge');
    setStatus('idle');
    setEnvelope(undefined);
    setOtpCode('');
  };

  const selectMethod = (next: string) => {
    setMethod(next);
    setStep('challenge');
    setStatus('idle');
    setEnvelope(undefined);
    setNotice(undefined);
    setOtpCode('');
    setPassword('');
  };

  const submit = async (values: Readonly<Record<string, string>>) => {
    setLoading(true);
    // captcha 凭据（§2.5 行 528：重置的下发必须）：challenge 段必带；
    // verify / set_password 不带（payload 无 captcha 字段，§2.4 行 465-466）。
    const needsCaptcha = step === 'challenge';
    const captcha = needsCaptcha ? captchaRef.current?.getToken() : undefined;
    const result = await runFlowStep(resetPassword, {
      method,
      step,
      payload: resetPayloadFor(
        step,
        step === 'set_password' ? { password } : values,
        captcha,
      ),
    });
    setLoading(false);
    if (!result.ok) {
      // 传输层失败：回到第一步 + failed 兜底（§1.6 行 272，不暴露内部信息）。
      restartFlow();
      setNotice('errors.status.failed');
      return;
    }
    const env = result.envelope;
    setEnvelope(env);
    setStatus(env.status);
    setNotice(undefined);
    if (env.status === 'success') {
      // 重置成功：会话与令牌已失效（loginToken 已由 api 层清空），提示重新登录。
      return;
    }
    if (env.status === 'next') {
      const next = advanceAfterStep(step, env);
      if (next !== undefined) {
        setStep(next);
      }
      return;
    }
    if (RESTART_STATUSES.has(env.status)) {
      restartFlow();
      setNotice(resolveFlowStatus(env.status).i18nKey);
    }
  };

  // verify 段「重新发送」：回到 challenge 段重走（每次下发都要新的 captcha）。
  const backToChallenge = () => {
    setStep('challenge');
    setStatus('idle');
    setEnvelope(undefined);
    setOtpCode('');
  };

  return (
    <ResetPageView
      snapshot={snapshot}
      status={status}
      envelope={envelope}
      notice={notice}
      method={method}
      step={step}
      loading={loading}
      otpCode={otpCode}
      password={password}
      onSelectMethod={selectMethod}
      onSubmit={submit}
      onOtpCodeChange={setOtpCode}
      onPasswordChange={setPassword}
      onResend={backToChallenge}
      captchaRef={captchaRef}
    />
  );
}
