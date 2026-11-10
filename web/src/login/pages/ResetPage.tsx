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
 * challenge 段复用 factors/OTPForm；verify 段与 OTPForm / RegisterPage 共享
 * login/VerifyCodeSection（评审 P2-10），重置语境提交按钮文案
 * login.nextStep 经 props 注入。
 *
 * 文案：重置页专属（标题 / 步骤按钮 / 成功提示）经 i18n 字典 login.* 键取用；
 * 关闭态提示复用 errors.status.reset_disabled。
 */
import { useState, type FormEvent } from 'react';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import { resolveFlowStatus } from '../../shared/api/errors';
import { CaptchaDialog } from '../../shared/captcha/CaptchaDialog';
import { useCaptchaGate } from '../../shared/captcha/useCaptchaGate';
import { ErrorBanner } from '../../shared/components';
import { PasswordStrengthMeter } from '../../shared/components/PasswordStrengthMeter';
import { t } from '../../shared/i18n';
import type {
  LoginMethodEntry,
  MethodsSnapshot,
} from '../../shared/types/init';
import { Modal } from '../components/Modal';
import { resetPassword, type ResetPasswordInput } from '../api';
import { OTPForm } from '../factors/OTPForm';
import { focusField, RETRY_RESUBMIT_STATUSES } from '../validate';
import { VerifyCodeSection } from '../VerifyCodeSection';
import { PasswordField } from './PasswordField';
import {
  advanceAfterStep,
  isFlowErrorStatus,
  RESTART_STATUSES,
  runFlowStep,
  SET_PASSWORD_FIELD_ORDER,
  setPasswordIssues,
  snapshotFields,
  ssoPath,
  type FlowStep,
} from './RegisterPage';
import pageStyles from './BasePage.module.less';
import styles from './ResetPage.module.less';
import { AppLayout } from '../components/AppLayout';
import { Link } from '@modern-js/runtime/router';
import { Tabs } from '../components/Tabs';

/** 重置可用方式白名单（§2.1 行 412：flow=reset 只保留 otp_sms / otp_email，快照已过滤，此处防御性收窄）。 */
export function resetOptionsFor(snapshot: MethodsSnapshot): LoginMethodEntry[] {
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
  snapshot: MethodsSnapshot;
  /** 最近一次响应 status（初始 'idle'）。 */
  status: string;
  /** 最近一次响应信封（失败态 ErrorBanner 字段来源）。 */
  envelope: LoginFlowResponse | undefined;
  /** restart / 传输失败的一次性提示（i18nKey）。 */
  notice?: string;
  /** 当前重置方式（快照 method）。 */
  method: string;
  /** 当前请求侧 step。 */
  step: FlowStep;
  /** 请求在途（提交按钮禁用，§3.2）。 */
  loading: boolean;
  /** verify 段已输码（容器持值防实例重建丢失，同款语义）。 */
  otpCode: string;
  /** set_password 段新密码（受控）。 */
  password: string;
  /** challenge 段已提交的目标值（评审 P1-5：reset / 重发回 challenge 段时经 OTPForm initialValues 回填）。 */
  challengeValues?: Readonly<Record<string, string>>;
  onSelectMethod: (method: string) => void;
  /** 提交（challenge 段上抛目标 values；verify 段 {code}；set_password 段 {}）。 */
  onSubmit: (values: Readonly<Record<string, string>>) => void;
  onOtpCodeChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  /** verify 段重发（回到 challenge 段重走）。 */
  onResend: () => void;
  /** 可重试失败态的「重试」动作（评审 P1-4：按当前 step 重提容器持值）。 */
  onRetry?: () => void;
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
  challengeValues,
  onSelectMethod,
  onSubmit,
  onOtpCodeChange,
  onPasswordChange,
  onResend,
  onRetry,
}: ResetPageViewProps) {
  const options = resetOptionsFor(snapshot);
  // 确认密码（P1-3，只本地比对）与 set_password 段前置校验错误（P0-2；
  // verify 段输码校验 / 重发倒计时归 VerifyCodeSection）。
  const [confirm, setConfirm] = useState('');
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  const entry = options.find((m) => m.method === method);

  // §4.4 行 465：methods 为空数组或 flags.passwordReset=false → 整页提示关闭。
  if (snapshot.flags?.passwordReset !== true || options.length === 0) {
    return (
      <AppLayout title={t('login.reset')}>
        <p role="status">{t('errors.status.reset_disabled')}</p>
      </AppLayout>
    );
  }
  // 任一 step 收到 reset_disabled → 提示并停止流程（§4.4 行 465 / §2.4 行 471）。
  if (status === 'reset_disabled') {
    return (
      <AppLayout title={t('login.reset')}>
        <p role="status">{t('errors.status.reset_disabled')}</p>
      </AppLayout>
    );
  }
  if (status === 'success') {
    return (
      <AppLayout title={t('login.reset')}>
        <p role="status">{t('login.resetSuccess')}</p>
        <Link className={styles.loginLink} to={ssoPath('/sso/login')}>
          {t('login.goLogin')}
        </Link>
      </AppLayout>
    );
  }

  const resolution = isFlowErrorStatus(status)
    ? resolveFlowStatus(status)
    : undefined;
  // §1.6「可重试 = 否」的失败态禁用提交（表单保留原地，不隐藏）。
  const submitDisabled = resolution !== undefined && !resolution.retryable;
  const error = envelope?.error;

  const submitSetPassword = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (loading || submitDisabled) {
      return;
    }
    // 评审 P0-2 + P1-3：密码必填 + 确认密码本地比对（重置无用户名字段，§10.4）。
    const issues = setPasswordIssues({
      username: '',
      password,
      confirm,
      requireUsername: false,
    });
    const first = SET_PASSWORD_FIELD_ORDER.find(
      (name) => issues[name] !== undefined,
    );
    if (first !== undefined) {
      setFormErrors(issues);
      focusField(`reset-${first}`);
      return;
    }
    setFormErrors({});
    onSubmit({}); // 确认密码不进 payload（P1-3；§10.4 行 1532 只提交 password）
  };

  return (
    <AppLayout title={t('login.reset')}>
      {notice !== undefined && <ErrorBanner i18nKey={notice} />}
      {resolution !== undefined && (
        <ErrorBanner
          i18nKey={resolution.i18nKey}
          fallbackMessage={error?.message}
          retryAfter={error?.retryAfter}
          // 评审 P1-4：verify 段剩余次数由字段旁内联承载，banner 不重复。
          attemptsLeft={step === 'verify' ? undefined : error?.attemptsLeft}
          retryable={resolution.retryable}
          onRetry={RETRY_RESUBMIT_STATUSES.has(status) ? onRetry : undefined}
        />
      )}
      {options.length > 1 && (
        <Tabs
          tabList={options.map((option) => ({
            itemKey: option.method,
            title: t(RESET_METHOD_NAME_KEYS[option.method] ?? option.method),
          }))}
          activeKey={method}
          onChange={onSelectMethod}
        />
      )}
      {step === 'challenge' && (
        <div className={styles.section}>
          <OTPForm
            fields={snapshotFields(entry?.challengeFields)}
            loading={loading}
            disabled={submitDisabled}
            onSubmit={onSubmit}
            initialValues={challengeValues}
          />
        </div>
      )}
      {step === 'verify' && (
        <VerifyCodeSection
          id="reset-code"
          length={codeLengthOf(entry)}
          code={otpCode}
          onCodeChange={onOtpCodeChange}
          onSubmit={(value) => onSubmit({ code: value })}
          submitLabelKey="login.nextStep"
          classes={{
            form: styles.section,
            label: styles.label,
            error: styles.fieldError,
            status: styles.status,
            resend: styles.resend,
            submit: styles.submit,
          }}
          loading={loading}
          disabled={submitDisabled}
          attemptsLeft={error?.attemptsLeft}
          retryAfter={
            envelope?.nextStep?.retryAfter ?? envelope?.error?.retryAfter
          }
          onResend={onResend}
        />
      )}
      {step === 'set_password' && (
        <form onSubmit={submitSetPassword} className={styles.section}>
          <PasswordField
            id="reset-password"
            name="password"
            label={t('login.newPasswordLabel')}
            value={password}
            onChange={(value) => {
              onPasswordChange(value);
              setFormErrors((prev) => {
                if (prev.password === undefined) {
                  return prev;
                }
                const next = { ...prev };
                delete next.password;
                return next;
              });
            }}
            error={formErrors.password}
            disabled={loading}
          />
          <PasswordField
            id="reset-confirm"
            name="password_confirm"
            label={t('login.confirmPasswordLabel')}
            value={confirm}
            onChange={(value) => {
              setConfirm(value);
              setFormErrors((prev) => {
                if (prev.confirm === undefined) {
                  return prev;
                }
                const next = { ...prev };
                delete next.confirm;
                return next;
              });
            }}
            error={formErrors.confirm}
            disabled={loading}
          />
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
    </AppLayout>
  );
}

// ---------------------------------------------------------------------------
// 页面壳（状态 + 提交编排 / 副作用）
// ---------------------------------------------------------------------------

export interface ResetPageProps {
  /** 注入快照（§2.1；bootstrap 读取后由 routes 传入，flow=reset）。 */
  snapshot: MethodsSnapshot;
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
  // challenge 段已提交目标（评审 P1-5：传输失败 / 重发回 challenge 段回填）。
  const [challengeValues, setChallengeValues] = useState<
    Readonly<Record<string, string>>
  >({});
  // captcha 弹窗编排（shared/captcha）：challenge 下发先问再发，窗内换凭据循环。
  const gate = useCaptchaGate(Modal);

  /** 回到 challenge 第一步（restart 类 / 传输失败；§1.6「回到第一步」；
   * 目标持值保留（P1-5 回填），已输码随流程重发而作废）。 */
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
    setChallengeValues({});
  };

  const submit = async (values: Readonly<Record<string, string>>) => {
    setLoading(true);
    if (step === 'challenge') {
      setChallengeValues(values);
    }
    // captcha 凭据由 gate 弹窗注入（§2.5 行 528：重置的下发必须）：challenge
    // 段后端恒拦截 → 先问再发；verify / set_password 的 payload 不含 captcha
    // （§2.4 行 465-466，resetPayloadFor 按 step 决定），命中才问（reactive 防御）。
    const result = await runFlowStep(
      resetPassword,
      {
        method,
        step,
        payloadFor: (token) =>
          resetPayloadFor(
            step,
            step === 'set_password' ? { password } : values,
            token,
          ),
      },
      gate.run,
      {
        mode: step === 'challenge' ? 'upfront' : 'reactive',
        // 权威配置（§2.5 行 518）：响应顶层优先，缺省回落快照首屏。
        config: envelope?.captcha ?? snapshot.captcha,
      },
    );
    setLoading(false);
    if (!result.ok) {
      if (result.cancelled) {
        // 取消弹窗：流程态与表单原样保留，用户可直接重提（不算失败、不回第一步）。
        return;
      }
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

  // verify 段「重新发送」：回到 challenge 段重走（每次下发都要新的 captcha；
  // 原目标经 challengeValues → OTPForm initialValues 回填，P1-5）。
  const backToChallenge = () => {
    setStep('challenge');
    setStatus('idle');
    setEnvelope(undefined);
    setOtpCode('');
  };

  // 评审 P1-4：可重试失败态「重试」= 按当前 step 重提容器持值。
  const retrySubmit = () => {
    if (step === 'challenge') {
      void submit(challengeValues);
    } else if (step === 'verify') {
      void submit({ code: otpCode });
    } else {
      void submit({});
    }
  };

  return (
    <>
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
        challengeValues={challengeValues}
        onSelectMethod={selectMethod}
        onSubmit={submit}
        onOtpCodeChange={setOtpCode}
        onPasswordChange={setPassword}
        onResend={backToChallenge}
        onRetry={retrySubmit}
      />
      <CaptchaDialog {...gate.dialogProps} />
    </>
  );
}
