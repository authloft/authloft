/**
 * 注册页（docs/前端架构.md §4.4 行 464；docs/接口文档.md §2.3 / §10.3）：
 * - 验证码注册 challenge → verify → set_password（§10.3 行 1521-1528）；用户名 +
 *   密码注册（allow_signup_password）从 set_password 直入，payload 含 captcha
 *   （§2.3 行 451）；注册方式只受注册开关控制、直接取注入快照 methods（flow=
 *   register 已按 §2.1 行 411 过滤，不读 login_methods）；
 * - flags.registration=false → 整页提示注册已关闭（§4.4 行 464）；任一 step
 *   收到 status=signup_disabled 即提示并停止流程（不渲染注册表单）；
 * - username_taken / password_weak 等失败态按 §1.6 出动作（ErrorBanner + 表单
 *   保留原地重试）；captcha_required / captcha_invalid 原地按响应顶层 captcha
 *   （权威来源，§2.5 行 518）渲染 / reset widget；restart 类回第一步；
 * - set_password 步渲染 PasswordStrengthMeter（§5.6 同源规则，服务端权威）；
 *   注册成功 = 完成登录（§2.3 行 455），终点跳转 syncCookieUrl 优先（§1.3 行 136）。
 *
 * 结构沿 LoginContainer / LoginFlowView 模式：RegisterPageView 为
 * 纯状态帧视图（renderToStaticMarkup 可测任意 status 帧），RegisterPage 为
 * 状态壳（提交编排 / 副作用）。
 *
 * 本文件同时导出注册 / 重置页族共用纯函数（advanceAfterStep / flowTerminalUrl /
 * runFlowStep / snapshotFields 等，ResetPage 复用）；如需迁往 shared/ 归后续实现。
 *
 * challenge 段复用 factors/OTPForm（「发送验证码」语义匹配，§4.4 行 464 钦定）；
 * verify 段自建（CodeInput + useCountdown）：OTPForm verify 段提交按钮文案为
 * login 域字面量「登录」（factors/** 未改动），注册语境应为「下一步」。
 *
 * 文案：注册页专属（标题 / 方式名 / 步骤按钮）经 i18n 字典 login.* 键取用；
 * 注册关闭提示复用 errors.status.signup_disabled。
 */
import { useEffect, useRef, useState, type FormEvent, type Ref } from 'react';
import { create } from '@bufbuild/protobuf';
import {
  FieldSchema,
  type Field,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
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
import { isValidUsername } from '../../shared/utils/validate';
import {
  getInit,
  type LoginMethodEntry,
  type MethodsSnapshot,
  type SnapshotField,
} from '../../shared/types/init';
import { register, type RegisterInput } from '../api';
import { OTPForm } from '../factors/OTPForm';
import styles from './RegisterPage.module.less';

// ---------------------------------------------------------------------------
// 页族共用纯函数（ResetPage 复用；node 可测）
// ---------------------------------------------------------------------------

/** 注册 / 重置请求侧 step（§2.2 行 422：set_password 属注册 / 重置端点）。 */
export type FlowStep = 'challenge' | 'verify' | 'set_password';

/** restart 类失败态（§1.6：step / token / state 类回到第一步）。 */
export const RESTART_STATUSES: ReadonlySet<string> = new Set([
  'step_invalid',
  'token_invalid',
  'token_expired',
  'state_mismatch',
]);

/** 注册 / 重置页非失败态（本页族不出现 mfa / binding / 轮询态，防御性收窄）。 */
const NON_ERROR_STATUSES: ReadonlySet<string> = new Set([
  'idle',
  'next',
  'success',
  'captcha_required',
  'captcha_invalid',
]);

/** 是否失败态（渲染 ErrorBanner 的判据；§4.1 行 395 同款语义）。 */
export function isFlowErrorStatus(status: string): boolean {
  return !NON_ERROR_STATUSES.has(status);
}

/**
 * status=next 时的下一步推进（§10.3 / §10.4 流程序列）：challenge → verify →
 * set_password；其余（含 set_password 后的 next，防御）不推进。
 */
export function advanceAfterStep(
  step: FlowStep,
  envelope: LoginFlowResponse,
): FlowStep | undefined {
  if (envelope.status !== 'next') {
    return undefined;
  }
  if (step === 'challenge') {
    return 'verify';
  }
  if (step === 'verify') {
    return 'set_password';
  }
  return undefined;
}

/**
 * 终点 URL（§1.3 行 136）：syncCookieUrl 非空优先（后端拼好的首跳完整 URL），
 * 否则 redirectTo；双空 → 空串（不跳转）。与 LoginContainer.terminalUrl 同款逻辑，
 * 此处不复用它以免本页静态拉入整个 login flow 模块链。
 */
export function flowTerminalUrl(envelope: LoginFlowResponse): string {
  return envelope.syncCookieUrl !== ''
    ? envelope.syncCookieUrl
    : envelope.redirectTo;
}

/** 流程步提交编排（纯逻辑，request 可注入；传输层异常 → ok:false 不伪造信封）。 */
export async function runFlowStep<P extends object>(
  request: (input: {
    method: string;
    step: string;
    payload: P;
  }) => Promise<LoginFlowResponse>,
  input: { method: string; step: string; payload: P },
): Promise<{ ok: true; envelope: LoginFlowResponse } | { ok: false }> {
  try {
    return { ok: true, envelope: await request(input) };
  } catch {
    return { ok: false };
  }
}

/** int64 十进制字符串（§1.12）→ bigint；缺失 / 非法兜底 0。 */
function parseCount(value: string | undefined): bigint {
  try {
    return BigInt(value ?? '');
  } catch {
    return BigInt(0);
  }
}

/**
 * 注入快照字段 → 生成物 Field（渲染模型转换，与 LoginContainer
 * snapshotFieldToField 同款逻辑；不复用它以免拉入 login flow 模块链）。
 */
export function snapshotFields(
  fields: readonly SnapshotField[] | undefined,
): Field[] {
  return (fields ?? []).map((snapshot) =>
    create(FieldSchema, {
      name: snapshot.name,
      label: snapshot.label ?? '',
      type: snapshot.type,
      required: snapshot.required ?? false,
      length: parseCount(snapshot.length),
      maxAttempts: parseCount(snapshot.maxAttempts),
    }),
  );
}

/** 同源部署下的 SSO 页面绝对地址（al_root 为部署根，§8；缺省同源根路径）。 */
export function ssoPath(path: string): string {
  const root = getInit()?.al_root ?? '';
  return `${root.replace(/\/+$/, '')}${path}`;
}

/** 注册可用方式白名单（§2.3：password / otp_sms / otp_email；快照已按 §2.1 行 411 过滤，此处防御性收窄）。 */
export function registerOptionsFor(
  snapshot: MethodsSnapshot,
): readonly LoginMethodEntry[] {
  return snapshot.methods.filter(
    (m) => m.method === 'password' || m.method === 'otp_sms' || m.method === 'otp_email',
  );
}

/** 方式首步（§2.3 行 451）：用户名 + 密码注册从 set_password 直入；otp 系 challenge 起。 */
export function registerFirstStep(method: string): FlowStep {
  return method === 'password' ? 'set_password' : 'challenge';
}

/** RegisterPayload 的 init 形状（login/api.ts 的 RegisterInput.payload）。 */
type RegisterPayloadInit = NonNullable<RegisterInput['payload']>;

/**
 * 注册各 step 的 payload 组装（§2.3 行 444-451 字段表）：
 * challenge {email|phone, captcha} / verify {code} / set_password {username,
 * password, captcha?}（captcha 仅用户名 + 密码直入必填，由调用方判定传入）。
 */
export function registerPayloadFor(
  step: FlowStep,
  values: Readonly<Record<string, string>>,
  captcha?: CaptchaPayload,
): RegisterPayloadInit {
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
  return {
    username: values.username ?? '',
    password: values.password ?? '',
    ...(captcha !== undefined ? { captcha } : {}),
  };
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
 * 注册方式 tab 文案键（快照 method → 注册语境名；i18n factors.* 是登录语境，
 * 另立键；未知 method 走 t() 键回显，与原字面量兜底同款）。
 */
const REGISTER_METHOD_NAME_KEYS: Readonly<Record<string, string>> = {
  password: 'login.registerMethodPassword',
  otp_sms: 'login.registerMethodOtpSms',
  otp_email: 'login.registerMethodOtpEmail',
};

export interface RegisterPageViewProps {
  /** 注入快照（§2.1，flow=register）。 */
  readonly snapshot: MethodsSnapshot;
  /** 最近一次响应 status（初始 'idle'）。 */
  readonly status: string;
  /** 最近一次响应信封（失败态 ErrorBanner 字段来源）。 */
  readonly envelope: LoginFlowResponse | undefined;
  /** restart / 传输失败的一次性提示（i18nKey）。 */
  readonly notice?: string;
  /** 当前注册方式（快照 method）。 */
  readonly method: string;
  /** 当前请求侧 step。 */
  readonly step: FlowStep;
  /** 请求在途（提交按钮禁用，§3.2）。 */
  readonly loading: boolean;
  /** verify 段已输码（容器持值防实例重建丢失，同款语义）。 */
  readonly otpCode: string;
  /** set_password 段用户名（受控）。 */
  readonly username: string;
  /** set_password 段密码（受控）。 */
  readonly password: string;
  /** challenge 段已提交的目标邮箱（set_password 段 Meter 的标识比对，§5.6）。 */
  readonly challengeEmail?: string;
  onSelectMethod: (method: string) => void;
  /** 提交（challenge 段上抛目标 values；verify 段 {code}；set_password 段 {}）。 */
  onSubmit: (values: Readonly<Record<string, string>>) => void;
  onOtpCodeChange: (value: string) => void;
  onUsernameChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  /** verify 段重发（回到 challenge 段重走）。 */
  onResend: () => void;
  captchaRef?: Ref<CaptchaWidgetHandle>;
}

export function RegisterPageView({
  snapshot,
  status,
  envelope,
  notice,
  method,
  step,
  loading,
  otpCode,
  username,
  password,
  challengeEmail,
  onSelectMethod,
  onSubmit,
  onOtpCodeChange,
  onUsernameChange,
  onPasswordChange,
  onResend,
  captchaRef,
}: RegisterPageViewProps) {
  const options = registerOptionsFor(snapshot);
  // verify 段重发倒计时（nextStep.retryAfter / error.retryAfter，§1.3 行 115/150）。
  const countdown = useCountdown(
    envelope?.nextStep?.retryAfter ?? envelope?.error?.retryAfter,
  );
  const entry = options.find((m) => m.method === method);

  // §4.4 行 464：flags.registration=false → 整页提示注册已关闭（不渲染表单）。
  if (snapshot.flags?.registration !== true) {
    return (
      <main className={styles.page}>
        <h1 className={styles.title}>{t('login.register')}</h1>
        <p role="status">{t('errors.status.signup_disabled')}</p>
      </main>
    );
  }
  // 任一 step 收到 signup_disabled → 提示并停止流程（§4.4 行 464 / §2.3 行 455）。
  if (status === 'signup_disabled') {
    return (
      <main className={styles.page}>
        <h1 className={styles.title}>{t('login.register')}</h1>
        <p role="status">{t('errors.status.signup_disabled')}</p>
      </main>
    );
  }
  if (status === 'success') {
    return (
      <main className={styles.page}>
        <h1 className={styles.title}>{t('login.register')}</h1>
        <p role="status">{t('login.registerSuccess')}</p>
      </main>
    );
  }
  if (options.length === 0) {
    return (
      <main className={styles.page}>
        <h1 className={styles.title}>{t('login.register')}</h1>
        <p role="status">{t('login.noRegisterMethods')}</p>
      </main>
    );
  }

  const resolution = isFlowErrorStatus(status)
    ? resolveFlowStatus(status)
    : undefined;
  // §1.6「可重试 = 否」的失败态禁用提交（表单保留原地，不隐藏）。
  const submitDisabled = resolution !== undefined && !resolution.retryable;
  const error = envelope?.error;
  // captcha 渲染位置（§2.3 行 447/451）：otp challenge 必填；password 直入
  // set_password 必填；otp 流程的 verify / set_password 不渲染（payload 无 captcha）。
  const showCaptcha =
    step === 'challenge' || (step === 'set_password' && method === 'password');
  // 权威 captcha 对象（§2.5 行 518）：响应顶层 captcha 优先，缺省回落快照首屏。
  const captchaConfig = envelope?.captcha ?? snapshot.captcha;
  const captchaNode =
    showCaptcha && captchaConfig !== undefined ? (
      <CaptchaWidget captcha={captchaConfig} ref={captchaRef} />
    ) : null;

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
      <h1 className={styles.title}>{t('login.register')}</h1>
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
                  {t(REGISTER_METHOD_NAME_KEYS[option.method] ?? option.method)}
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
          {captchaNode}
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
            <label className={styles.label}>{t('login.usernameLabel')}</label>
            <input
              className={styles.input}
              name="username"
              type="text"
              value={username}
              autoComplete="username"
              onChange={(e) => onUsernameChange(e.target.value)}
            />
            {username !== '' && !isValidUsername(username) && (
              <p role="status" className={styles.hint}>
                {t('login.usernameHint')}
              </p>
            )}
          </div>
          <div className={styles.field}>
            <label className={styles.label}>{t('login.passwordLabel')}</label>
            <input
              className={styles.input}
              name="password"
              type="password"
              value={password}
              autoComplete="new-password"
              onChange={(e) => onPasswordChange(e.target.value)}
            />
          </div>
          <PasswordStrengthMeter
            password={password}
            username={username}
            email={challengeEmail}
          />
          {captchaNode}
          <button
            type="submit"
            disabled={loading || submitDisabled}
            className={styles.submit}
          >
            {t('login.register')}
          </button>
        </form>
      )}
    </main>
  );
}

// ---------------------------------------------------------------------------
// 页面壳（状态 + 提交编排 / 副作用）
// ---------------------------------------------------------------------------

export interface RegisterPageProps {
  /** 注入快照（§2.1；bootstrap 读取后由 routes 传入，flow=register）。 */
  readonly snapshot: MethodsSnapshot;
}

export function RegisterPage({ snapshot }: RegisterPageProps) {
  const options = registerOptionsFor(snapshot);
  const [method, setMethod] = useState(options[0]?.method ?? '');
  const [step, setStep] = useState<FlowStep>(() =>
    registerFirstStep(options[0]?.method ?? ''),
  );
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('idle');
  const [envelope, setEnvelope] = useState<LoginFlowResponse | undefined>(
    undefined,
  );
  const [notice, setNotice] = useState<string | undefined>(undefined);
  const [otpCode, setOtpCode] = useState('');
  // challenge 段已提交目标（set_password 段 Meter 标识比对用，§5.6）。
  const [challengeValues, setChallengeValues] = useState<
    Readonly<Record<string, string>>
  >({});
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const captchaRef = useRef<CaptchaWidgetHandle>(null);

  // captcha_invalid → reset widget 后重试（§1.6 行 241；权威 captcha 对象
  // 变化时 adapterKey 自动按新对象重建，无需此处处理）。
  useEffect(() => {
    if (status === 'captcha_invalid') {
      captchaRef.current?.reset();
    }
  }, [status, envelope]);

  /** 回到当前方式首步（restart 类 / 传输失败；§1.6「回到第一步」）。 */
  const restartFlow = () => {
    setStep(registerFirstStep(method));
    setStatus('idle');
    setEnvelope(undefined);
    setOtpCode('');
  };

  const selectMethod = (next: string) => {
    setMethod(next);
    setStep(registerFirstStep(next));
    setStatus('idle');
    setEnvelope(undefined);
    setNotice(undefined);
    setOtpCode('');
    setUsername('');
    setPassword('');
  };

  const submit = async (values: Readonly<Record<string, string>>) => {
    setLoading(true);
    if (step === 'challenge') {
      setChallengeValues(values);
    }
    // captcha 凭据（§2.3 行 447/451）：otp challenge 与 password 直入必填；
    // otp 流程 verify / set_password 不带（payload 无 captcha 字段）。
    const needsCaptcha =
      step === 'challenge' || (step === 'set_password' && method === 'password');
    const captcha = needsCaptcha ? captchaRef.current?.getToken() : undefined;
    const result = await runFlowStep(register, {
      method,
      step,
      payload: registerPayloadFor(
        step,
        step === 'set_password' ? { username, password } : values,
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
      // 注册成功 = 完成登录（§2.3 行 455）：终点跳转（loginToken 已由 api 层清空）。
      const url = flowTerminalUrl(env);
      if (url !== '') {
        location.replace(url);
      }
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

  // verify 段「重新发送」：回到 challenge 段重走（每次下发都要新的 captcha，
  // §2.5 行 525；原目标在 OTPForm challenge 段重渲染，用户可改可重发）。
  const backToChallenge = () => {
    setStep('challenge');
    setStatus('idle');
    setEnvelope(undefined);
    setOtpCode('');
  };

  return (
    <RegisterPageView
      snapshot={snapshot}
      status={status}
      envelope={envelope}
      notice={notice}
      method={method}
      step={step}
      loading={loading}
      otpCode={otpCode}
      username={username}
      password={password}
      challengeEmail={challengeValues.email}
      onSelectMethod={selectMethod}
      onSubmit={submit}
      onOtpCodeChange={setOtpCode}
      onUsernameChange={setUsername}
      onPasswordChange={setPassword}
      onResend={backToChallenge}
      captchaRef={captchaRef}
    />
  );
}
