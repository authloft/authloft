/**
 * 注册页（docs/前端架构.md §4.4 行 464；docs/接口文档.md §2.3 / §10.3）：
 * - 验证码注册 challenge → verify → set_password（§10.3 行 1521-1528）；用户名 +
 *   密码注册（allow_signup_password）从 set_password 直入，payload 含 captcha
 *   （§2.3 行 451）；注册方式只受注册开关控制、直接取注入快照 methods（flow=
 *   register 已按 §2.1 行 411 过滤，不读 login_methods）；
 * - flags.registration=false → 整页提示注册已关闭（§4.4 行 464）；任一 step
 *   收到 status=signup_disabled 即提示并停止流程（不渲染注册表单）；
 * - username_taken / password_weak 等失败态按 §1.6 出动作（ErrorBanner + 表单
 *   保留原地重试）；captcha_required / captcha_invalid 由弹窗 gate 吸收
 *   （shared/captcha）：确认即重提、窗内换凭据循环，权威配置取错误体 details
 *   （§1.5 / §2.5）；用户取消不动流程态；restart 类回第一步；
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
 * verify 段与 OTPForm / ResetPage 共享 login/VerifyCodeSection，
 * 注册语境提交按钮文案 login.nextStep 经 props 注入。
 *
 * 文案：注册页专属（标题 / 方式名 / 步骤按钮）经 i18n 字典 login.* 键取用；
 * 注册关闭提示复用 errors.status.signup_disabled。
 *
 * 卡片底部：入口导航（「已有账号？立即登录」右对齐；主表单帧与关闭类帧
 * 渲染，成功帧不渲染）+ 全帧一致的 footer 语言切换（与 LoginPage 共用
 * login/components/LocaleSwitcher）。
 */
import { useEffect, useState, type FormEvent } from 'react';
import { create } from '@bufbuild/protobuf';
import { Link, useSearchParams } from '@modern-js/runtime/router';
import {
  FieldSchema,
  type Field,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import { resolveFlowStatus } from '../../shared/api/errors';
import { CaptchaDialog } from '../../shared/captcha/CaptchaDialog';
import {
  flowCaptchaOutcome,
  type CaptchaGateMode,
} from '../../shared/captcha/captchaGate';
import {
  useCaptchaGate,
  type CaptchaGate,
} from '../../shared/captcha/useCaptchaGate';
import { ErrorBanner } from '../../shared/components';
import {
  effectivePasswordPolicy,
  PasswordStrengthMeter,
  passwordWeakLabels,
} from '../../shared/components/PasswordStrengthMeter';
import { getLocale, setLocale, t, type Locale } from '../../shared/i18n';
import {
  usernameIssue,
  validatePassword,
  type PasswordPolicy,
} from '../../shared/utils/validate';
import {
  DEFAULT_ACCOUNT_HOME,
  isValidReturnTo,
  sanitizeReturnTo,
} from '../../shared/urls';
import {
  getInit,
  type LoginMethodEntry,
  type MethodsSnapshot,
  type SnapshotField,
} from '../../shared/types/init';
import { Modal } from '../components/Modal';
import { hasOidcContext } from '../oidcContext';
import { RESTART_STATUSES } from '../flow/machine';
import { loadLoginBootstrap } from '../bootstrap';
import { register, type RegisterInput } from '../api';
import { clearLoginToken } from '../loginTokenStore';
import { OTPForm } from '../factors/OTPForm';
import { StepBackLink } from '../components/StepBackLink';
import { focusField, RETRY_RESUBMIT_STATUSES } from '../validate';
import { VerifyCodeSection } from '../VerifyCodeSection';
import { PasswordField } from './PasswordField';
import styles from './RegisterPage.module.less';
import { AppLayout } from '../components/AppLayout';
import { LocaleSwitcher } from '../components/LocaleSwitcher';
import { Tabs } from '../../shared/components';

// ---------------------------------------------------------------------------
// 页族共用纯函数（ResetPage 复用；node 可测）
// ---------------------------------------------------------------------------

/** 注册 / 重置请求侧 step（§2.2 行 422：set_password 属注册 / 重置端点）。 */
export type FlowStep = 'challenge' | 'verify' | 'set_password';

/** restart 类失败态收口在 flow/machine（§1.6 唯一定义），此处转出复用。 */
export { RESTART_STATUSES };

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
 * 终点 URL（§1.3 定稿 + returnTo 消费）：syncCookieUrl
 * 非空优先（后端拼好的首跳完整 URL，同步链 returnTo 不生效）；否则按流程
 * 分派——OIDC 流（oidc 上下文在场，§1.3）redirectTo 优先
 * （fail-closed）；非 OIDC 流 returnTo（白名单校验通过）优先——显式指定
 * 落点时不做应用默认回跳，非法 / 缺失再取 redirectTo；皆空（直登场景）→
 * 默认落点 DEFAULT_ACCOUNT_HOME（禁止停留提示页）。returnTo 由调用方
 * useSearchParams 取值（已解码，本函数不二次 decode）。与
 * LoginContainer.terminalUrl 同款逻辑，此处不复用它以免本页静态拉入整个
 * login flow 模块链。
 */
export function flowTerminalUrl(
  envelope: LoginFlowResponse,
  returnTo?: string,
): string {
  if (envelope.syncCookieUrl !== '') {
    return envelope.syncCookieUrl;
  }
  if (hasOidcContext()) {
    if (envelope.redirectTo !== '') {
      return envelope.redirectTo;
    }
    return returnTo === undefined
      ? DEFAULT_ACCOUNT_HOME
      : sanitizeReturnTo(returnTo);
  }
  if (returnTo !== undefined && isValidReturnTo(returnTo)) {
    return returnTo;
  }
  if (envelope.redirectTo !== '') {
    return envelope.redirectTo;
  }
  return DEFAULT_ACCOUNT_HOME;
}

/**
 * 流程步终局（三者互斥）：信封 / 用户取消 captcha 弹窗 / 传输层失败。
 * 取消不是失败——流程态与表单原样保留，用户可直接重提。
 */
export type FlowStepOutcome =
  { ok: true; envelope: LoginFlowResponse } | { ok: false; cancelled: boolean };

/**
 * 流程步提交编排（纯逻辑，request 与 gate 均可注入；ResetPage 复用）：
 * captcha 凭据由 gate 弹窗提供，作为**请求顶层 `captcha`**（与 payload 平级，
 * §2.5 / §2.6 行 672：captcha 不属于任何因子的 payload）；payloadFor 每轮重建
 * （不含 captcha）；captcha_required / captcha_invalid 在 gate 内吸收循环、不落
 * 页面状态；传输层异常 → ok:false 不伪造信封（§1.6 行 272）。
 */
export async function runFlowStep<P extends object>(
  request: (input: {
    method: string;
    step: string;
    payload: P;
    captcha?: CaptchaPayload;
  }) => Promise<LoginFlowResponse>,
  input: {
    method: string;
    step: string;
    /** 每轮重建 payload（不含 captcha；captcha 走请求顶层）。 */
    payloadFor: () => P;
  },
  runGate: CaptchaGate['run'],
  captcha: { mode: CaptchaGateMode; config?: CaptchaConfig },
): Promise<FlowStepOutcome> {
  const outcome = await runGate({
    mode: captcha.mode,
    config: captcha.config,
    request: (token) =>
      request({
        method: input.method,
        step: input.step,
        payload: input.payloadFor(),
        ...(token !== undefined ? { captcha: token } : {}),
      }),
    readOutcome: flowCaptchaOutcome,
  });
  if (outcome.kind === 'result') {
    return { ok: true, envelope: outcome.result };
  }
  return { ok: false, cancelled: outcome.kind === 'cancelled' };
}

/**
 * 注册各 step 的 captcha 触发时机（§2.3 行 447/451 + 后端 captcha/gate.go）：
 * otp challenge（下发）与 password 直入 set_password 后端恒拦截 → 点击即弹窗
 * 再发（upfront）；otp 流程 verify / set_password 的 payload 本不含 captcha →
 * 先发裸请求，命中才问（reactive 防御）。
 */
export function registerCaptchaMode(
  step: FlowStep,
  method: string,
): CaptchaGateMode {
  return step === 'challenge' ||
    (step === 'set_password' && method === 'password')
    ? 'upfront'
    : 'reactive';
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
export function snapshotFields(fields: SnapshotField[] | undefined): Field[] {
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
): LoginMethodEntry[] {
  return snapshot.methods.filter(
    (m) =>
      m.method === 'password' ||
      m.method === 'otp_sms' ||
      m.method === 'otp_email',
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
 * challenge {email|phone} / verify {code} / set_password {username, password}。
 * captcha 不在 payload 内（§2.6 行 672：captcha 不属于任何因子的 payload），
 * 由 runFlowStep 作为请求顶层字段传递。
 */
export function registerPayloadFor(
  step: FlowStep,
  values: Readonly<Record<string, string>>,
): RegisterPayloadInit {
  if (step === 'challenge') {
    return {
      email: values.email ?? '',
      phone: values.phone ?? '',
    };
  }
  if (step === 'verify') {
    return { code: values.code ?? '' };
  }
  return {
    username: values.username ?? '',
    password: values.password ?? '',
  };
}

/** 验证码分段数（快照 codeLength，§2.1 行 391；缺失 / 非法兜底 6）。 */
function codeLengthOf(entry: LoginMethodEntry | undefined): number {
  const parsed = Number.parseInt(entry?.codeLength ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 6;
}

/**
 * set_password 段前置校验（ResetPage 复用）：
 * 用户名必填 + 格式（§2.3 唯一定义；requireUsername=false 的重置页跳过）、
 * 密码必填 + 注入策略预校验（§2.1 passwordPolicy：validatePassword 覆盖项
 * 传入，缺省回落 §5.6 默认档；取首条未满足项文案，与强度条同源）、
 * 确认密码只本地比对（不进 payload，§10.3 / §10.4 字段表无此字段）。
 * 用户名命中 deleted_ 保留前缀给专属提示（区别于通用格式提示）。
 * 返回「字段锚（username / password / confirm）→ 错误文案」，空对象 = 全过；
 * 聚焦顺序即对象键序（SET_PASSWORD_FIELD_ORDER）。纯函数，node 可测。
 */
export const SET_PASSWORD_FIELD_ORDER = [
  'username',
  'password',
  'confirm',
] as const;

export function setPasswordIssues(input: {
  username: string;
  password: string;
  confirm: string;
  /** 注册 = true（校验用户名）；重置 = false（无用户名字段，§10.4 行 1532）。 */
  requireUsername: boolean;
  /** 注入策略覆盖项（§2.1；缺省 = 默认档 8/64/3）。 */
  policy?: Partial<PasswordPolicy>;
}): Record<string, string> {
  const issues: Record<string, string> = {};
  if (input.requireUsername) {
    if (input.username.trim() === '') {
      issues.username = t('common.errRequired');
    } else {
      const issue = usernameIssue(input.username);
      if (issue !== null) {
        issues.username =
          issue === 'reserved_prefix'
            ? t('admin.usernameReservedPrefixHint')
            : t('login.usernameHint');
      }
    }
  }
  if (input.password === '') {
    issues.password = t('common.errRequired');
  } else {
    const reasons = validatePassword(input.password, { policy: input.policy });
    if (reasons.length > 0) {
      issues.password = passwordWeakLabels(
        effectivePasswordPolicy(input.policy),
      )[reasons[0]];
    }
  }
  if (input.confirm === '') {
    issues.confirm = t('common.errRequired');
  } else if (input.confirm !== input.password) {
    issues.confirm = t('login.errPasswordMismatch');
  }
  return issues;
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
  snapshot: MethodsSnapshot;
  /** 最近一次响应 status（初始 'idle'）。 */
  status: string;
  /** 最近一次响应信封（失败态 ErrorBanner 字段来源）。 */
  envelope: LoginFlowResponse | undefined;
  /** restart / 传输失败的一次性提示（i18nKey）。 */
  notice?: string;
  /** 当前注册方式（快照 method）。 */
  method: string;
  /** 当前请求侧 step。 */
  step: FlowStep;
  /** 请求在途（提交按钮禁用，§3.2）。 */
  loading: boolean;
  /** verify 段已输码（容器持值防实例重建丢失，同款语义）。 */
  otpCode: string;
  /** set_password 段用户名（受控）。 */
  username: string;
  /** set_password 段密码（受控）。 */
  password: string;
  /** challenge 段已提交的目标邮箱（set_password 段 Meter 的标识比对，§5.6）。 */
  challengeEmail?: string;
  /**
   * 注入策略覆盖项（§2.1 passwordPolicy 经 bootstrap 解析；缺省回落默认档
   * §5.6）。强度条与提交前预校验同源消费。
   */
  policy?: Partial<PasswordPolicy>;
  /**
   * challenge 段已提交的目标值（传输失败 / 重发回 challenge
   * 段时经 OTPForm initialValues 回填；容器持值，页面壳注入）。
   */
  challengeValues?: Readonly<Record<string, string>>;
  onSelectMethod: (method: string) => void;
  /** 提交（challenge 段上抛目标 values；verify 段 {code}；set_password 段 {}）。 */
  onSubmit: (values: Readonly<Record<string, string>>) => void;
  onOtpCodeChange: (value: string) => void;
  onUsernameChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  /** verify 段重发（回到 challenge 段重走）。 */
  onResend: () => void;
  /** verify 段「返回上一步」（原地回 challenge 段改目标，不发请求）。 */
  onBackToChallenge: () => void;
  /** 可重试失败态的「重试」动作（按当前 step 重提容器持值）。 */
  onRetry?: () => void;
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
  policy,
  challengeValues,
  onSelectMethod,
  onSubmit,
  onOtpCodeChange,
  onUsernameChange,
  onPasswordChange,
  onResend,
  onBackToChallenge,
  onRetry,
}: RegisterPageViewProps) {
  const options = registerOptionsFor(snapshot);
  // 确认密码（只本地比对）与 set_password 段前置校验错误；
  // verify 段输码校验 / 重发倒计时归 VerifyCodeSection。
  const [confirm, setConfirm] = useState('');
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  const entry = options.find((m) => m.method === method);
  // 内存内语言切换（与 LoginPage 同款，持久化口径待定）；state 驱动重渲染
  // 使 t() 生效。footer 语言切换全状态帧一致，入口导航只挂主表单帧。
  const [locale, setLocaleState] = useState<Locale>(getLocale);
  const switchLocale = (next: Locale) => {
    setLocale(next);
    setLocaleState(next);
  };
  const footer = <LocaleSwitcher locale={locale} onSwitch={switchLocale} />;
  // 入口导航（已有账号？立即登录）：主表单帧与关闭类帧共用——关闭帧是死路，
  // 回登录页是唯一出路；成功帧不渲染（自动跳转终点）。
  const loginNav = (
    <nav className={styles.entryNav}>
      {t('login.hasAccount')}
      <Link className={styles.entryLink} to={ssoPath('/sso/login')}>
        {t('login.goLogin')}
      </Link>
    </nav>
  );

  // §4.4 行 464：flags.registration=false → 整页提示注册已关闭（不渲染表单）。
  if (snapshot.flags?.registration !== true) {
    return (
      <AppLayout title={t('login.register')} footer={footer}>
        <p role="status">{t('errors.status.signup_disabled')}</p>
        {loginNav}
      </AppLayout>
    );
  }
  // 任一 step 收到 signup_disabled → 提示并停止流程（§4.4 行 464 / §2.3 行 455）。
  if (status === 'signup_disabled') {
    return (
      <AppLayout title={t('login.register')} footer={footer}>
        <p role="status">{t('errors.status.signup_disabled')}</p>
        {loginNav}
      </AppLayout>
    );
  }
  if (status === 'success') {
    return (
      <AppLayout title={t('login.register')} footer={footer}>
        <p role="status">{t('login.registerSuccess')}</p>
      </AppLayout>
    );
  }
  if (options.length === 0) {
    return (
      <AppLayout title={t('login.register')} footer={footer}>
        <p role="status">{t('login.noRegisterMethods')}</p>
        {loginNav}
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
    // 必填 / 用户名格式 / 注入策略预校验 / 确认密码本地比对，
    // 未过聚焦首错。
    const issues = setPasswordIssues({
      username,
      password,
      confirm,
      requireUsername: true,
      policy,
    });
    const first = SET_PASSWORD_FIELD_ORDER.find(
      (name) => issues[name] !== undefined,
    );
    if (first !== undefined) {
      setFormErrors(issues);
      focusField(`reg-${first}`);
      return;
    }
    setFormErrors({});
    onSubmit({}); // 确认密码不进 payload（§2.3 字段表）
  };

  return (
    <AppLayout title={t('login.register')} footer={footer}>
      {notice !== undefined && <ErrorBanner i18nKey={notice} />}
      {resolution !== undefined && (
        <ErrorBanner
          i18nKey={resolution.i18nKey}
          fallbackMessage={error?.message}
          retryAfter={error?.retryAfter}
          // verify 段剩余次数由字段旁内联承载，banner 不重复。
          attemptsLeft={step === 'verify' ? undefined : error?.attemptsLeft}
          retryable={resolution.retryable}
          onRetry={RETRY_RESUBMIT_STATUSES.has(status) ? onRetry : undefined}
        />
      )}
      {options.length > 1 && (
        <Tabs
          tabList={options.map((option) => ({
            itemKey: option.method,
            title: t(REGISTER_METHOD_NAME_KEYS[option.method] ?? option.method),
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
          id="reg-code"
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
      {/* verify 段「返回上一步」：原地回 challenge 段改目标（不发请求；已提交
          目标经 challengeValues 回填）。set_password 段不挂——后端 token 状态机
          前向单行，verify 已消费、重放必 step_invalid。 */}
      {step === 'verify' && <StepBackLink onBack={onBackToChallenge} />}
      {step === 'set_password' && (
        <form onSubmit={submitSetPassword} className={styles.section}>
          <div className={styles.field}>
            <label className={styles.label} htmlFor="reg-username">
              {t('login.usernameLabel')}
            </label>
            <input
              className={styles.input}
              id="reg-username"
              name="username"
              type="text"
              value={username}
              autoComplete="username"
              onChange={(e) => {
                onUsernameChange(e.target.value);
                setFormErrors((prev) => {
                  if (prev.username === undefined) {
                    return prev;
                  }
                  const next = { ...prev };
                  delete next.username;
                  return next;
                });
              }}
              {...(formErrors.username !== undefined
                ? {
                    'aria-invalid': true as const,
                    'aria-describedby': 'reg-username-error',
                  }
                : {})}
            />
            {formErrors.username !== undefined ? (
              <p id="reg-username-error" className={styles.fieldError}>
                {formErrors.username}
              </p>
            ) : (
              username !== '' &&
              usernameIssue(username) !== null && (
                <p role="status" className={styles.hint}>
                  {usernameIssue(username) === 'reserved_prefix'
                    ? t('admin.usernameReservedPrefixHint')
                    : t('login.usernameHint')}
                </p>
              )
            )}
          </div>
          <PasswordField
            id="reg-password"
            name="password"
            label={t('login.passwordLabel')}
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
            id="reg-confirm"
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
          <PasswordStrengthMeter
            password={password}
            username={username}
            email={challengeEmail}
            policy={policy}
          />
          <button
            type="submit"
            disabled={loading || submitDisabled}
            className={styles.submit}
          >
            {t('login.register')}
          </button>
        </form>
      )}
      {/* 入口导航：主表单帧底部（成功帧不渲染，自动跳转终点）。 */}
      {loginNav}
    </AppLayout>
  );
}

// ---------------------------------------------------------------------------
// 页面壳（状态 + 提交编排 / 副作用）
// ---------------------------------------------------------------------------

export interface RegisterPageProps {
  /** 注入快照（§2.1；bootstrap 读取后由 routes 传入，flow=register）。 */
  snapshot: MethodsSnapshot;
}

export function RegisterPage({ snapshot }: RegisterPageProps) {
  // SPA 内路由跳转不清内存 loginToken（注册挂载时上一流程的残留 token 会
  // 带进首签请求），挂载即清——本页流程的 token 由 challenge 响应重签。
  useEffect(() => {
    clearLoginToken();
  }, []);
  const options = registerOptionsFor(snapshot);
  // 注入策略随 snapshot 带出（§2.1 passwordPolicy 经 bootstrap 解析；缺省
  // undefined → 视图层回落默认档）。routes 已消费同一注入读 snapshot，
  // 此处补读仅取策略（纯同步读取，PasswordChangeForm 读 account bootstrap
  // 同款）。
  const boot = loadLoginBootstrap();
  const policy = boot.ok ? boot.policy : undefined;
  // 注册成功 = 完成登录的终点 returnTo 消费（useSearchParams
  // 已解码，flowTerminalUrl 不二次 decode）。
  const [searchParams] = useSearchParams();
  const returnTo = searchParams.get('returnTo') ?? undefined;
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
  // captcha 弹窗编排（shared/captcha）：吸收 captcha_required / captcha_invalid，
  // 确认即重提；弹窗声明式挂在页面壳根级（窗体由注入的 login 域 Modal 脱体）。
  const gate = useCaptchaGate(Modal);

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
    // 换方式 = 全新流程：目标持值一并清空（防上一种方式的目标泄进新流程的 Meter 比对）。
    setChallengeValues({});
  };

  const submit = async (values: Readonly<Record<string, string>>) => {
    setLoading(true);
    if (step === 'challenge') {
      setChallengeValues(values);
    }
    // captcha 凭据由 gate 弹窗注入，走请求顶层（§2.3 行 447/451、§2.6 行 672）：
    // otp challenge 与 password 直入 set_password 先问再发；otp 流程 verify /
    // set_password 的 payload 本不含 captcha，命中才问（reactive 防御）。
    const source = step === 'set_password' ? { username, password } : values;
    const result = await runFlowStep(
      register,
      {
        method,
        step,
        payloadFor: () => registerPayloadFor(step, source),
      },
      gate.run,
      {
        mode: registerCaptchaMode(step, method),
        // 首屏配置只作提前量（§2.5 / §1.5 行 228）：运行期权威配置取错误体 details，
        // 不再消费 200 信封的 captcha 字段。
        config: snapshot.captcha,
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
      // 注册成功 = 完成登录（§2.3 行 455）：终点跳转（loginToken 已由 api 层清空）。
      const url = flowTerminalUrl(env, returnTo);
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
  // §2.5；原目标经 challengeValues → OTPForm initialValues 回填）。
  const backToChallenge = () => {
    setStep('challenge');
    setStatus('idle');
    setEnvelope(undefined);
    setOtpCode('');
  };

  // 可重试失败态「重试」= 按当前 step 重提容器持值
  // （challenge 目标 / verify 已输码 / set_password 受控用户名密码均在壳内）。
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
        policy={policy}
        challengeValues={challengeValues}
        onSelectMethod={selectMethod}
        onSubmit={submit}
        onOtpCodeChange={setOtpCode}
        onBackToChallenge={backToChallenge}
        onUsernameChange={setUsername}
        onPasswordChange={setPassword}
        onResend={backToChallenge}
        onRetry={retrySubmit}
      />
      <CaptchaDialog {...gate.dialogProps} />
    </>
  );
}
