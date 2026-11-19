/**
 * 敏感操作二次验证弹窗（接口文档 §3.8）：调 StartVerification 取可用因子 →
 * tabs 常驻展示全部方式（factors.* 文案）→ 点 tab 即取该方式挑战令牌并就地
 * 渲染表单 → 底部单一提交按钮一次提交，成功把结论交回调用方。
 *
 * 零第三方 UI 依赖：窗体由调用方按 domain 注入（account 传
 * `shared/app-ui/Modal`），本组件只拼正文。因子渲染按 method 分派——
 * webauthn 走原生断言（浏览器原生 UI，不经通用字段渲染器），验证码类因子
 * 复用通用 FieldRenderer（docs/前端架构.md §3.3）；step-up 弹窗属 shared
 * 通用层、无 login/factors/registry 可查，方式集合随二次因子全集收敛在此，
 * 新增二次因子同步登记。
 *
 * 交互一次提交（无 select / 「下一步」两段式）：StartVerification 选定因子即
 * 下发阶段——OTP 发码、WebAuthn 取 options（后端架构 §7.3 步骤 6），响应
 * nextStep.challengeData 为断言 options（§3.8.2），challengeToken 只透传。
 * otp 系支持窗内重发（重走 Start、每轮新凭据）与失败剩余次数展示；Submit
 * 失败不关窗、同一 challengeToken 原地重试；调用方 onVerified 抛错同样留窗。
 *
 * captcha gate 自闭环（§2.5 / §3.8.5）：调用方只注入基础配置（captcha），
 * gate 由本弹窗持有并驱动——选定因子的 Start 按 §2.5 触发表分派 upfront
 * （OTP 下发恒拦截）/ reactive（webauthn 取 options、TOTP / 恢复码无下发）
 * 两模式，captcha_required / captcha_invalid 在窗内循环换凭据；用户取消
 * captcha 询问只中止本次取挑战，窗内状态原地保留。
 *
 * 成功分组（§3.8.1）：submit 返回非空串即成功——AccountService 组为
 * verificationToken（交 onVerified）；SsoService 组响应即登录流程结论，
 * 终点跳转由调用方在 submit 内完成（回传非空占位判成功）。
 */
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ComponentType,
  type ReactNode,
} from 'react';
import { create, type JsonObject } from '@bufbuild/protobuf';
import {
  startAuthentication,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import {
  FieldSchema,
  type Field,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import type {
  StartVerificationResponse,
  VerificationMethod,
} from '../../gen/proto/api/common/v1/verification_pb';
import { ApiError, resolveCode } from '../api/errors';
import {
  errorCaptchaOutcome,
  type CaptchaGateMode,
} from '../captcha/captchaGate';
import type { CaptchaDialogProps } from '../captcha/CaptchaDialog';
import { useCaptchaGate, type CaptchaGate } from '../captcha/useCaptchaGate';
import { resolveCapability } from '../hooks/useCapability';
import { useCountdown } from '../hooks/useCountdown';
import { t } from '../i18n';
import { toDisplay } from '../utils/int';
import { FieldRenderer } from './FieldRenderer';
import { Tabs } from './Tabs';
import type { ModalRenderer } from './modal';

// CaptchaDialog 懒加载（本弹窗首实例挂载时拉起）：阻断「本组件 →
// CaptchaDialog → CaptchaWidget → adapters/Image → shared/api/sso →
// http.ts」的 transport 求值链进入静态 import 图——transport 单例在模块
// 求值时读取注入快照，测试环境须在 __AUTHLOFT_INIT__ 注入后才加载；生产
// 无感知（弹窗挂载远早于任何 captcha 询问，会话出现前加载早已完成）。
let CaptchaDialogImpl: ComponentType<CaptchaDialogProps> | undefined;
let captchaDialogChunk: Promise<void> | undefined;

function useCaptchaDialogComponent():
  | ComponentType<CaptchaDialogProps>
  | undefined {
  const [, loaded] = useState(0);
  useEffect(() => {
    if (CaptchaDialogImpl !== undefined) {
      return;
    }
    captchaDialogChunk ??= import('../captcha/CaptchaDialog').then((m) => {
      CaptchaDialogImpl = m.CaptchaDialog;
    });
    void captchaDialogChunk.then(() => loaded((n) => n + 1));
  }, []);
  return CaptchaDialogImpl;
}

/**
 * 弹窗阶段：取方式列表 / 表单交互 / 失败重试。选中方式即进 verify
 *（点 tab 取挑战并渲染表单），不再有独立的选择阶段。
 */
export type StepUpPhase = 'loading' | 'verify' | 'error';

/** 因子名 → 展示文案（factors.* 字典；缺译回显 method 本身）。 */
export function factorLabel(method: string): string {
  const key = `factors.${method}`;
  const text = t(key);
  return text === key ? method : text;
}

/** OTP 系判定（§2.6：challenge 下发两段 + 重发冷却 + 剩余次数；MFA 场景不传目标）。 */
export function isStepUpOtpMethod(method: string): boolean {
  return method === 'otp_sms' || method === 'otp_email';
}

/** webauthn 判定（§2.6 verify 载荷 {credential}；断言由弹窗主按钮驱动）。 */
export function isStepUpWebAuthn(method: string): boolean {
  return method === 'webauthn';
}

/** challengeFields（Struct 承载，§3.8.2）→ 通用 Field；未知形状按零值兜底。 */
function fieldFromStruct(raw: JsonObject): Field {
  const rawLength = raw.length;
  let length = BigInt(0);
  if (typeof rawLength === 'string' && /^\d+$/.test(rawLength)) {
    length = BigInt(rawLength);
  }
  return create(FieldSchema, {
    name: typeof raw.name === 'string' ? raw.name : '',
    label: typeof raw.label === 'string' ? raw.label : '',
    type: typeof raw.type === 'string' ? raw.type : 'text',
    required: raw.required === true,
    length,
  });
}

/** 以 `code` 作为因子载荷的验证方式（§2.6 payload 表）。 */
const CODE_METHODS: ReadonlySet<string> = new Set([
  'otp_sms',
  'otp_email',
  'totp',
  'recovery_code',
]);

/**
 * 因子表单字段：优先用 start 下发能力视图的 challengeFields；无字段的
 * 验证码类因子（TOTP / 恢复码等，§2.6 payload 恒 `{code}`）补一个 code 字段，
 * 位数由 codeLength 驱动，无位数时退回文本输入（恢复码格式）。
 * 非 code 因子不得退化成 code 输入（webauthn 的载荷是 {credential}，
 * 由专属断言流程承担）。
 */
export function stepUpFields(method: VerificationMethod): Field[] {
  const fields = method.challengeFields.map(fieldFromStruct);
  if (fields.length > 0) {
    return fields;
  }
  if (!CODE_METHODS.has(method.method)) {
    return [];
  }
  return [
    create(FieldSchema, {
      name: 'code',
      label: `factors.${method.method}`,
      type: method.codeLength > BigInt(0) ? 'otp' : 'text',
      required: true,
      length: method.codeLength,
    }),
  ];
}

/** 表单值 → 因子 payload（§2.6）：省略空值与 captcha 字段。 */
export function stepUpPayload(
  fields: Field[],
  values: Readonly<Record<string, string>>,
): JsonObject {
  const payload: JsonObject = {};
  for (const field of fields) {
    if (field.type === 'captcha') {
      continue;
    }
    const value = values[field.name];
    if (value !== undefined && value !== '') {
      payload[field.name] = value;
    }
  }
  return payload;
}

/**
 * 选定因子的 captcha 触发时机（§2.5 触发表）：OTP 系下发验证码、后端恒拦截
 * → upfront（先问再发，省一次注定被拦的往返）；webauthn 只取 options（豁免）、
 * TOTP / 恢复码无下发 → reactive（先裸发，命中才问）。
 */
export function stepUpStartMode(method: string): CaptchaGateMode {
  return isStepUpOtpMethod(method) ? 'upfront' : 'reactive';
}

/**
 * 弹窗内取挑战的 gate 编排（§2.5 / §3.8.5，node 可测）：凭据由 gate 现取并
 * 挂到 StartVerification 请求级 captcha（与 payload 平级）；权威配置以错误体
 * details 为准（含服务端降级），captcha_required / captcha_invalid 窗内循环；
 * 用户取消询问 → undefined（调用方窗内原地保留）；其余错误原样抛出。
 * StartVerification 响应无流程状态字段：captcha 结论只在 ApiError 一侧。
 */
export async function runStepUpStart(
  method: string,
  config: CaptchaConfig | undefined,
  start: (
    method: string,
    captcha?: CaptchaPayload,
  ) => Promise<StartVerificationResponse | undefined>,
  runGate: CaptchaGate['run'],
): Promise<StartVerificationResponse | undefined> {
  const outcome = await runGate({
    mode: stepUpStartMode(method),
    config,
    request: (captcha) => start(method, captcha),
    readOutcome: () => ({ action: 'message' }),
    readError: errorCaptchaOutcome,
  });
  if (outcome.kind === 'result') {
    return outcome.result;
  }
  if (outcome.kind === 'cancelled') {
    return undefined;
  }
  throw outcome.error;
}

/** 断言发起依赖（缺省 @simplewebauthn/browser；测试替身注入）。 */
export interface StepUpAuthenticateDeps {
  /** 断言发起替身：optionsJSON 整体透传（不解析、不额外传 allowCredentials）。 */
  start?: (optionsJSON: JsonObject) => Promise<JsonObject>;
}

/** 断言结果：ok=false 时 cancelled 区分用户取消与失败（错误语义独立）。 */
export type StepUpAuthResult =
  | { ok: true; credential: JsonObject }
  | { ok: false; cancelled: boolean };

/** 缺省发起：@simplewebauthn/browser startAuthentication（浏览器原生 UI）。 */
async function defaultStepUpStart(optionsJSON: JsonObject): Promise<JsonObject> {
  const assertion: AuthenticationResponseJSON = await startAuthentication({
    optionsJSON:
      optionsJSON as unknown as PublicKeyCredentialRequestOptionsJSON,
  });
  // @simplewebauthn 断言对象 → Struct JSON 形状（§12.9 credential 透传）。
  return assertion as unknown as JsonObject;
}

/**
 * 发起断言（纯函数，node 可测）：challengeData（StartVerification 下发的
 * nextStep.challengeData，§3.8.2）整体透传给浏览器断言；NotAllowedError =
 * 用户取消（浏览器原生 UI 关闭），其余为失败——异常语义收口在此，弹窗只
 * 消费 cancelled 布尔。
 */
export async function stepUpAuthenticate(
  challengeData: JsonObject,
  deps: StepUpAuthenticateDeps = {},
): Promise<StepUpAuthResult> {
  const start = deps.start ?? defaultStepUpStart;
  try {
    const credential = await start(challengeData);
    return { ok: true, credential };
  } catch (err) {
    return {
      ok: false,
      cancelled: err instanceof DOMException && err.name === 'NotAllowedError',
    };
  }
}

/**
 * 错误 → 窗内文案（§1.5 i18n 优先，未知异常兜底不透出内部信息）。
 * 验证码类失败按 §1.6「提示 + 剩余次数」拼接 attempts_left（有则展示）。
 */
export function stepUpErrorText(error: unknown): string {
  if (error instanceof ApiError) {
    const base = t(resolveCode(error).i18nKey);
    const attemptsLeft = error.attemptsLeft;
    if (attemptsLeft === undefined) {
      return base;
    }
    return t('login.stepUpAttemptsLeft', {
      message: base,
      count: toDisplay(attemptsLeft),
    });
  }
  return t('errors.code.unknown');
}

/**
 * 弹窗主按钮可用性（纯函数，静态可测）：在途 / 取方式列表中禁用；verify
 * 阶段未选定方式（方式列表引导态）或选定因子无可渲染字段时禁用——不留
 * 「点了没反应」的静默态；webauthn 断言由主按钮驱动、恒可用；error 阶段
 * 主按钮即「重试」，恒可用。
 */
export function stepUpOkDisabled(
  phase: StepUpPhase,
  activeMethod: VerificationMethod | undefined,
  fields: readonly Field[],
  busy: boolean,
): boolean {
  if (busy || phase === 'loading') {
    return true;
  }
  if (phase === 'error') {
    return false;
  }
  if (activeMethod === undefined) {
    return true;
  }
  if (isStepUpWebAuthn(activeMethod.method)) {
    return false;
  }
  return fields.length === 0;
}

/** 弹窗正文（纯视图，静态渲染可测各阶段帧）。 */
export interface StepUpDialogViewProps {
  phase: StepUpPhase;
  methods: VerificationMethod[];
  /** 当前选定方式；undefined = 尚未选择（tabs 引导态，主按钮禁用）。 */
  activeMethod?: VerificationMethod;
  values: Readonly<Record<string, string>>;
  errorText?: string;
  /** 在途（取挑战 / 提交 / 断言），驱动重发按钮禁用。 */
  busy?: boolean;
  /** OTP 系重发冷却（能力视图 resendAfter；undefined=无倒计时）。 */
  retryAfter?: bigint;
  onTabSelect?: (method: string) => void;
  onChange?: (name: string, value: string) => void;
  onResend?: () => void;
}

export function StepUpDialogView(props: StepUpDialogViewProps): ReactNode {
  const fields =
    props.activeMethod === undefined ? [] : stepUpFields(props.activeMethod);
  const isWebAuthn =
    props.activeMethod !== undefined &&
    isStepUpWebAuthn(props.activeMethod.method);
  const isOtp =
    props.activeMethod !== undefined &&
    isStepUpOtpMethod(props.activeMethod.method);
  // 重发倒计时基于时间戳（§9 第 7 条）；非 OTP 系不渲染重发位。
  const countdown = useCountdown(props.retryAfter);

  return (
    <>
      <p>{t('account.stepUpHint')}</p>
      {props.errorText !== undefined ? (
        <p role="alert">{props.errorText}</p>
      ) : null}
      {props.phase === 'loading' && props.methods.length === 0 ? (
        <p>{t('common.loading')}</p>
      ) : null}
      {props.methods.length > 0 ? (
        <>
          <p>{t('login.mfaSelectHint')}</p>
          <Tabs
            tabList={props.methods.map((method) => ({
              itemKey: method.method,
              title: factorLabel(method.method),
            }))}
            activeKey={props.activeMethod?.method ?? ''}
            onChange={(key) => props.onTabSelect?.(key)}
          />
        </>
      ) : props.phase === 'verify' ? (
        <p role="status">{t('account.stepUpNoMethods')}</p>
      ) : null}
      {props.phase === 'verify' && props.activeMethod !== undefined ? (
        isWebAuthn ? null : fields.length === 0 ? (
          <p role="status">{t('login.stepUpFactorUnsupported')}</p>
        ) : (
          <>
            <FieldRenderer
              fields={fields}
              values={props.values}
              onChange={props.onChange ?? (() => undefined)}
              idPrefix="stepup"
            />
            {isOtp ? (
              <button
                type="button"
                disabled={props.busy === true || !countdown.expired}
                onClick={props.onResend}
              >
                {countdown.expired
                  ? t('login.resend')
                  : t('login.resendCountdown', { seconds: countdown.seconds })}
              </button>
            ) : null}
          </>
        )
      ) : null}
    </>
  );
}

export interface StepUpDialogProps {
  /** domain 窗体实现（account / admin 传 shared/app-ui/Modal）。 */
  modal: ModalRenderer;
  title?: string;
  /**
   * captcha 基础配置（§2.5：login 注入快照 methods.captcha / account 取
   * GetConfig）；gate 运行期配置以错误体 details 为准，本弹窗不缓存。
   */
  captcha?: CaptchaConfig;
  /**
   * 取可用因子与挑战令牌；method 空 = 只取 methods[]，非空 = 选定该因子
   * （Start 即下发阶段）。captcha 凭据由弹窗内 gate 注入；captcha 询问被
   * 用户取消时返回 undefined（窗内状态原地保留）。
   */
  start: (
    method: string,
    captcha?: CaptchaPayload,
  ) => Promise<StartVerificationResponse | undefined>;
  /** 提交因子载荷，成功返回 verificationToken 或登录结论占位（空串视为失败响应）。 */
  submit: (
    challengeToken: string,
    method: string,
    payload: JsonObject,
  ) => Promise<string>;
  /** 二次验证通过：AccountService 组参数为不透明 verificationToken；抛错则留在窗内可重试。 */
  onVerified: (verificationToken: string) => void | Promise<void>;
  onCancel: () => void;
}

export function StepUpDialog(props: StepUpDialogProps): ReactNode {
  const { modal, start, submit, onVerified, onCancel } = props;
  const [phase, setPhase] = useState<StepUpPhase>('loading');
  const [methods, setMethods] = useState<VerificationMethod[]>([]);
  const [activeMethod, setActiveMethod] = useState<
    VerificationMethod | undefined
  >(undefined);
  const [challengeToken, setChallengeToken] = useState('');
  const [challengeData, setChallengeData] = useState<JsonObject | undefined>(
    undefined,
  );
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | undefined>(undefined);
  const [retryAfter, setRetryAfter] = useState<bigint | undefined>(undefined);

  // start 放 ref：取方式列表的首屏 effect 只随挂载跑一次，调用方即使传内联
  // 闭包（每次渲染换新引用）也不会重跑 StartVerification、清掉在途挑战令牌。
  const startRef = useRef(start);
  startRef.current = start;

  // captcha gate 自闭环（§2.5）：窗体复用注入的 domain Modal，弹窗铺在根级；
  // 调用方只注入基础配置，凭据由 gate 每轮现取（一次性，不复用）。
  const gate = useCaptchaGate(modal);
  const CaptchaDialogComp = useCaptchaDialogComponent();

  const loadMethods = useCallback(async () => {
    setPhase('loading');
    setMessage(undefined);
    setMethods([]);
    setActiveMethod(undefined);
    setChallengeToken('');
    setChallengeData(undefined);
    setValues({});
    setRetryAfter(undefined);
    try {
      const response = await startRef.current('');
      if (response === undefined) {
        setMessage(t('account.stepUpInvalidResponse'));
        setPhase('error');
        return;
      }
      // capability 不满足的因子不进 tabs（§2.1 口径：不支持自动不展示）。
      setMethods(
        response.methods.filter((m) => resolveCapability(m.capability)),
      );
      setPhase('verify');
    } catch (error) {
      setMessage(stepUpErrorText(error));
      setPhase('error');
    }
  }, []);

  useEffect(() => {
    void loadMethods();
  }, [loadMethods]);

  /**
   * 选定方式：Start 即下发阶段（OTP 发码 / WebAuthn options），gate 内收在
   * 弹窗。captcha 询问取消 → 原地保留（含既有表单）；取挑战失败 → 目标 tab
   * 高亮、主按钮转「重试」（重取当前方式挑战）。
   */
  const beginMethod = useCallback(
    async (method: string) => {
      const entry = methods.find((item) => item.method === method);
      if (entry === undefined) {
        return;
      }
      setBusy(true);
      setMessage(undefined);
      try {
        const response = await runStepUpStart(
          method,
          props.captcha,
          (target, captcha) => startRef.current(target, captcha),
          gate.run,
        );
        if (response === undefined) {
          return;
        }
        if (response.challengeToken === '') {
          setMessage(t('account.stepUpInvalidResponse'));
          return;
        }
        setActiveMethod(entry);
        setChallengeToken(response.challengeToken);
        setChallengeData(response.nextStep?.challengeData);
        setValues({});
        setRetryAfter(
          entry.resendAfter > BigInt(0) ? entry.resendAfter : undefined,
        );
        setPhase('verify');
      } catch (error) {
        setActiveMethod(entry);
        setMessage(stepUpErrorText(error));
        setPhase('error');
      } finally {
        setBusy(false);
      }
    },
    [gate.run, methods, props.captcha],
  );

  /**
   * 提交因子载荷：失败只更新窗内错误位（invalid_code 附剩余次数，§1.6），
   * 同一 challengeToken 原地重试；webauthn 经 override 提交 {credential}。
   */
  const submitForm = useCallback(
    async (override?: JsonObject) => {
      if (activeMethod === undefined || challengeToken === '') {
        return;
      }
      const payload =
        override ?? stepUpPayload(stepUpFields(activeMethod), values);
      setBusy(true);
      setMessage(undefined);
      try {
        const token = await submit(
          challengeToken,
          activeMethod.method,
          payload,
        );
        if (token === '') {
          setMessage(t('account.stepUpInvalidResponse'));
          return;
        }
        await onVerified(token);
      } catch (error) {
        setMessage(stepUpErrorText(error));
      } finally {
        setBusy(false);
      }
    },
    [activeMethod, challengeToken, onVerified, submit, values],
  );

  /** webauthn 主按钮驱动：原生断言成功即提交 {credential}（§2.6）。 */
  const submitWebAuthn = useCallback(async () => {
    if (activeMethod === undefined) {
      return;
    }
    if (challengeData === undefined) {
      setMessage(t('account.stepUpInvalidResponse'));
      return;
    }
    setBusy(true);
    setMessage(undefined);
    try {
      const result = await stepUpAuthenticate(challengeData);
      if (!result.ok) {
        setMessage(
          t(
            result.cancelled
              ? 'login.passkeyCancelled'
              : 'login.passkeyFailed',
          ),
        );
        return;
      }
      await submitForm({ credential: result.credential });
    } finally {
      setBusy(false);
    }
  }, [activeMethod, challengeData, submitForm]);

  const handleOk = () => {
    if (busy) {
      return;
    }
    if (phase === 'error') {
      // 重试：取挑战失败重取当前方式；方式列表失败重取列表。
      if (activeMethod !== undefined) {
        void beginMethod(activeMethod.method);
      } else {
        void loadMethods();
      }
      return;
    }
    if (phase !== 'verify' || activeMethod === undefined) {
      return;
    }
    if (isStepUpWebAuthn(activeMethod.method)) {
      void submitWebAuthn();
      return;
    }
    void submitForm();
  };

  const okText =
    phase === 'error' ? t('common.retry') : t('account.stepUpVerifyAction');
  const fields = activeMethod === undefined ? [] : stepUpFields(activeMethod);
  const Modal = modal;

  return (
    <>
      <Modal
        visible
        title={props.title ?? t('account.stepUpTitle')}
        okText={okText}
        cancelText={t('common.cancel')}
        confirmLoading={busy}
        closable={!busy}
        closeOnEsc={!busy}
        maskClosable={false}
        okButtonProps={{
          disabled: stepUpOkDisabled(phase, activeMethod, fields, busy),
        }}
        onOk={handleOk}
        onCancel={() => {
          if (!busy) {
            onCancel();
          }
        }}
      >
        <StepUpDialogView
          phase={phase}
          methods={methods}
          activeMethod={activeMethod}
          values={values}
          errorText={message}
          busy={busy}
          retryAfter={retryAfter}
          onTabSelect={(method) => {
            if (!busy) {
              void beginMethod(method);
            }
          }}
          onChange={(name, value) =>
            setValues((prev) => ({ ...prev, [name]: value }))
          }
          onResend={() => {
            // 重发 = 重走当前方式 Start（新凭据、新挑战令牌，§2.5 一次性）。
            if (!busy && activeMethod !== undefined) {
              void beginMethod(activeMethod.method);
            }
          }}
        />
      </Modal>
      {CaptchaDialogComp !== undefined ? (
        <CaptchaDialogComp {...gate.dialogProps} />
      ) : null}
    </>
  );
}
