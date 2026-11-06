/**
 * 登录状态机容器（docs/前端架构.md §4.1 行 383）：消费
 * flow/{machine,reducer,selectors} 与 api.ts——发起请求、处理响应、驱动子组件、
 * 处理终点。
 *
 * - mfa_required **原地渲染**（不跳页、不新开流程，§4.1 行 407）：mfa.methods
 *   选择器（因子名取 factors.* 字典 + webauthn 条目 hint 提示，§1.3 行 125）+
 *   选中方式的因子组件（select_method 清信封，方式列表由容器本地镜像保持）；
 * - status=next 按 next_step.kind 接 steps/StepDispatcher 分派（§4.2 行 423）：
 *   form → form 段（专属因子 verify 段（OTPForm，含重发倒计时 / 错误计数）
 *   或 FormStep——totp 显式 null 的渲染落点）；challenge / redirect / qrcode /
 *   poll 未实现、external 宿主承载（§9 第 10 条）→ 兜底「请刷新重试」；
 * - OTP 链路（§1.10 行 306-307 challenge→form）：challenge 提交后响应
 *   next_step.kind=form 时 advance 推进请求侧 step 到 verify（runSubmit 内）；
 *   verify 段重发 = 容器以 step=challenge 重走（onResend，主因子场景带原目标、
 *   MFA 场景空 payload，§2.6 行 544-545）；
 * - 终点（§4.1 行 383；§1.3 行 158-162 三级优先级）：syncCookieUrl
 *   是后端拼好的多域名同步首跳完整 URL（§1.3 行 137、§2.9）→ location.replace
 *   它（跳转链由各域页面接力，最终回 redirectTo）；省略时直接 replace(redirectTo)；
 *   皆空（直登场景）→ 默认落点 DEFAULT_ACCOUNT_HOME，禁止停留提示页——移动端用
 *   replace 防回退死循环（§4.2 行 426 RedirectStep 同款语义）；
 * - captcha_required / captcha_invalid **原地插入** CaptchaWidget（shared/captcha）：
 *   运行期响应顶层 captcha 是权威来源（§2.5 行 519），按新 captcha 对象重新渲染、
 *   不刷新页面（adapterKey 重建机制）；
 *   captcha_invalid 时 reset widget 后重试（§1.6 行 241）；
 * - 请求状态复用状态机的 loading（既有机制，不引 useRequest 双状态源；
 *   提交按钮按 loading 禁用，§3.2）；
 * - kind→step 映射归容器层（注入快照 steps 为唯一定义，reducer 只镜像事件
 *   不自造语义）。
 *
 * 文案：占位 / 引导类文案经 i18n 字典 login.* 键取用。
 */
import {
  useEffect,
  useReducer,
  useRef,
  useState,
  type ReactNode,
  type Ref,
} from 'react';
import { create, type JsonObject } from '@bufbuild/protobuf';
import {
  FieldSchema,
  type Field,
  type LoginFlowResponse,
  type MfaMethod,
} from '../gen/proto/api/sso/v1/envelope_pb';
import type { CaptchaPayload } from '../gen/proto/api/sso/v1/login_pb';
import { resolveFlowStatus } from '../shared/api/errors';
import { CaptchaWidget, type CaptchaWidgetHandle } from '../shared/captcha/CaptchaWidget';
import { ErrorBanner } from '../shared/components';
import { t } from '../shared/i18n';
import { DEFAULT_ACCOUNT_HOME } from '../shared/urls';
import type {
  MethodsSnapshot,
  SnapshotField,
} from '../shared/types/init';
import { loginDefault, type LoginDefaultInput } from './api';
import { BindingPage } from './pages/BindingPage';
import { OTPForm, isOtpForm } from './factors/OTPForm';
import {
  WebAuthnButton,
  isWebAuthnForm,
} from './factors/WebAuthnButton';
import { lookupFactor } from './factors/registry';
import { FormStep } from './steps/FormStep';
import { StepDispatcher } from './steps/StepDispatcher';
import { MethodTabs } from './MethodTabs';
import { RETRY_RESUBMIT_STATUSES } from './validate';
import styles from './LoginContainer.module.less';
import {
  flowReducer,
  type FlowEvent,
} from './flow/reducer';
import {
  selectShowCaptcha,
  selectSubmitDisabled,
} from './flow/selectors';
import {
  INITIAL_FLOW_STATE,
  type FlowEffect,
  type FlowState,
  type LoginStatus,
  type MachineStatus,
} from './flow/machine';

/** LoginPayload 的 init 形状（login/api.ts 的 LoginDefaultInput.payload）。 */
type PayloadInit = NonNullable<LoginDefaultInput['payload']>;

// ---------------------------------------------------------------------------
// 容器层纯函数（node 可测；编排 / 映射 / 终点语义的唯一落点）
// ---------------------------------------------------------------------------

/**
 * login 域 kind→step 映射（§1.10 唯一定义）：
 * 注入快照 steps 的首个 kind → 请求侧 step（§2.2 行 422）。login 域取值仅
 * form / challenge（§1.10：password=一步 form；otp 系 / webauthn=challenge→form），
 * form 映射 verify（set_password 属注册 / 重置端点，§2.2 行 422）；空 / 未知
 * 兜底同 verify（§9 第 18 条零值兜底口径）。
 */
export function firstStepFor(steps: readonly string[]): string {
  return steps[0] === 'challenge' ? 'challenge' : 'verify';
}

/** int64 十进制字符串（§1.12）→ bigint；缺失 / 空串 / 非法兜底 0。 */
function parseCount(value: string | undefined): bigint {
  try {
    return BigInt(value ?? '');
  } catch {
    return BigInt(0);
  }
}

/**
 * 注入快照字段 → 生成物 Field（渲染模型转换）：快照是原始 JSON（protojson
 * 口径，int64 十进制字符串，shared/types/init.ts）；FieldRenderer 消费生成物
 * 形状（bigint），转换是容器职责（与 kind→step 映射同层）。
 */
export function snapshotFieldToField(snapshot: SnapshotField): Field {
  return create(FieldSchema, {
    name: snapshot.name,
    label: snapshot.label ?? '',
    type: snapshot.type,
    required: snapshot.required ?? false,
    length: parseCount(snapshot.length),
    maxAttempts: parseCount(snapshot.maxAttempts),
  });
}

/**
 * 表单值 → LoginPayload init：字段名与请求体一致（§1.3 行 114「字段名，与
 * 请求体字段一致」），白名单 = 生成物 LoginPayload 的 string 字段全集
 * （webauthn 的 credential 是 Struct、不走表单值通道，§2.6）；captcha 字段
 * 由容器从 CaptchaWidget 取三元组、不经表单值（§1.11 skip）。
 */
const PAYLOAD_STRING_FIELDS: ReadonlySet<string> = new Set([
  'username',
  'password',
  'phone',
  'email',
  'code',
]);

export function toPayloadInit(
  values: Readonly<Record<string, string>>,
  fields: readonly Field[],
): PayloadInit {
  const init: Record<string, string> = {};
  for (const field of fields) {
    if (field.type !== 'captcha' && PAYLOAD_STRING_FIELDS.has(field.name)) {
      init[field.name] = values[field.name] ?? '';
    }
  }
  return init as PayloadInit;
}

/**
 * 提交白名单字段源（抽为可导出纯函数；容器 submit / resend 的
 * toPayloadInit 输入）：
 * - mfa 场景（信封方式条目，§1.3 行 121-127）：challenge 步取 challengeFields、
 *   verify 步取 fields；verify 步 fields 为空且 OTP 系时补 code 白名单——
 *   后端 mfa.go 对 otp 系 mfa 条目不填 fields，而 otp verify
 *   的 payload 恒 {code}（§2.6 行 546），不补则提交必丢 code；
 * - 主因子（注入快照，§2.1 行 390-394）：challenge 步取 challengeFields、
 *   form 步取 fields；OTP 系 verify 步快照无 form 步字段（code 字段由响应
 *   nextStep.fields 下发，§1.3 行 114；失败态信封无 next_step）同款补 code
 *   白名单描述，codeLength 取快照（§2.1 行 391，缺失兜底 0，§9 第 18 条）。
 */
export function fieldsFor(
  method: string,
  step: string,
  snapshot: MethodsSnapshot,
  mfaMethods: readonly MfaMethod[] | undefined,
): readonly Field[] {
  const snapshotEntry = snapshot.methods.find((m) => m.method === method);
  const otp = isOtpForm(lookupFactor(method));
  /** OTP 系 verify 步的 code 白名单描述（§2.6 行 546 payload 恒 {code}）。 */
  const otpCodeField = (): Field[] => [
    create(FieldSchema, {
      name: 'code',
      type: 'otp',
      length: parseCount(snapshotEntry?.codeLength),
    }),
  ];

  const mfaEntry = mfaMethods?.find((m) => m.method === method);
  if (mfaEntry !== undefined) {
    if (step === 'challenge') {
      return mfaEntry.challengeFields;
    }
    return mfaEntry.fields.length > 0
      ? mfaEntry.fields
      : otp
        ? otpCodeField()
        : [];
  }

  const fields = (
    (step === 'challenge' ? snapshotEntry?.challengeFields : snapshotEntry?.fields) ??
    []
  ).map(snapshotFieldToField);
  if (fields.length > 0) {
    return fields;
  }
  return otp ? otpCodeField() : fields;
}

/**
 * 终点 URL（§4.1 行 383；§1.3 行 158-162 定稿）：syncCookieUrl 非空 →
 * 它（后端拼好的首跳完整 URL，§1.3 行 137）；否则 redirectTo；两者皆空 →
 * 默认落点 DEFAULT_ACCOUNT_HOME（直登场景，三级互斥完备；禁止停留「登录成功」提示页）。
 */
export function terminalUrl(envelope: LoginFlowResponse): string {
  if (envelope.syncCookieUrl !== '') {
    return envelope.syncCookieUrl;
  }
  if (envelope.redirectTo !== '') {
    return envelope.redirectTo;
  }
  return DEFAULT_ACCOUNT_HOME;
}

/**
 * 扫码结论信封事件（§2.8 行 739-743）：QRCodeStep 上抛外层信封，
 * 登录结论在**内层 `login`**（§1.3 同构信封）——内层非 success → 状态机
 * response 事件（binding_required → LoginFlowView 原地渲染 BindingPage，
 * §1.6 行 234；失败态 → 表单区 + ErrorBanner 表驱动文案，图标墙可重新
 * 拉码 = 重试动作，§1.6 行 240）；内层 success 不镜像（终点跳转已由
 * QRCodeStep completeLogin 完成，防二次 replace）；内层缺失（防御，
 * 后端 pollResult 必填）→ undefined 交消费方零值兜底。纯函数，node 可测。
 */
export function qrResultEvent(
  outer: LoginFlowResponse,
): FlowEvent | undefined {
  const login = outer.login;
  return login !== undefined && login.status !== 'success'
    ? { type: 'response', envelope: login }
    : undefined;
}

/**
 * 副作用执行（machine.FlowEffect 的容器落地）：complete → 跳转（注入
 * location.replace 语义，测试传记录函数）；restart → 回到第一步并按 status
 * 提示（token 类提示「登录已超时…」由 errors.status.* 字典承载，§4.1 行 403）。
 */
export function executeEffects(
  effects: readonly FlowEffect[],
  handlers: {
    complete: (url: string) => void;
    restart: (status: LoginStatus) => void;
  },
): void {
  for (const effect of effects) {
    if (effect.type === 'complete') {
      const url = terminalUrl(effect.envelope);
      if (url !== '') {
        handlers.complete(url);
      }
    } else {
      handlers.restart(effect.status);
    }
  }
}

/**
 * 提交编排（纯逻辑，request 可注入）：request_started 由容器在调用前同步
 * dispatch（loading 立即反映 UI）；本函数只承担「请求 → response 事件」。
 * captcha 凭据由调用方注入的 getCaptchaToken 提供（§2.5 行 503-510 提交
 * 格式；未完成 → undefined → 不带 captcha 提交，§3.5 adapter 契约）。
 * 传输层异常（登录流程域业务态一律 HTTP 200，§1.5；非 200 / 网络失败经
 * http.ts 归一 ApiError 抛出）→ 回到第一步（reset）+ failed 兜底（§1.6 行
 * 272：不暴露内部信息），不伪造信封。
 */
export async function runSubmit(
  state: FlowState,
  payload: PayloadInit,
  getCaptchaToken: () => CaptchaPayload | undefined,
  request: (input: LoginDefaultInput) => Promise<LoginFlowResponse>,
): Promise<{ events: readonly FlowEvent[]; failed: boolean }> {
  const captcha = getCaptchaToken();
  const payloadWithCaptcha =
    captcha === undefined ? payload : { ...payload, captcha };
  try {
    const envelope = await request({
      method: state.method,
      step: state.step,
      payload: payloadWithCaptcha,
    });
    const events: FlowEvent[] = [{ type: 'response', envelope }];
    if (
      state.step === 'challenge' &&
      envelope.status === 'next' &&
      envelope.nextStep?.kind === 'form'
    ) {
      // §1.10 行 306-307 OTP 系 kind 序列 challenge→form：form 步对应请求侧
      // verify（kind→step 映射），advance 推进下一次提交的 step。
      events.push({ type: 'advance', step: 'verify' });
    }
    return { events, failed: false };
  } catch {
    return { events: [{ type: 'reset' }], failed: true };
  }
}

/** 非失败态（§4.1 行 395 状态机图：流程 / 轮询 / captcha 中间态）——不渲染 ErrorBanner。 */
const NON_ERROR_STATUSES: ReadonlySet<string> = new Set([
  'idle',
  'next',
  'mfa_required',
  'binding_required',
  'success',
  'captcha_required',
  'captcha_invalid',
  'pending',
  'scanned',
  'expired',
]);

/** 是否失败态（§4.1 行 395：非 success 即失败，轮询进行中除外）：渲染 ErrorBanner 的判据。 */
export function isErrorStatus(status: MachineStatus): boolean {
  return !NON_ERROR_STATUSES.has(status);
}

// ---------------------------------------------------------------------------
// 视图（状态分支渲染；静态可测——renderToStaticMarkup 下不执行副作用）
// ---------------------------------------------------------------------------

export interface LoginFlowViewProps {
  /** 注入快照（§2.1）。 */
  snapshot: MethodsSnapshot;
  /** 状态机状态（FlowState）。 */
  state: FlowState;
  /** restart / 传输失败的一次性提示（i18nKey；选择新方式时清空）。 */
  notice?: string;
  onSelect: (method: string) => void;
  /** mfa 方式选择（§1.3 行 121 mfa.methods；容器推导首步后 dispatch select_method）。 */
  onSelectMfa?: (method: string, firstStep: string) => void;
  onSubmit: (values: Readonly<Record<string, string>>) => void;
  /** OTP verify 段重发（容器以 step=challenge 重走，§1.10 challenge→form 序列）。 */
  onResend?: () => void;
  /** OTP verify 段已输码（容器持值，实例随状态分支重建不丢）。 */
  otpCode?: string;
  /** OTP verify 段输码变化上抛（与 otpCode 成对注入）。 */
  onOtpCodeChange?: (value: string) => void;
  captchaRef?: Ref<CaptchaWidgetHandle>;
  /** mfa 场景方式列表（select_method 清信封后由容器本地保持，§4.1 行 407 就地渲染）。 */
  mfaMethods?: readonly MfaMethod[];
  /** webauthn verify 段断言上抛（容器组装 payload {credential}，§2.6 行 548）。 */
  onCredential?: (credential: JsonObject) => void;
  /** webauthn 最近一次下发的 options 容器镜像（失败态信封无 nextStep，容器持值注入）。 */
  challengeData?: JsonObject;
  /**
   * 扫码登录结论（§2.8 行 739-743）：透传 MethodTabs → ProviderButtons
   * → QRCodeStep 上抛——binding_required / 失败态经容器 qrResultEvent 分派。
   */
  onQrResult?: (envelope: LoginFlowResponse) => void;
  /**
   * 「返回方式列表」入口（评审 P0-1）：next / mfa 分支渲染次级链接，
   * 容器 dispatch reset 回第一步（reducer「换方式 = 全新流程」语义）。
   */
  onBackToMethods?: () => void;
  /** 可重试失败态的「重试」动作（评审 P1-4：重提最近一次提交的容器持值）。 */
  onRetry?: () => void;
  /** challenge 段已提交目标值（评审 P1-5：OTPForm initialValues 回填）。 */
  challengeValues?: Readonly<Record<string, string>>;
}

/**
 * mfa 方式选择器（§4.1 行 407：mfa.methods 原地渲染、不跳页；§1.3 行 121-127）：
 * 按钮即因子（factors.* 字典），点击上抛 method + 首步（容器 kind→step 映射后
 * dispatch select_method，与主因子方式切换同款语义）；webauthn 条目的 hint
 * 提示文案（§1.3 行 125，如「请触摸已绑定的通行密钥」）附在按钮下方展示
 * （其余因子 hint 零值空串不渲染）。
 */
function MfaSelector({
  methods,
  current,
  onSelect,
}: {
  methods: readonly MfaMethod[];
  current: string;
  onSelect?: (method: string, firstStep: string) => void;
}) {
  return (
    <nav>
      <ul className={styles.mfaList}>
        {methods.map((m) => (
          <li key={m.method} className={styles.mfaItem}>
            <button
              type="button"
              className={m.method === current ? styles.mfaTabActive : styles.mfaTab}
              aria-current={m.method === current ? 'true' : undefined}
              onClick={() => onSelect?.(m.method, firstStepFor(m.steps))}
            >
              {t(`factors.${m.method}`)}
            </button>
            {m.hint !== '' && <span className={styles.mfaHint}>{m.hint}</span>}
          </li>
        ))}
      </ul>
    </nav>
  );
}

/** 状态分支渲染（§4.1 行 386-395 状态机图的视图落地）。 */
export function LoginFlowView({
  snapshot,
  state,
  notice,
  onSelect,
  onSelectMfa,
  onSubmit,
  onResend,
  otpCode,
  onOtpCodeChange,
  captchaRef,
  mfaMethods,
  onCredential,
  challengeData,
  onQrResult,
  onBackToMethods,
  onRetry,
  challengeValues,
}: LoginFlowViewProps) {
  // 扫码轮询态（本容器不发起轮询；QRCodeStep / PollStep 归后续实现）。
  if (
    state.status === 'pending' ||
    state.status === 'scanned' ||
    state.status === 'expired'
  ) {
    return <p role="status">{t('login.pollPlaceholder')}</p>;
  }
  if (state.status === 'success') {
    return <p role="status">{t('login.redirecting')}</p>;
  }
  // binding_required → 原地渲染绑定选择页（§4.1 行 406；§4.4 行 466）：
  // 不跳页、不新开流程（mfa_required 同款原地模式）、/sso/binding 不在路由表；
  // 两选项与建号 / 退出编排在 BindingPage 内闭环（§2.7.5）。
  if (state.status === 'binding_required') {
    return <BindingPage binding={state.envelope?.binding} notice={notice} />;
  }

  const error = state.envelope?.error;
  // OTP 系扩展 props（§4.3 行 436）：重发倒计时取 nextStep.retryAfter（next 态）
  // / error.retryAfter（失败态，§1.3 行 115/150）；错误计数取 error.attemptsLeft（行 151）。
  const otpRetryAfter =
    state.envelope?.nextStep?.retryAfter ?? error?.retryAfter;
  const resolution = isErrorStatus(state.status)
    ? resolveFlowStatus(state.status)
    : undefined;

  /**
   * 评审 P1-4：banner 公共接线——OTP 系因子的剩余次数由字段旁内联
   * 承载（OTPForm attemptsLeft），banner 不再重复；onRetry 仅「重提同值有意义」
   * 的白名单失败态接线（RETRY_RESUBMIT_STATUSES；retryable 由 ErrorBanner 自身判定）。
   */
  const bannerExtras = (factorMethod: string) => ({
    attemptsLeft: isOtpForm(lookupFactor(factorMethod))
      ? undefined
      : error?.attemptsLeft,
    onRetry: RETRY_RESUBMIT_STATUSES.has(state.status) ? onRetry : undefined,
  });

  /** 评审 P0-1：next / mfa 分支的「返回方式列表」次级入口。 */
  const backToMethodsNode = onBackToMethods !== undefined && (
    <button
      type="button"
      className={styles.backLink}
      onClick={onBackToMethods}
    >
      {t('login.backToMethods')}
    </button>
  );

  /**
   * 因子渲染三态（§4.3 行 434）：undefined → 缺映射兜底（如 thirdparty，不静默
   * 回退）；null → 通用 FormStep（totp 显式 null 的语义落地）；组件 → 专属因子
   * 表单（OTP 系注入扩展 props，verify 段重发倒计时 / 错误计数；webauthn 注入
   * challengeData / onCredential——challengeData 信封 nextStep 优先，
   * 失败态信封无 nextStep 回退容器镜像，§1.6 行 247 原地重试可重走断言）。
   */
  const renderFactorNode = (
    method: string,
    fields: readonly Field[],
    maskedTarget?: string,
  ): ReactNode => {
    const factor = lookupFactor(method);
    const factorProps = {
      fields,
      loading: state.loading,
      disabled: selectSubmitDisabled(state),
      onSubmit,
    };
    if (factor === undefined) {
      return <p role="alert">{t('common.refreshAndRetry')}</p>;
    }
    if (factor === null) {
      return <FormStep {...factorProps} />;
    }
    if (isWebAuthnForm(factor)) {
      return (
        <WebAuthnButton
          {...factorProps}
          challengeData={state.envelope?.nextStep?.challengeData ?? challengeData}
          onCredential={onCredential}
        />
      );
    }
    if (isOtpForm(factor)) {
      return (
        <OTPForm
          {...factorProps}
          step={state.step}
          retryAfter={otpRetryAfter}
          attemptsLeft={error?.attemptsLeft}
          maskedTarget={maskedTarget}
          onResend={onResend}
          code={otpCode}
          onCodeChange={onOtpCodeChange}
          initialValues={challengeValues}
        />
      );
    }
    // JSX 组件变量须大写开头（小写会被解析为字符串标签）。
    const Factor = factor;
    return <Factor {...factorProps} />;
  };

  // mfa 场景（§4.1 行 407：原地渲染选择器 + 因子组件，不跳页、不新开流程）：
  // mfa_required 刚到达时读信封 mfa.methods；选择方式后（select_method 清信封）
  // 读容器本地镜像 mfaMethods。
  const mfaList =
    state.status === 'mfa_required'
      ? (state.envelope?.mfa?.methods ?? [])
      : (mfaMethods ?? []);
  if (state.status === 'mfa_required' || (mfaMethods?.length ?? 0) > 0) {
    if (mfaList.length === 0) {
      // 零值兜底（§9 第 18 条）：mfa_required 无可用方式（防御，后端必附）。
      return <p role="alert">{t('common.refreshAndRetry')}</p>;
    }
    const mfaEntry = mfaList.find((m) => m.method === state.method);
    return (
      <div className={styles.flow}>
        {notice !== undefined && <ErrorBanner i18nKey={notice} />}
        <MfaSelector
          methods={mfaList}
          current={state.method}
          onSelect={onSelectMfa}
        />
        {state.status === 'next' && state.envelope?.nextStep !== undefined ? (
          // OTP 系 mfa challenge 后的 next（kind=form）：StepDispatcher 分派 verify 段。
          <StepDispatcher
            nextStep={state.envelope.nextStep}
            form={renderFactorNode(
              state.envelope.nextStep.method !== ''
                ? state.envelope.nextStep.method
                : state.method,
              state.envelope.nextStep.fields,
            )}
          />
        ) : mfaEntry === undefined ? (
          // 未选择二次方式（刚进入 mfa_required，state.method 还是主因子）。
          <p role="status">{t('login.mfaSelectHint')}</p>
        ) : (
          renderFactorNode(mfaEntry.method, mfaEntry.fields, mfaEntry.maskedTarget)
        )}
        {selectShowCaptcha(state) &&
          state.envelope?.captcha !== undefined && (
            <CaptchaWidget captcha={state.envelope.captcha} ref={captchaRef} />
          )}
        {resolution !== undefined && (
          <ErrorBanner
            i18nKey={resolution.i18nKey}
            fallbackMessage={error?.message}
            retryAfter={error?.retryAfter}
            retryable={resolution.retryable}
            {...bannerExtras(mfaEntry?.method ?? state.method)}
          />
        )}
        {backToMethodsNode}
      </div>
    );
  }

  // status=next → next_step.kind 分派（§4.2：form → form 段；其余 kind 兜底）。
  if (state.status === 'next') {
    const next = state.envelope?.nextStep;
    if (next === undefined) {
      // 零值兜底（§9 第 18 条）：status=next 必有 next_step（防御，§1.3 行 110）。
      return <p role="alert">{t('common.refreshAndRetry')}</p>;
    }
    // nextStep.method 零值兜底：空串保持当前方式（与 reducer response 语义一致）。
    const nextMethod = next.method !== '' ? next.method : state.method;
    return (
      <div className={styles.flow}>
        {notice !== undefined && <ErrorBanner i18nKey={notice} />}
        <StepDispatcher
          nextStep={next}
          form={renderFactorNode(nextMethod, next.fields)}
        />
        {selectShowCaptcha(state) &&
          state.envelope?.captcha !== undefined && (
            <CaptchaWidget captcha={state.envelope.captcha} ref={captchaRef} />
          )}
        {resolution !== undefined && (
          <ErrorBanner
            i18nKey={resolution.i18nKey}
            fallbackMessage={error?.message}
            retryAfter={error?.retryAfter}
            retryable={resolution.retryable}
            {...bannerExtras(nextMethod)}
          />
        )}
        {backToMethodsNode}
      </div>
    );
  }

  // 表单区（idle / captcha_required / captcha_invalid / 失败态：表单保留
  // 原地重试，§1.6 可重试语义；不可重试态由 selectSubmitDisabled 禁用提交）。
  const entry =
    state.method === ''
      ? undefined
      : snapshot.methods.find((m) => m.method === state.method);
  // challenge 步渲染目标输入（§2.1 行 390-394 challengeFields）；form 步取 fields。
  const fields = (
    (state.step === 'challenge' ? entry?.challengeFields : entry?.fields) ?? []
  ).map(snapshotFieldToField);

  return (
    <div className={styles.flow}>
      {notice !== undefined && <ErrorBanner i18nKey={notice} />}
      <MethodTabs
        methods={snapshot.methods}
        current={state.method}
        onSelect={onSelect}
        onQrResult={onQrResult}
      />
      {state.method === '' ? (
        <p role="status">{t('login.selectMethodHint')}</p>
      ) : (
        renderFactorNode(state.method, fields)
      )}
      {selectShowCaptcha(state) &&
        state.envelope?.captcha !== undefined && (
          <CaptchaWidget captcha={state.envelope.captcha} ref={captchaRef} />
        )}
      {resolution !== undefined && (
        <ErrorBanner
          i18nKey={resolution.i18nKey}
          fallbackMessage={error?.message}
          retryAfter={error?.retryAfter}
          retryable={resolution.retryable}
          {...bannerExtras(state.method)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 容器（编排壳：dispatch / effects 落地 / 终点跳转）
// ---------------------------------------------------------------------------

export interface LoginContainerProps {
  /** 注入快照（§2.1；由 bootstrap / 页面层读取后传入）。 */
  snapshot: MethodsSnapshot;
  /**
   * 初始信封（OAuth 回调 mfa_required 场景）：LoginOauth 响应直接
   * 进状态机（response 事件语义，挂载即生效）——mfa_required 就地渲染
   * mfa.methods 选择器 + 因子组件（§1.6 行 233「不跳页」），MFA 提交走
   * SsoService/LoginDefault（loginToken 由 api 层 applyEnvelope 托管续接，
   * 页面不自管），success 终点跳转 executeEffects（§4.1 行 383）。
   */
  initialEnvelope?: LoginFlowResponse;
}

export function LoginContainer({
  snapshot,
  initialEnvelope,
}: LoginContainerProps) {
  // 惰性初始化：初始信封经 reducer response 事件进状态机（effects 语义
  // 完整保留——mfa_required / binding_required 无副作用标记）。
  const [state, dispatch] = useReducer(
    flowReducer,
    initialEnvelope,
    (env) =>
      env === undefined
        ? INITIAL_FLOW_STATE
        : flowReducer(INITIAL_FLOW_STATE, { type: 'response', envelope: env }),
  );
  const [notice, setNotice] = useState<string | undefined>(undefined);
  const captchaRef = useRef<CaptchaWidgetHandle>(null);
  // mfa 场景方式列表本地镜像（§4.1 行 407 就地渲染）：select_method 清信封，
  // mfa_required 信封到达时镜像；restart / complete / 传输失败时清空退出 mfa 场景。
  const [mfaMethods, setMfaMethods] = useState<
    readonly MfaMethod[] | undefined
  >(undefined);
  // challenge 段表单值（重发时原目标重用，§4.3 行 436 重发倒计时）：OTPForm
  // 实例随状态分支（表单区 ↔ StepDispatcher form 段）重建，值上提容器。
  const [challengeValues, setChallengeValues] = useState<
    Readonly<Record<string, string>>
  >({});
  // OTP verify 段已输码（同 challengeValues 模式）：invalid_code 等
  // 可重试失败态（§1.6 行 247）在 StepDispatcher next 槽位 ↔ 直渲染位间切换
  // 会重建 OTPForm 实例，本地 state 丢已输码——容器持值受控注入。
  const [otpCode, setOtpCode] = useState('');
  // webauthn 最近一次下发的 options 镜像（容器持值同款）：invalid_
  // credentials 等 failure 态信封无 nextStep，verify 段原地重试（§1.6 行 247）
  // 仍需最近 options 重走浏览器断言；换方式 / restart / 终点时清空。
  const [challengeData, setChallengeData] = useState<JsonObject | undefined>(
    undefined,
  );
  // 最近一次提交的表单值（评审 P1-4：可重试失败态 onRetry 重提）。
  const [lastValues, setLastValues] = useState<
    Readonly<Record<string, string>> | undefined
  >(undefined);

  const submit = async (values: Readonly<Record<string, string>>) => {
    // request_started 先于请求同步派发（loading 立即反映 UI）。
    dispatch({ type: 'request_started', step: state.step });
    if (state.step === 'challenge') {
      setChallengeValues(values);
    }
    setLastValues(values);
    const { events, failed } = await runSubmit(
      state,
      toPayloadInit(
        values,
        fieldsFor(state.method, state.step, snapshot, mfaMethods),
      ),
      () =>
        selectShowCaptcha(state) ? captchaRef.current?.getToken() : undefined,
      loginDefault,
    );
    for (const event of events) {
      dispatch(event);
    }
    if (failed) {
      // 传输层失败：回到第一步（reset 已派发）+ failed 兜底提示（§1.6 行 272）。
      setMfaMethods(undefined);
      setNotice('errors.status.failed');
    }
  };

  // OTP verify 段重发（§1.10 行 306-307 challenge→form 序列重走）：以
  // step=challenge 重发——主因子场景带原目标（§2.6 行 544）、MFA 场景空
  // payload（行 545，目标取 uid 绑定资料）；每次 challenge 均过 captcha 拦截
  // （§2.2 编排规则 4），返回 captcha_required 时由表单区 CaptchaWidget 接力。
  const resend = async () => {
    dispatch({ type: 'request_started', step: 'challenge' });
    const { events, failed } = await runSubmit(
      { ...state, step: 'challenge' },
      toPayloadInit(
        challengeValues,
        fieldsFor(state.method, 'challenge', snapshot, mfaMethods),
      ),
      () =>
        selectShowCaptcha(state) ? captchaRef.current?.getToken() : undefined,
      loginDefault,
    );
    for (const event of events) {
      dispatch(event);
    }
    if (failed) {
      setMfaMethods(undefined);
      setNotice('errors.status.failed');
    }
  };

  // webauthn verify 段断言提交（§2.6 行 548 payload {credential}）：credential
  // 是 Struct JSON 对象、不走表单值通道（toPayloadInit 白名单只收 string 字段，
  // §2.6 行 547 credential 通道），容器直接组装 payload 后走同一 runSubmit 编排。
  const submitCredential = async (credential: JsonObject) => {
    dispatch({ type: 'request_started', step: state.step });
    const payload: PayloadInit = { credential };
    const { events, failed } = await runSubmit(
      state,
      payload,
      () =>
        selectShowCaptcha(state) ? captchaRef.current?.getToken() : undefined,
      loginDefault,
    );
    for (const event of events) {
      dispatch(event);
    }
    if (failed) {
      setMfaMethods(undefined);
      setNotice('errors.status.failed');
    }
  };

  // mfa_required 信封到达 → 本地镜像（§4.1 行 407：select_method 清信封后仍可渲染）。
  useEffect(() => {
    if (state.status === 'mfa_required' && state.envelope?.mfa !== undefined) {
      setMfaMethods(state.envelope.mfa.methods);
    }
  }, [state.status, state.envelope]);

  // next 态信封到达 → 镜像 nextStep.challengeData（§1.3 行 117）：webauthn 的
  // verify 段 options 持值（失败态重试复用）；其余因子该字段为 undefined，
  // 自然清空镜像。
  useEffect(() => {
    if (state.status === 'next' && state.envelope?.nextStep !== undefined) {
      setChallengeData(state.envelope.nextStep.challengeData);
    }
  }, [state.status, state.envelope]);

  // 副作用落地（reducer 标记 → 容器执行；effects 每次迁移重置，不重复执行）。
  useEffect(() => {
    executeEffects(state.effects, {
      complete: (url) => {
        setMfaMethods(undefined);
        setChallengeData(undefined);
        location.replace(url);
      },
      restart: (status) => {
        setMfaMethods(undefined);
        setChallengeData(undefined);
        dispatch({ type: 'reset' });
        setNotice(resolveFlowStatus(status).i18nKey);
      },
    });
  }, [state.effects]);

  // captcha_invalid → reset widget 后重试（§1.6 行 241；权威 captcha 对象
  // 变化时 adapterKey 自动按新对象重建，无需此处处理）。
  useEffect(() => {
    if (state.status === 'captcha_invalid') {
      captchaRef.current?.reset();
    }
  }, [state.status, state.envelope]);

  const onSelect = (method: string) => {
    const entry = snapshot.methods.find((m) => m.method === method);
    dispatch({
      type: 'select_method',
      method,
      firstStep: firstStepFor(entry?.steps ?? []),
    });
    // 换方式 = 全新流程（reducer 语义），一次性提示与 options 镜像随之清空。
    setNotice(undefined);
    setChallengeData(undefined);
  };

  // mfa 方式选择：与主因子切换同款 select_method（reducer「含 mfa 方式切换」
  // 语义）；mfa 场景方式列表在本地镜像中、不查注入快照。
  const onSelectMfa = (method: string, firstStep: string) => {
    dispatch({ type: 'select_method', method, firstStep });
    setNotice(undefined);
    setChallengeData(undefined);
  };

  // 扫码登录结论（§2.8 行 739-743）：内层非 success 信封进状态机
  // 分派（binding_required → 原地 BindingPage；失败态 → 表单区 + ErrorBanner，
  // 图标墙可重新拉码 = 重试）；success / 内层缺失不动作（终点跳转已由
  // QRCodeStep completeLogin 完成）。
  const onQrResult = (outer: LoginFlowResponse) => {
    const event = qrResultEvent(outer);
    if (event !== undefined) {
      dispatch(event);
    }
  };

  // 评审 P0-1：「返回方式列表」= 回第一步（reducer「换方式 = 全新
  // 流程」语义的 reset 落地）；一次性提示与 options 镜像清空，challengeValues /
  // otpCode 持值保留（重选 OTP 方式时回填，P1-5 同款语义）。
  const backToMethods = () => {
    dispatch({ type: 'reset' });
    setMfaMethods(undefined);
    setChallengeData(undefined);
    setNotice(undefined);
  };

  // 评审 P1-4：可重试失败态「重试」= 重提最近一次提交值（captcha
  // 凭据由 submit 内 captchaRef 现取，captcha_invalid 换凭据重提成立）。
  const retrySubmit = () => {
    if (lastValues !== undefined) {
      void submit(lastValues);
    }
  };

  return (
    <LoginFlowView
      snapshot={snapshot}
      state={state}
      notice={notice}
      onSelect={onSelect}
      onSelectMfa={onSelectMfa}
      onSubmit={submit}
      onResend={resend}
      otpCode={otpCode}
      onOtpCodeChange={setOtpCode}
      captchaRef={captchaRef}
      mfaMethods={mfaMethods}
      onCredential={submitCredential}
      challengeData={challengeData}
      onQrResult={onQrResult}
      onBackToMethods={backToMethods}
      onRetry={retrySubmit}
      challengeValues={challengeValues}
    />
  );
}
