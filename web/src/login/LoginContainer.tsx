/**
 * 登录状态机容器（docs/前端架构.md §4.1 行 383）：消费
 * flow/{machine,reducer,selectors} 与 api.ts——发起请求、处理响应、驱动子组件、
 * 处理终点。
 *
 * - mfa_required **原地渲染**（不跳页、不新开流程，§4.1 行 407）：因子选择器
 *   UI 归后续因子实现，本实现在该分支渲染占位说明 + 状态标注；
 * - 终点（§4.1 行 383）：syncCookieUrl 是后端拼好的多域名同步首跳完整 URL
 *   （§1.3 行 136、§2.9）→ location.replace 它（跳转链由各域页面接力，最终回
 *   redirectTo）；省略时直接 replace(redirectTo)——移动端用 replace 防回退
 *   死循环（§4.2 行 426 RedirectStep 同款语义）；
 * - captcha_required / captcha_invalid **原地插入** CaptchaWidget（shared/captcha）：
 *   运行期响应顶层 captcha 是权威来源（§2.5 行 519），按新 captcha 对象重新渲染、
 *   不刷新页面（adapterKey 重建机制）；
 *   captcha_invalid 时 reset widget 后重试（§1.6 行 241）；
 * - 请求状态复用状态机的 loading（既有机制，不引 useRequest 双状态源；
 *   提交按钮按 loading 禁用，§3.2）；
 * - kind→step 映射归容器层（注入快照 steps 为唯一定义，reducer 只镜像事件
 *   不自造语义）。
 *
 * 文案：占位 / 引导类文案在 i18n 字典无键，中文字面量 + 注释声明，扩键归
 * 后续 i18n 实现。
 */
import {
  useEffect,
  useReducer,
  useRef,
  useState,
  type Ref,
} from 'react';
import { create } from '@bufbuild/protobuf';
import {
  FieldSchema,
  type Field,
  type LoginFlowResponse,
} from '../gen/proto/api/sso/v1/envelope_pb';
import type { CaptchaPayload } from '../gen/proto/api/sso/v1/login_pb';
import { resolveFlowStatus } from '../shared/api/errors';
import { CaptchaWidget, type CaptchaWidgetHandle } from '../shared/captcha/CaptchaWidget';
import { ErrorBanner } from '../shared/components';
import { t } from '../shared/i18n';
import type {
  MethodsSnapshot,
  SnapshotField,
} from '../shared/types/init';
import { loginDefault, type LoginDefaultInput } from './api';
import { lookupFactor } from './factors/registry';
import { MethodTabs, SELECT_HINT } from './MethodTabs';
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
 * form 映射 'verify'（set_password 属注册 / 重置端点，§2.2 行 422）；空 / 未知
 * 兜底 'verify'（§9 第 18 条零值兜底口径）。
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
 * 终点 URL（§4.1 行 383）：syncCookieUrl 非空 → 它（后端拼好的首跳完整 URL，
 * §1.3 行 136）；否则 redirectTo；两者皆空 → ''（无跳转目标，不 replace）。
 */
export function terminalUrl(envelope: LoginFlowResponse): string {
  return envelope.syncCookieUrl !== ''
    ? envelope.syncCookieUrl
    : envelope.redirectTo;
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
    return { events: [{ type: 'response', envelope }], failed: false };
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

/** 占位文案（i18n 无键，字面量声明见文件头）。 */
const MFA_PLACEHOLDER = '多因子登录即将支持';
const BINDING_PLACEHOLDER = '账号绑定流程即将支持';
const NEXT_STEP_PLACEHOLDER = '该步骤类型即将支持';
const POLL_PLACEHOLDER = '扫码流程即将支持';
const GENERIC_FORM_PLACEHOLDER = '该方式由通用表单渲染，即将支持';
/** 缺映射兜底（§4.3 行 434：不许无映射静默回退；与 StepDispatcher 兜底同款文案，§4.2 行 423）。 */
const MISSING_FACTOR_TEXT = '请刷新重试';
/** success 渲染（跳转由 complete 副作用执行）。 */
const REDIRECTING_TEXT = '登录成功，正在跳转…';

export interface LoginFlowViewProps {
  /** 注入快照（§2.1）。 */
  snapshot: MethodsSnapshot;
  /** 状态机状态（FlowState）。 */
  state: FlowState;
  /** restart / 传输失败的一次性提示（i18nKey；选择新方式时清空）。 */
  notice?: string;
  onSelect: (method: string) => void;
  onSubmit: (values: Readonly<Record<string, string>>) => void;
  captchaRef?: Ref<CaptchaWidgetHandle>;
}

/** 状态分支渲染（§4.1 行 386-395 状态机图的视图落地）。 */
export function LoginFlowView({
  snapshot,
  state,
  notice,
  onSelect,
  onSubmit,
  captchaRef,
}: LoginFlowViewProps) {
  // 扫码轮询态（本容器不发起轮询；QRCodeStep / PollStep 归后续实现）。
  if (
    state.status === 'pending' ||
    state.status === 'scanned' ||
    state.status === 'expired'
  ) {
    return <p role="status">{POLL_PLACEHOLDER}</p>;
  }
  if (state.status === 'success') {
    return <p role="status">{REDIRECTING_TEXT}</p>;
  }
  // mfa_required 原地占位（§4.1 行 407：不跳页；选择器 UI 归后续因子实现）。
  if (state.status === 'mfa_required') {
    return (
      <div>
        <p role="status">{t('errors.status.mfa_required')}</p>
        <p>{MFA_PLACEHOLDER}</p>
      </div>
    );
  }
  // binding_required 占位（绑定选择页归后续实现，§4.4）。
  if (state.status === 'binding_required') {
    return (
      <div>
        <p role="status">{t('errors.status.binding_required')}</p>
        <p>{BINDING_PLACEHOLDER}</p>
      </div>
    );
  }
  // status=next → next_step 分派（steps/ 归后续实现，本实现占位）。
  if (state.status === 'next') {
    return (
      <div>
        <p role="status">{t('errors.status.next')}</p>
        <p>{NEXT_STEP_PLACEHOLDER}</p>
      </div>
    );
  }

  // 表单区（idle / captcha_required / captcha_invalid / 失败态：表单保留
  // 原地重试，§1.6 可重试语义；不可重试态由 selectSubmitDisabled 禁用提交）。
  const entry =
    state.method === ''
      ? undefined
      : snapshot.methods.find((m) => m.method === state.method);
  const fields = (entry?.fields ?? []).map(snapshotFieldToField);
  const factor = state.method === '' ? undefined : lookupFactor(state.method);
  // JSX 组件变量须大写开头（小写会被解析为字符串标签）。
  const Factor = factor;
  const resolution = isErrorStatus(state.status)
    ? resolveFlowStatus(state.status)
    : undefined;
  const error = state.envelope?.error;

  return (
    <div>
      {notice !== undefined && <ErrorBanner i18nKey={notice} />}
      <MethodTabs
        methods={snapshot.methods}
        current={state.method}
        onSelect={onSelect}
      />
      {state.method === '' ? (
        <p role="status">{SELECT_HINT}</p>
      ) : Factor === undefined ? (
        <p role="alert">{MISSING_FACTOR_TEXT}</p>
      ) : Factor === null ? (
        <p role="status">{GENERIC_FORM_PLACEHOLDER}</p>
      ) : (
        <Factor
          fields={fields}
          loading={state.loading}
          disabled={selectSubmitDisabled(state)}
          onSubmit={onSubmit}
        />
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
          attemptsLeft={error?.attemptsLeft}
          retryable={resolution.retryable}
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
}

export function LoginContainer({ snapshot }: LoginContainerProps) {
  const [state, dispatch] = useReducer(flowReducer, INITIAL_FLOW_STATE);
  const [notice, setNotice] = useState<string | undefined>(undefined);
  const captchaRef = useRef<CaptchaWidgetHandle>(null);

  const submit = async (values: Readonly<Record<string, string>>) => {
    // request_started 先于请求同步派发（loading 立即反映 UI）。
    dispatch({ type: 'request_started', step: state.step });
    const fields = (snapshot.methods.find((m) => m.method === state.method)
      ?.fields ?? []).map(snapshotFieldToField);
    const { events, failed } = await runSubmit(
      state,
      toPayloadInit(values, fields),
      () =>
        selectShowCaptcha(state) ? captchaRef.current?.getToken() : undefined,
      loginDefault,
    );
    for (const event of events) {
      dispatch(event);
    }
    if (failed) {
      // 传输层失败：回到第一步（reset 已派发）+ failed 兜底提示（§1.6 行 272）。
      setNotice('errors.status.failed');
    }
  };

  // 副作用落地（reducer 标记 → 容器执行；effects 每次迁移重置，不重复执行）。
  useEffect(() => {
    executeEffects(state.effects, {
      complete: (url) => {
        location.replace(url);
      },
      restart: (status) => {
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
    // 换方式 = 全新流程（reducer 语义），一次性提示随之清空。
    setNotice(undefined);
  };

  return (
    <LoginFlowView
      snapshot={snapshot}
      state={state}
      notice={notice}
      onSelect={onSelect}
      onSubmit={submit}
      captchaRef={captchaRef}
    />
  );
}
