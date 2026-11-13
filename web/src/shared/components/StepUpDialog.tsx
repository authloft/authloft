/**
 * 敏感操作二次验证弹窗（接口文档 §3.8）：调 StartVerification 取可用因子 →
 * 渲染因子表单 → SubmitVerification，成功后把 verificationToken 交回调用方。
 *
 * 零第三方 UI 依赖：窗体由调用方按 domain 注入（account 传
 * `shared/app-ui/Modal`），本组件只拼正文；因子表单复用通用 FieldRenderer，
 * 不复制字段组件（docs/前端架构.md §3.3）。
 *
 * 因子选择：StartVerification 先不带 method 取 `methods[]`，用户选定后再
 * 以该 method 下发挑战令牌；challengeToken / verificationToken 只透传不解析。
 * StartVerification 选定因子时按 §2.5 需要 captcha，弹窗复用人机校验 gate
 * （reactive：裸发命中 captcha_required 才开窗，配置取错误体 details）。
 *
 * 失败不关窗：Submit 失败只更新窗内错误位，表单原地保留可重试；调用方
 * 的 onVerified 抛错同样留在窗内。
 */
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { create, type JsonObject } from '@bufbuild/protobuf';
import {
  FieldSchema,
  type Field,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import type {
  StartVerificationResponse,
  VerificationMethod,
} from '../../gen/proto/api/common/v1/verification_pb';
import { ApiError, resolveCode } from '../api/errors';
import { t } from '../i18n';
import { toDisplay } from '../utils/int';
import { FieldRenderer } from './FieldRenderer';
import type { ModalRenderer } from './modal';

/** 弹窗阶段：取方式 / 选方式 / 填因子 / 取方式失败。 */
export type StepUpPhase = 'loading' | 'select' | 'verify' | 'error';

/** 因子名 → 展示文案（factors.* 字典；缺译回显 method 本身）。 */
export function factorLabel(method: string): string {
  const key = `factors.${method}`;
  const text = t(key);
  return text === key ? method : text;
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
 * 非 code 因子（如 webauthn 的 `{credential}`，§2.6）不得退化成 code 输入：
 * 无能力字段即返回空表单，由视图给出提示。
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
 * 弹窗主按钮可用性（纯函数，静态可测）：在途 / 取方式中禁用；select 阶段
 * 无可用因子、verify 阶段无可渲染字段时同样禁用——不留「点了没反应」的静默态。
 */
export function stepUpOkDisabled(
  phase: StepUpPhase,
  methods: readonly VerificationMethod[],
  fields: readonly Field[],
  busy: boolean,
): boolean {
  if (busy || phase === 'loading') {
    return true;
  }
  if (phase === 'select') {
    return methods.length === 0;
  }
  if (phase === 'verify') {
    return fields.length === 0;
  }
  return false;
}

/** 弹窗正文（纯视图，静态渲染可测各阶段帧）。 */
export interface StepUpDialogViewProps {
  phase: StepUpPhase;
  methods: VerificationMethod[];
  /** 当前选中的 method（select 阶段）。 */
  selectedMethod: string;
  /** verify 阶段的因子字段。 */
  fields: Field[];
  values: Readonly<Record<string, string>>;
  errorText?: string;
  onSelect?: (method: string) => void;
  onChange?: (name: string, value: string) => void;
}

export function StepUpDialogView(props: StepUpDialogViewProps): ReactNode {
  return (
    <>
      <p>{t('account.stepUpHint')}</p>
      {props.errorText !== undefined ? (
        <p role="alert">{props.errorText}</p>
      ) : null}
      {props.phase === 'loading' ? <p>{t('common.loading')}</p> : null}
      {props.phase === 'select' ? (
        props.methods.length === 0 ? (
          <p role="status">{t('account.stepUpNoMethods')}</p>
        ) : (
          <label>
            <span>{t('account.stepUpMethodLabel')}</span>
            <select
              value={props.selectedMethod}
              onChange={(event) => props.onSelect?.(event.target.value)}
            >
              {props.methods.map((method) => (
                <option key={method.method} value={method.method}>
                  {factorLabel(method.method)}
                </option>
              ))}
            </select>
          </label>
        )
      ) : null}
      {props.phase === 'verify' ? (
        props.fields.length === 0 ? (
          <p role="status">{t('login.stepUpFactorUnsupported')}</p>
        ) : (
          <FieldRenderer
            fields={props.fields}
            values={props.values}
            onChange={props.onChange ?? (() => undefined)}
            idPrefix="stepup"
          />
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
   * 取可用因子；method 为空 = 只取 methods[]。调用方负责按其域接入 captcha
   * （account 侧经 shared/captcha 的 gate）；用户取消时返回 undefined。
   */
  start: (method: string) => Promise<StartVerificationResponse | undefined>;
  /** 提交因子载荷，成功返回 verificationToken（空串视为失败响应）。 */
  submit: (
    challengeToken: string,
    method: string,
    payload: JsonObject,
  ) => Promise<string>;
  /** 二次验证通过：参数为不透明 verificationToken；抛错则留在窗内可重试。 */
  onVerified: (verificationToken: string) => void | Promise<void>;
  onCancel: () => void;
}

export function StepUpDialog(props: StepUpDialogProps): ReactNode {
  const { modal, start, submit, onVerified, onCancel } = props;
  const [phase, setPhase] = useState<StepUpPhase>('loading');
  const [methods, setMethods] = useState<VerificationMethod[]>([]);
  const [selectedMethod, setSelectedMethod] = useState('');
  const [activeMethod, setActiveMethod] = useState<
    VerificationMethod | undefined
  >(undefined);
  const [challengeToken, setChallengeToken] = useState('');
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | undefined>(undefined);

  // start 放 ref：取因子的首屏 effect 只随挂载跑一次，调用方即使传内联闭包
  // （每次渲染换新引用）也不会重跑 StartVerification、清掉在途挑战令牌。
  const startRef = useRef(start);
  startRef.current = start;

  const loadMethods = useCallback(async () => {
    setPhase('loading');
    setMessage(undefined);
    setMethods([]);
    setSelectedMethod('');
    setActiveMethod(undefined);
    setChallengeToken('');
    setValues({});
    try {
      const response = await startRef.current('');
      if (response === undefined) {
        setMessage(t('account.stepUpInvalidResponse'));
        setPhase('error');
        return;
      }
      const first = response.methods[0]?.method ?? '';
      setMethods(response.methods);
      setSelectedMethod(first);
      setPhase('select');
    } catch (error) {
      setMessage(stepUpErrorText(error));
      setPhase('error');
    }
  }, []);

  useEffect(() => {
    void loadMethods();
  }, [loadMethods]);

  const begin = useCallback(async () => {
    if (selectedMethod === '') {
      return;
    }
    setBusy(true);
    setMessage(undefined);
    try {
      const response = await startRef.current(selectedMethod);
      if (response === undefined) {
        return;
      }
      if (response.challengeToken === '') {
        setMessage(t('account.stepUpInvalidResponse'));
        return;
      }
      const method = methods.find((item) => item.method === selectedMethod);
      if (method === undefined) {
        setMessage(t('account.stepUpInvalidResponse'));
        return;
      }
      setActiveMethod(method);
      setChallengeToken(response.challengeToken);
      setValues({});
      setPhase('verify');
    } catch (error) {
      setMessage(stepUpErrorText(error));
    } finally {
      setBusy(false);
    }
  }, [methods, selectedMethod]);

  const submitForm = useCallback(async () => {
    if (activeMethod === undefined || challengeToken === '') {
      return;
    }
    const fields = stepUpFields(activeMethod);
    setBusy(true);
    setMessage(undefined);
    try {
      const token = await submit(
        challengeToken,
        activeMethod.method,
        stepUpPayload(fields, values),
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
  }, [activeMethod, challengeToken, onVerified, submit, values]);

  const handleOk = () => {
    if (busy) {
      return;
    }
    if (phase === 'error') {
      void loadMethods();
      return;
    }
    if (phase === 'select') {
      void begin();
      return;
    }
    if (phase === 'verify') {
      void submitForm();
    }
  };

  const okText =
    phase === 'verify'
      ? t('account.stepUpVerifyAction')
      : phase === 'error'
        ? t('common.retry')
        : t('account.stepUpNextAction');
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
          disabled: stepUpOkDisabled(phase, methods, fields, busy),
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
          selectedMethod={selectedMethod}
          fields={fields}
          values={values}
          errorText={message}
          onSelect={(method) => {
            setSelectedMethod(method);
            setMessage(undefined);
          }}
          onChange={(name, value) =>
            setValues((prev) => ({ ...prev, [name]: value }))
          }
        />
      </Modal>
    </>
  );
}
