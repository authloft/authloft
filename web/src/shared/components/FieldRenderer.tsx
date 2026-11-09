/**
 * 通用字段渲染器（docs/前端架构.md §3.3 行 322）：只吃后端下发的 fields[]
 * （api.sso.v1.Field 生成物，接口文档 §1.3 行 114 / §2.2 注入快照），按
 * §1.11 行 318-335 的 12 种 type 分派渲染；禁止在组件内硬编码任何业务字段；
 * 未知 type 走兜底渲染（单行文本）。
 *
 * 受控组件：值由调用方以 values 注入、经 onChange(name, value) 上抛，
 * 组件不持有业务状态（secret 的「显示 / 隐藏」是本地 UI 态，非业务值）。
 * 分派逻辑抽为纯函数 controlKindFor / codeLengthOf（node 环境测试覆盖）。
 */
import { useState, type ReactNode } from 'react';
import type { Field } from '../../gen/proto/api/sso/v1/envelope_pb';
import { toCount } from '../utils/int';
import { t } from '../i18n';
import { CodeInput, DEFAULT_CODE_LENGTH } from './CodeInput';
import styles from './FieldRenderer.module.less';

/** §1.11 的 12 种 type + 未知兜底 → 渲染控件形态。 */
export type ControlKind =
  | 'text'
  | 'password'
  | 'tel'
  | 'email'
  | 'code'
  | 'checkbox'
  | 'select'
  | 'secret'
  | 'json'
  | 'number'
  /** captcha：由 CaptchaWidget 承接，不走通用输入渲染（§1.11）。 */
  | 'skip';

/** type → 控件形态分派（§1.11 全表；未知 type 兜底单行文本）。 */
export function controlKindFor(type: string): ControlKind {
  switch (type) {
    case 'text':
      return 'text';
    case 'password':
      return 'password';
    case 'phone':
      return 'tel';
    case 'email':
      return 'email';
    case 'otp':
    case 'totp':
      return 'code';
    case 'checkbox':
      return 'checkbox';
    case 'select':
      return 'select';
    case 'captcha':
      return 'skip';
    case 'secret':
      return 'secret';
    case 'json':
      return 'json';
    case 'number':
      return 'number';
    default:
      return 'text';
  }
}

/**
 * 验证码分段数：field.length（生成消息 int64，bigint）经 utils/int 的
 * toCount 归一为 number（§1.12：禁止 Number(x) 直转）；缺省 / 零值 /
 * 超界异常 → 默认 6（体验参数，与 useCountdown 的 countdownSeconds 同款
 * try/catch 兜底口径）。
 */
export function codeLengthOf(field: Field): number {
  const raw = field.length ?? BigInt(0);
  if (raw <= BigInt(0)) {
    return DEFAULT_CODE_LENGTH;
  }
  try {
    return toCount(raw);
  } catch {
    return DEFAULT_CODE_LENGTH;
  }
}

export interface FieldRendererProps {
  /** 后端下发的字段集合（NextStep.fields / MfaMethod.fields / 注入快照）。 */
  fields: Field[];
  /** 表单值（字段名 → 字符串；checkbox 用 'true' / 'false'，number 按字符串回传 §1.12）。 */
  values: Readonly<Record<string, string>>;
  /** 字段值变化上抛（组件不持有业务状态）。 */
  onChange: (name: string, value: string) => void;
  /** 字段级错误文案（字段名 → 已解析的最终展示文案；评审 P1-2：命中即渲染错误槽并标 aria-invalid + aria-describedby 关联）。 */
  errors?: Readonly<Record<string, string>>;
  /** 控件 id 前缀（默认 'fr'；同页多个实例并存时调用方传不同前缀避免撞 id）。 */
  idPrefix?: string;
}

/** 按 fields[] 渲染表单控件；空数组渲染空（不产生任何 DOM）。 */
export function FieldRenderer({
  fields,
  values,
  onChange,
  errors,
  idPrefix = 'fr',
}: FieldRendererProps) {
  return (
    <>
      {fields.map((field) => (
        <FieldControl
          key={field.name}
          field={field}
          value={values[field.name] ?? ''}
          error={errors?.[field.name]}
          idPrefix={idPrefix}
          onChange={onChange}
        />
      ))}
    </>
  );
}

function FieldControl({
  field,
  value,
  error,
  idPrefix,
  onChange,
}: {
  field: Field;
  value: string;
  error: string | undefined;
  idPrefix: string;
  onChange: (name: string, value: string) => void;
}) {
  const kind = controlKindFor(field.type);
  const [revealed, setRevealed] = useState(false);

  if (kind === 'skip') {
    // §1.11：captcha 由 CaptchaWidget 承接（独立卡），本渲染器跳过。
    return null;
  }

  // 评审 P0-3：稳定 id（label htmlFor 关联）+ 错误时 aria-invalid /
  // aria-describedby 绑到错误槽。
  const inputId = `${idPrefix}-${field.name}`;
  const errorId = `${inputId}-error`;
  const hasError = error !== undefined && error !== '';
  const invalidProps = hasError
    ? { 'aria-invalid': true as const, 'aria-describedby': errorId }
    : {};

  const emit = (v: string) => onChange(field.name, v);
  const input = (type: string, extra: Record<string, unknown> = {}) => (
    <input
      className={styles.input}
      id={inputId}
      name={field.name}
      type={type}
      value={value}
      onChange={(e) => emit(e.target.value)}
      {...invalidProps}
      {...extra}
    />
  );

  let control: ReactNode;
  switch (kind) {
    case 'password':
      control = input('password');
      break;
    case 'tel':
      control = input('tel', { inputMode: 'tel' });
      break;
    case 'email':
      control = input('email', { inputMode: 'email' });
      break;
    case 'number':
      // §1.12：数字提交时按字符串回传；不用 type=number（浏览器会规范化
      // 前导零 / 科学计数），inputMode 提供数字键盘体验。
      control = input('text', { inputMode: 'decimal' });
      break;
    case 'code':
      control = (
        <CodeInput
          value={value}
          onChange={emit}
          length={codeLengthOf(field)}
          ariaLabel={field.label}
          id={inputId}
          ariaInvalid={hasError}
          ariaDescribedBy={hasError ? errorId : undefined}
        />
      );
      break;
    case 'checkbox':
      control = (
        <input
          className={styles.checkbox}
          id={inputId}
          name={field.name}
          type="checkbox"
          checked={value === 'true'}
          onChange={(e) => emit(String(e.target.checked))}
          {...invalidProps}
        />
      );
      break;
    case 'select':
      // §1.11：select 的 options 由后端下发；api.sso.v1.Field 不携带 options
      // 字段（wire 上无此字段，见 envelope.proto），故仅渲染占位项，不自造选项。
      control = (
        <select
          className={styles.input}
          id={inputId}
          name={field.name}
          value={value}
          onChange={(e) => emit(e.target.value)}
          {...invalidProps}
        >
          <option value="">{t('common.selectPlaceholder')}</option>
        </select>
      );
      break;
    case 'secret':
      control = (
        <>
          {input(revealed ? 'text' : 'password', { autoComplete: 'off' })}
          <button
            type="button"
            className={styles.inlineButton}
            onClick={() => setRevealed((v) => !v)}
          >
            {revealed ? t('common.hide') : t('common.reveal')}
          </button>
        </>
      );
      break;
    case 'json':
      control = (
        <textarea
          className={styles.textarea}
          id={inputId}
          name={field.name}
          rows={6}
          spellCheck={false}
          value={value}
          onChange={(e) => emit(e.target.value)}
          {...invalidProps}
        />
      );
      break;
    default:
      control = input('text');
      break;
  }

  return (
    <div className={styles.field}>
      <label className={styles.label} htmlFor={inputId}>
        {field.label}
        {field.required ? ' *' : ''}
      </label>
      {control}
      {hasError && (
        <p id={errorId} className={styles.fieldError}>
          {error}
        </p>
      )}
    </div>
  );
}
