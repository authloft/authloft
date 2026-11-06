/**
 * 登录域密码输入字段（评审 P1-3）：注册 / 重置页共用的「密码 + 显隐」
 * 控件——FieldRenderer 的 secret 类型硬编码 autoComplete="off"，不适配注册 /
 * 重置的 new-password 语义，且 shared/** 已另行收口（非本实现目标），
 * 故在 login 域内落地同款能力（显隐按钮文案复用 common.reveal / common.hide）。
 *
 * 自带稳定 id（label htmlFor 关联）与错误槽（aria-invalid + aria-describedby，
 * 与 FieldRenderer 错误槽同款模式，P0-2 前置校验错误落点）。
 */
import { useState } from 'react';
import { t } from '../../shared/i18n';
import styles from './PasswordField.module.less';

export interface PasswordFieldProps {
  /** 控件稳定 id（错误槽派生 `${id}-error`）。 */
  id: string;
  /** 字段名（提交语义 / 测试锚点）。 */
  name: string;
  label: string;
  /** 受控值。 */
  value: string;
  onChange: (value: string) => void;
  /** 错误文案（非空即渲染错误槽并标 aria-invalid）。 */
  error?: string;
  disabled?: boolean;
  /** 缺省 new-password（注册 / 重置场景）。 */
  autoComplete?: string;
}

export function PasswordField({
  id,
  name,
  label,
  value,
  onChange,
  error,
  disabled,
  autoComplete = 'new-password',
}: PasswordFieldProps) {
  // 「显示 / 隐藏」是本地 UI 态，非业务值（FieldRenderer secret 同款口径）。
  const [revealed, setRevealed] = useState(false);
  const errorId = `${id}-error`;
  const hasError = error !== undefined && error !== '';

  return (
    <div className={styles.field}>
      <label className={styles.label} htmlFor={id}>
        {label}
      </label>
      <input
        className={styles.input}
        id={id}
        name={name}
        type={revealed ? 'text' : 'password'}
        value={value}
        autoComplete={autoComplete}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        {...(hasError
          ? { 'aria-invalid': true as const, 'aria-describedby': errorId }
          : {})}
      />
      <button
        type="button"
        className={styles.toggle}
        onClick={() => setRevealed((v) => !v)}
      >
        {revealed ? t('common.hide') : t('common.reveal')}
      </button>
      {hasError && (
        <p id={errorId} className={styles.error}>
          {error}
        </p>
      )}
    </div>
  );
}
