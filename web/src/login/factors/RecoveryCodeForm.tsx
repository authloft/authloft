/**
 * 恢复码因子表单（recovery_code；docs/前端架构.md §4.3 行 441）：
 * 普通文本输入（格式 xxxx-xxxx 的最简输入，不做自动格式化），仅二次因子
 * （§1.10 行 310）。字段渲染复用 shared FieldRenderer（fields 以后端下发为准，
 * §1.3 行 126 recovery_code fields=[{name:code,type:text}]）；提交上抛
 * props.onSubmit（容器组装 payload {code}，§2.6 行 550）。
 *
 * 文案（i18n 收口）：提交按钮经 shared/i18n 的 t() 消费（login.submit）。
 */
import { useState, type FormEvent } from 'react';
import type { Field } from '../../gen/proto/api/sso/v1/envelope_pb';
import { FieldRenderer, Spinner } from '../../shared/components';
import { t } from '../../shared/i18n';
import { focusField, validateFormValues } from '../validate';
import type { FactorProps } from './registry';
import styles from './RecoveryCodeForm.module.less';

/** 提交拦截结果（recoverySubmitGuard 未过）：错误槽文案 + 首错字段聚焦锚。 */
export interface RecoverySubmitBlock {
  errors: Readonly<Record<string, string>>;
  focusId: string;
}

/**
 * 提交前校验决策（评审 P0-2；纯函数，node 可测）：空恢复码不直提——
 * 返回 undefined = 放行；否则交组件落错误槽 + 聚焦首错字段（`fr-` 前缀与
 * FieldRenderer 缺省 idPrefix 对齐，PasswordForm / FormStep 同款模式）。
 */
export function recoverySubmitGuard(
  fields: Field[],
  values: Readonly<Record<string, string>>,
): RecoverySubmitBlock | undefined {
  const { errors, firstField } = validateFormValues(fields, values);
  return firstField === undefined
    ? undefined
    : { errors, focusId: `fr-${firstField}` };
}

export function RecoveryCodeForm({
  fields,
  loading,
  disabled,
  onSubmit,
}: FactorProps) {
  const [values, setValues] = useState<Record<string, string>>({});
  // 评审 P0-2：前置校验未过的字段级错误（落 FieldRenderer 错误槽）。
  const [errors, setErrors] = useState<Readonly<Record<string, string>>>({});

  const onChange = (name: string, value: string) => {
    setValues((prev) => ({ ...prev, [name]: value }));
    setErrors((prev) => {
      if (prev[name] === undefined) {
        return prev;
      }
      const next = { ...prev };
      delete next[name];
      return next;
    });
  };

  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (loading || disabled) {
      return;
    }
    // 评审 P0-2：空恢复码不直提——前置校验，未过聚焦首错字段。
    const block = recoverySubmitGuard(fields, values);
    if (block !== undefined) {
      setErrors(block.errors);
      focusField(block.focusId);
      return;
    }
    setErrors({});
    onSubmit(values);
  };

  return (
    <form onSubmit={submit} className={styles.form}>
      <FieldRenderer
        fields={fields}
        values={values}
        onChange={onChange}
        errors={errors}
      />
      <button
        type="submit"
        disabled={loading || disabled}
        className={styles.submit}
      >
        {/* 提交在途的加载视觉。 */}
        {loading ? (
          <>
            <Spinner size="sm" /> {t('login.submitting')}
          </>
        ) : (
          t('login.submit')
        )}
      </button>
    </form>
  );
}
