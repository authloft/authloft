/**
 * 通用表单步骤（kind=form；docs/前端架构.md §4.2 行 424）：
 * 渲染后端下发 fields[] → shared FieldRenderer（§1.11 的 12 种 type 分派），
 * 受控收集表单值，提交上抛 props 注入的回调（容器组装 payload——字段名与
 * 请求体字段一致，§1.3 行 114）。
 *
 * totp 显式映射 null 的渲染落点（registry 语义，§4.3 行 434「totp 由通用
 * FormStep 渲染」）：无专属因子组件的方式与 StepDispatcher 的 form 分派都由
 * 本组件渲染。props 形状与 factors 的 FactorProps 一致（注册 / 重置页可直接
 * 复用，场景差异经 onSubmit 注入）。
 *
 * 文案：提交按钮经 i18n 字典 login.submit 键取用（复用既有键）。
 */
import { useState, type FormEvent } from 'react';
import type { Field } from '../../gen/proto/api/sso/v1/envelope_pb';
import { FieldRenderer, Spinner } from '../../shared/components';
import { t } from '../../shared/i18n';
import { focusField, validateFormValues } from '../validate';
import styles from './FormStep.module.less';

export interface FormStepProps {
  /** form 步的后端下发字段（§1.3 行 114 fields[]；captcha 字段被 FieldRenderer 跳过，§1.11）。 */
  fields: readonly Field[];
  /** 请求在途（提交按钮禁用，§3.2）。 */
  loading: boolean;
  /** 不可重试失败态禁用提交（selectors.selectSubmitDisabled，§1.6「可重试」列）。 */
  disabled: boolean;
  /** 提交：表单值上抛，由容器组装 payload（含 captcha）。 */
  onSubmit: (values: Readonly<Record<string, string>>) => void;
}

export function FormStep({
  fields,
  loading,
  disabled,
  onSubmit,
}: FormStepProps) {
  const [values, setValues] = useState<Record<string, string>>({});
  // 评审 P0-2：前置校验未过的字段级错误（字段名 → 文案，落 FieldRenderer 错误槽）。
  const [errors, setErrors] = useState<Readonly<Record<string, string>>>({});

  const onChange = (name: string, value: string) => {
    setValues((prev) => ({ ...prev, [name]: value }));
    // 编辑即清该字段错误（提交前再整表校验）。
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
    // 评审 P0-2：提交前统一前置校验，未过聚焦首错字段、不发请求。
    const { errors: issues, firstField } = validateFormValues(fields, values);
    if (firstField !== undefined) {
      setErrors(issues);
      focusField(`fr-${firstField}`);
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
