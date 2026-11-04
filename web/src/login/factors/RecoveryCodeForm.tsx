/**
 * 恢复码因子表单（recovery_code；docs/前端架构.md §4.3 行 441）：
 * 普通文本输入（格式 xxxx-xxxx 的最简输入，不做自动格式化），仅二次因子
 * （§1.10 行 310）。字段渲染复用 shared FieldRenderer（fields 以后端下发为准，
 * §1.3 行 126 recovery_code fields=[{name:code,type:text}]）；提交上抛
 * props.onSubmit（容器组装 payload {code}，§2.6 行 550）。
 *
 * 文案：提交按钮在 i18n 字典无键，中文字面量 + 注释声明，扩键归后续 i18n 实现。
 */
import { useState, type FormEvent } from 'react';
import { FieldRenderer } from '../../shared/components';
import type { FactorProps } from './registry';

/** 提交按钮文案（i18n 无键，字面量声明见文件头）。 */
const SUBMIT_TEXT = '登录';

export function RecoveryCodeForm({
  fields,
  loading,
  disabled,
  onSubmit,
}: FactorProps) {
  const [values, setValues] = useState<Record<string, string>>({});

  const onChange = (name: string, value: string) => {
    setValues((prev) => ({ ...prev, [name]: value }));
  };

  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!loading && !disabled) {
      onSubmit(values);
    }
  };

  return (
    <form onSubmit={submit}>
      <FieldRenderer fields={fields} values={values} onChange={onChange} />
      <button type="submit" disabled={loading || disabled}>
        {SUBMIT_TEXT}
      </button>
    </form>
  );
}
