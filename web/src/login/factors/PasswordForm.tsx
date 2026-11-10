/**
 * 密码因子表单（docs/前端架构.md §4.3 行 435）：password 主因子的
 * 专属表单组件。字段渲染以后端下发为准（注入快照 methods[].fields，§2.1 行
 * 384-387：username(text) + password(password)；captcha 字段由容器的
 * captcha 弹窗承接、FieldRenderer 按 §1.11 跳过），复用 shared 的
 * FieldRenderer（§3.3）；CapsLock 提示（§4.3 行 435）；提交把表单值上抛容器，
 * 由容器组装 payload（含 captcha 三元组）后走 login/api.ts 的 loginDefault
 * （§2.2 / §2.6 行 543：{username, password, captcha?}）。
 *
 * 密码强度提示仅注册 / 改密场景（§4.3 行 435），本组件不实现。
 * 文案（i18n 收口）：CapsLock 提示与提交按钮经 shared/i18n 的 t() 消费
 * （login.capsLockOn / login.submit）。
 */
import { useState, type FormEvent, type KeyboardEvent } from 'react';
import { FieldRenderer, Spinner } from '../../shared/components';
import { t } from '../../shared/i18n';
import { focusField, validateFormValues } from '../validate';
import type { FactorProps } from './registry';
import styles from './PasswordForm.module.less';

export function PasswordForm({
  fields,
  loading,
  disabled,
  onSubmit,
}: FactorProps) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [capsLock, setCapsLock] = useState(false);
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

  // CapsLock 检测：键盘事件冒泡到 form 统一判定 getModifierState，
  // keydown / keyup 都刷新（锁定状态可能在任意时刻切换）。
  const trackCapsLock = (e: KeyboardEvent<HTMLElement>) => {
    setCapsLock(e.getModifierState('CapsLock'));
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
    <form
      onKeyDown={trackCapsLock}
      onKeyUp={trackCapsLock}
      onSubmit={submit}
      className={styles.form}
    >
      <FieldRenderer
        fields={fields}
        values={values}
        onChange={onChange}
        errors={errors}
      />
      {capsLock && (
        <p role="status" className={styles.status}>
          {t('login.capsLockOn')}
        </p>
      )}
      <button
        type="submit"
        disabled={loading || disabled}
        className={styles.submit}
      >
        {/* 提交在途的加载视觉（disabled 防重已有，此处只补可见反馈）。 */}
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
