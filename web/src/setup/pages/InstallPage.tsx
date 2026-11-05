/**
 * 全新安装页（路径 B，docs/前端架构.md §6b / 接口文档 §13.3）：
 * DB / Redis 连接、主域名与 RP ID（自动读取默认值）、管理员账号密码。
 * 约束（§6b）：密码字段不回显；字段级错误（username_invalid / password_weak 等）
 * 按 §13 映射到字段；成功（restarting:true）进入重启流程。
 */
import { useState, type FormEvent } from 'react';
import { requestInstall, setupMessage } from '../api';
import { ApiError } from '../../shared/api/errors';
import styles from './InstallPage.module.less';

interface InstallPageProps {
  onRestarting: () => void;
}

interface InstallFormState {
  dbDsn: string;
  redisAddr: string;
  redisPassword: string;
  redisDb: string;
  root: string;
  rpId: string;
  adminUsername: string;
  adminPassword: string;
}

type InstallField = keyof InstallFormState;

/** §6b：字段级错误按接口文档 §13 映射到字段。 */
const FIELD_BY_CODE: Readonly<Record<string, InstallField>> = {
  username_invalid: 'adminUsername',
  password_weak: 'adminPassword',
  db_unreachable: 'dbDsn',
  redis_unreachable: 'redisAddr',
};

/**
 * 自动读取默认值（§6b / §13.3）：root 取当前站点源（缺省后端取请求 Host）、
 * rp_id 取当前 Host 去掉端口；均可显式覆盖。
 */
function initialFormState(): InstallFormState {
  return {
    dbDsn: '',
    redisAddr: '',
    redisPassword: '',
    redisDb: '0',
    root: location.origin,
    rpId: location.hostname,
    adminUsername: '',
    adminPassword: '',
  };
}

export default function InstallPage({ onRestarting }: InstallPageProps) {
  const [form, setForm] = useState<InstallFormState>(initialFormState);
  const [fieldErrors, setFieldErrors] = useState<
    Partial<Record<InstallField, string>>
  >({});
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // §13.3 必填：db_dsn / redis_addr / admin_username / admin_password
  //（前端仅体验性校验，后端是唯一权威——编码约束 §9 第 4 条）。
  const requiredFilled =
    form.dbDsn.trim() !== '' &&
    form.redisAddr.trim() !== '' &&
    form.adminUsername.trim() !== '' &&
    form.adminPassword !== '';

  function setField(field: InstallField, value: string): void {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function handleSubmit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setFieldErrors({});
    setFormError(null);
    try {
      await requestInstall({
        dbDsn: form.dbDsn.trim(),
        redisAddr: form.redisAddr.trim(),
        redisPassword: form.redisPassword,
        redisDb: Number.parseInt(form.redisDb, 10) || 0,
        root: form.root.trim(),
        rpId: form.rpId.trim(),
        adminUsername: form.adminUsername.trim(),
        adminPassword: form.adminPassword,
      });
      // §13.3 ⑤：成功响应 restarting:true，进入与上传配置一致的重启流程。
      onRestarting();
    } catch (error) {
      if (error instanceof ApiError) {
        const message = setupMessage(error.code);
        const field = FIELD_BY_CODE[error.code];
        if (field) {
          setFieldErrors((prev) => ({ ...prev, [field]: message }));
        } else {
          setFormError(message);
        }
      } else {
        setFormError(setupMessage('internal'));
      }
    } finally {
      setSubmitting(false);
    }
  }

  const fields: Array<{
    key: InstallField;
    label: string;
    type?: 'text' | 'password' | 'number';
    required?: boolean;
    hint?: string;
  }> = [
    { key: 'dbDsn', label: '数据库连接串（DSN）', required: true },
    { key: 'redisAddr', label: 'Redis 地址', required: true },
    { key: 'redisPassword', label: 'Redis 密码', type: 'password' },
    { key: 'redisDb', label: 'Redis 库号', type: 'number', hint: '默认 0' },
    { key: 'root', label: '主域名', hint: '默认取当前站点' },
    { key: 'rpId', label: 'WebAuthn RP ID', hint: '默认取当前域名' },
    { key: 'adminUsername', label: '管理员用户名', required: true },
    {
      key: 'adminPassword',
      label: '管理员密码',
      type: 'password',
      required: true,
    },
  ];

  return (
    <form onSubmit={handleSubmit}>
      <h1>全新安装</h1>
      <p>填写数据库与 Redis 连接信息及管理员账号；成功后自动进入重启。</p>
      {fields.map((field) => (
        <div key={field.key} className={styles.field}>
          <label className={styles.fieldLabel}>
            {field.label}
            {field.required ? '（必填）' : ''}
            <input
              type={field.type ?? 'text'}
              value={form[field.key]}
              onChange={(event) => setField(field.key, event.target.value)}
              autoComplete={
                field.key === 'adminUsername'
                  ? 'username'
                  : field.key === 'adminPassword'
                    ? 'new-password'
                    : 'off'
              }
            />
          </label>
          {field.hint ? <small>{field.hint}</small> : null}
          {fieldErrors[field.key] ? (
            <p role="alert" className={styles.fieldError}>
              {fieldErrors[field.key]}
            </p>
          ) : null}
        </div>
      ))}
      {formError ? (
        <p role="alert" className={styles.formError}>
          {formError}
        </p>
      ) : null}
      <button type="submit" disabled={!requiredFilled || submitting}>
        {submitting ? '正在安装…' : '开始安装'}
      </button>
    </form>
  );
}
