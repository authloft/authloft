/**
 * 全新安装页（路径 B，docs/前端架构.md §6b / 接口文档 §13.3）：
 * DB（六字段，../dsn 拼装为单个 dbDsn，wire 契约不变）/ Redis 连接、
 * 主域名与 RP ID（自动读取默认值）、管理员账号密码。
 * 约束（§6b）：密码字段不回显；字段级错误（username_invalid / password_weak 等）
 * 按 §13 映射到字段（db_unreachable 定位到 DSN 字段组提示）；成功
 * （restarting:true）进入重启流程。
 */
import { useState, type FormEvent } from 'react';
import { requestInstall, setupMessage } from '../api';
import {
  buildMysqlDsn,
  validateDbDsnFields,
  type DbDsnFieldError,
  type DbDsnFieldKey,
  type DbDsnFormFields,
} from '../dsn';
import { ApiError } from '../../shared/api/errors';
import { t } from '../../shared/i18n';
import styles from './InstallPage.module.less';

interface InstallPageProps {
  onRestarting: () => void;
}

interface InstallFormState {
  dbHost: string;
  dbPort: string;
  dbUser: string;
  dbPassword: string;
  dbName: string;
  dbParams: string;
  redisAddr: string;
  redisPassword: string;
  redisDb: string;
  root: string;
  rpId: string;
  adminUsername: string;
  adminPassword: string;
}

type InstallField = keyof InstallFormState;

/** §6b：字段级错误按接口文档 §13 映射到字段（root 缺失 / IP / 非法 → config_invalid → 域名字段）。 */
const FIELD_BY_CODE: Readonly<Record<string, InstallField>> = {
  config_invalid: 'root',
  username_invalid: 'adminUsername',
  password_weak: 'adminPassword',
  db_unreachable: 'dbHost',
  redis_unreachable: 'redisAddr',
};

/**
 * 字段级展示文案键覆盖（拆字段后 db_unreachable 指向 DSN 字段组合，
 * 不复用 UploadConfig 的「检查连接串」措辞，其余错误码沿用 setupMessage）。
 */
const FIELD_MESSAGE_KEY_BY_CODE: Readonly<Record<string, string>> = {
  db_unreachable: 'setup.error.dbUnreachableFields',
};

/** dsn.ts 字段键 → 本表单字段键。 */
const DB_FIELD_TO_FORM: Readonly<Record<DbDsnFieldKey, InstallField>> = {
  host: 'dbHost',
  port: 'dbPort',
  user: 'dbUser',
  password: 'dbPassword',
  database: 'dbName',
  params: 'dbParams',
};

/** DB 必填文案按字段区分（params 可选，不会触发 required）。 */
const DB_REQUIRED_KEYS: Readonly<Partial<Record<DbDsnFieldKey, string>>> = {
  host: 'setup.error.dbHostRequired',
  port: 'setup.error.dbPortRequired',
  user: 'setup.error.dbUserRequired',
  password: 'setup.error.dbPasswordRequired',
  database: 'setup.error.dbNameRequired',
};

/** DB 非必填类校验失败 → i18n 键（体验性校验，§9 第 4 条：后端为唯一权威）。 */
const DB_ERROR_KEYS: Readonly<
  Record<Exclude<DbDsnFieldError, 'required'>, string>
> = {
  portInvalid: 'setup.error.dbPortInvalid',
  userColon: 'setup.error.dbUserColon',
  nameInvalid: 'setup.error.dbNameInvalid',
};

/** 表单 DB 六字段 → dsn.ts 校验入参（host/port/user/database/params）。 */
function formToDbDsnFields(form: InstallFormState): DbDsnFormFields {
  return {
    host: form.dbHost,
    port: form.dbPort,
    user: form.dbUser,
    password: form.dbPassword,
    database: form.dbName,
    params: form.dbParams,
  };
}

/**
 * 域名 host 形状（§13.3：域名或 localhost；label 为字母数字连字符，
 * 不以连字符开头 / 结尾）。IP 由 isIpHost 单独判定。
 */
const DOMAIN_HOST_PATTERN =
  /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;

/** host 是否为 IP（§13.3 拒 IP）：v4 点分四段数字；v6 含冒号（hostname 无端口与方括号）。 */
export function isIpHost(host: string): boolean {
  return host.includes(':') || /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

/** root 前置校验失败项（§6b：必填 / 拒 IP / 域名格式），文案键见 ROOT_ERROR_KEYS。 */
export type RootCheckError = 'rootRequired' | 'rootIpRejected' | 'rootInvalid';

/** 校验失败项 → i18n 键（体验性校验，§9 第 4 条：后端为唯一权威）。 */
const ROOT_ERROR_KEYS: Readonly<Record<RootCheckError, string>> = {
  rootRequired: 'setup.error.rootRequired',
  rootIpRejected: 'setup.error.rootIpRejected',
  rootInvalid: 'setup.error.rootInvalid',
};

/**
 * root 前置校验（§6b / §13.3）：必填、完整 URL（http:// 或 https:// 开头）、
 * host 为域名或 localhost（拒 IP v4 / v6）。合法返回 null，非法返回失败项。
 */
export function checkRoot(value: string): RootCheckError | null {
  const trimmed = value.trim();
  if (trimmed === '') {
    return 'rootRequired';
  }
  if (!/^https?:\/\//.test(trimmed)) {
    return 'rootInvalid';
  }
  try {
    const { hostname } = new URL(trimmed);
    if (isIpHost(hostname)) {
      return 'rootIpRejected';
    }
    return DOMAIN_HOST_PATTERN.test(hostname) ? null : 'rootInvalid';
  } catch {
    return 'rootInvalid';
  }
}

/**
 * root 预填（§6b）：仅当 origin 的 host 为域名或 localhost 才回填 origin；
 * host 为 IP（v4 / v6）一律留空。
 */
export function prefillRoot(origin: string): string {
  try {
    const { hostname } = new URL(origin);
    return !isIpHost(hostname) && DOMAIN_HOST_PATTERN.test(hostname)
      ? origin
      : '';
  } catch {
    return '';
  }
}

/**
 * 自动读取默认值（§6b / §13.3）：root 按 §6b 条件预填当前页源（host 为 IP 一律留空），
 * rp_id 取当前 Host 去掉端口；均可显式覆盖。
 */
function initialFormState(): InstallFormState {
  return {
    dbHost: '',
    // MySQL 标准端口预填（与 redisDb 默认 '0' 同款惯例；仍可显式覆盖）。
    dbPort: '3306',
    dbUser: '',
    dbPassword: '',
    dbName: '',
    dbParams: '',
    redisAddr: '',
    redisPassword: '',
    redisDb: '0',
    root: prefillRoot(location.origin),
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

  // §13.3 必填：DB 五项 / redis_addr / admin_username / admin_password
  //（前端仅体验性校验，后端是唯一权威——编码约束 §9 第 4 条）。
  const requiredFilled =
    form.dbHost.trim() !== '' &&
    form.dbPort.trim() !== '' &&
    form.dbUser.trim() !== '' &&
    form.dbPassword !== '' &&
    form.dbName.trim() !== '' &&
    form.redisAddr.trim() !== '' &&
    form.adminUsername.trim() !== '' &&
    form.adminPassword !== '';

  function setField(field: InstallField, value: string): void {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function handleSubmit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setFieldErrors({});
    setFormError(null);
    // §6b 前置体验性校验（后端为唯一权威——编码约束 §9 第 4 条）：
    // root 必填 + 拒 IP + 域名格式；DB 六字段口径（必填 / 端口 1-65535 /
    // 用户名拒 `:` / 库名拒 `?` `/`，见 ../dsn）。失败项合并一次展示。
    const nextErrors: Partial<Record<InstallField, string>> = {};
    const rootError = checkRoot(form.root);
    if (rootError !== null) {
      nextErrors.root = t(ROOT_ERROR_KEYS[rootError]);
    }
    const dbErrors = validateDbDsnFields(formToDbDsnFields(form));
    for (const [field, error] of Object.entries(
      dbErrors,
    ) as Array<[DbDsnFieldKey, DbDsnFieldError]>) {
      nextErrors[DB_FIELD_TO_FORM[field]] =
        error === 'required'
          ? t(DB_REQUIRED_KEYS[field] ?? 'setup.error.unknown')
          : t(DB_ERROR_KEYS[error]);
    }
    if (Object.keys(nextErrors).length > 0) {
      setFieldErrors(nextErrors);
      return;
    }
    setSubmitting(true);
    try {
      await requestInstall({
        // wire 契约不变（§13.3）：六字段拼装为单个 dbDsn 再提交。
        dbDsn: buildMysqlDsn(formToDbDsnFields(form)),
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
        const overrideKey = FIELD_MESSAGE_KEY_BY_CODE[error.code];
        const message = overrideKey
          ? t(overrideKey)
          : setupMessage(error.code);
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
    { key: 'dbHost', label: t('setup.fieldDbHost'), required: true },
    {
      key: 'dbPort',
      label: t('setup.fieldDbPort'),
      type: 'number',
      required: true,
      hint: t('setup.hintDbPort'),
    },
    { key: 'dbUser', label: t('setup.fieldDbUser'), required: true },
    {
      key: 'dbPassword',
      label: t('setup.fieldDbPassword'),
      type: 'password',
      required: true,
    },
    { key: 'dbName', label: t('setup.fieldDbName'), required: true },
    {
      key: 'dbParams',
      label: t('setup.fieldDbParams'),
      hint: t('setup.hintDbParams'),
    },
    { key: 'redisAddr', label: t('setup.fieldRedisAddr'), required: true },
    {
      key: 'redisPassword',
      label: t('setup.fieldRedisPassword'),
      type: 'password',
    },
    {
      key: 'redisDb',
      label: t('setup.fieldRedisDb'),
      type: 'number',
      hint: t('setup.hintRedisDb'),
    },
    {
      key: 'root',
      label: t('setup.fieldRoot'),
      required: true,
      hint: t('setup.hintRoot'),
    },
    { key: 'rpId', label: 'WebAuthn RP ID', hint: t('setup.hintRpId') },
    {
      key: 'adminUsername',
      label: t('setup.fieldAdminUsername'),
      required: true,
    },
    {
      key: 'adminPassword',
      label: t('setup.fieldAdminPassword'),
      type: 'password',
      required: true,
    },
  ];

  return (
    <form className={styles.form} onSubmit={handleSubmit}>
      <h1 className={styles.title}>{t('setup.installTitle')}</h1>
      <p className={styles.intro}>{t('setup.installIntro')}</p>
      {fields.map((field) => (
        <div key={field.key} className={styles.field}>
          <label className={styles.fieldLabel}>
            <span className={styles.labelText}>
              {field.label}
              {field.required ? t('setup.requiredMark') : ''}
            </span>
            <input
              type={field.type ?? 'text'}
              className={styles.input}
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
          {field.hint ? (
            <small className={styles.hint}>{field.hint}</small>
          ) : null}
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
      <button type="submit" className={styles.submit} disabled={!requiredFilled || submitting}>
        {submitting ? t('setup.installing') : t('setup.startInstall')}
      </button>
    </form>
  );
}
