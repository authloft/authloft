/**
 * 全新安装页（路径 B，docs/前端架构.md §6b / 接口文档 §13.3）：
 * DB（六字段，../dsn 拼装为单个 dbDsn，wire 契约不变）/ Redis 连接、
 * 主域名与 RP ID（自动读取默认值）、管理员账号密码。
 * §9 第 13 条 setup 例外：Semi Form 化——label 自动关联 +
 * 必填星号 + onBlur 单字段 / submit 全量校验（trigger="blur"，校验
 * 复用 ../dsn 与 ../wizard 纯函数，语义不变）；安装失败 Banner danger +
 * 「重试安装」（S-4：goose 单条失败可安全重跑，已定稿口径）。
 * 约束（§6b）：密码字段不回显；字段级错误（username_invalid / password_weak
 * 等）按 §13 映射回字段；成功（restarting:true）进入重启流程。
 */
import { useRef, useState } from 'react';
import { Banner, Button, Form, Typography } from '@douyinfe/semi-ui-19';
import { requestInstall, setupMessage, type InstallPayload } from '../api';
import {
  buildMysqlDsn,
  validateDbDsnFields,
  type DbDsnFieldError,
  type DbDsnFieldKey,
  type DbDsnFormFields,
} from '../dsn';
import { checkRoot, prefillRoot, ROOT_ERROR_KEYS } from '../wizard';
import { ApiError } from '../../shared/api/errors';
import { t } from '../../shared/i18n';
import styles from './InstallPage.module.less';

interface InstallPageProps {
  onRestarting: () => void;
  /** S-2：提交态上抛给 SetupPage 推进 Steps「执行安装」步并锁步骤跳转。 */
  onSubmittingChange?: (submitting: boolean) => void;
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

/**
 * Semi FormApi 类型未从大包入口转出（§9 第 21 条禁子路径），按本页用到的
 * 方法做结构建模。
 */
interface InstallFormApi {
  setError: (field: InstallField, fieldError: string) => void;
}

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
 * dsn.ts 六字段纯函数接 Semi Form 校验——拿全量 values 跑
 * validateDbDsnFields、只取本字段结果，纯函数语义不变。
 */
function dsnFieldValidator(key: DbDsnFieldKey) {
  return (_value: unknown, values: Record<string, unknown>): string => {
    // Semi 回调 values 为 Record<string, any>：按字段取字符串零值兜底，不做 as 断言。
    const pick = (name: keyof InstallFormState): string => {
      const fieldValue = values[name];
      return typeof fieldValue === 'string' ? fieldValue : '';
    };
    const error = validateDbDsnFields({
      host: pick('dbHost'),
      port: pick('dbPort'),
      user: pick('dbUser'),
      password: pick('dbPassword'),
      database: pick('dbName'),
      params: pick('dbParams'),
    })[key];
    if (error === undefined) {
      return '';
    }
    return error === 'required'
      ? t(DB_REQUIRED_KEYS[key] ?? 'setup.error.unknown')
      : t(DB_ERROR_KEYS[error]);
  };
}

/** root 前置校验接 Semi Form（复用 ../wizard.checkRoot，含必填 / 拒 IP / 域名格式）。 */
function rootValidator(value: string): string {
  const error = checkRoot(value);
  return error === null ? '' : t(ROOT_ERROR_KEYS[error]);
}

/** trim 后必填（redisAddr / adminUsername 沿用原 requiredFilled 的 trim 口径）。 */
function requiredTrimValidator(messageKey: string) {
  return (value: string): string =>
    value.trim() === '' ? t(messageKey) : '';
}

/** 管理员密码必填：原值判空不 trim（首尾空格可能是真实密码的一部分，同 dsn.ts 口径）。 */
function adminPasswordValidator(value: string): string {
  return value === '' ? t('setup.error.adminPasswordRequired') : '';
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

export default function InstallPage({
  onRestarting,
  onSubmittingChange,
}: InstallPageProps) {
  const formApi = useRef<InstallFormApi | null>(null);
  const [failure, setFailure] = useState<{
    message: string;
    payload: InstallPayload;
  } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function setSubmittingBoth(value: boolean): void {
    setSubmitting(value);
    onSubmittingChange?.(value);
  }

  async function doInstall(payload: InstallPayload): Promise<void> {
    setFailure(null);
    setSubmittingBoth(true);
    try {
      await requestInstall(payload);
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
          formApi.current?.setError(field, message);
        } else {
          // S-4：表单级失败（migration_failed / admin_missing 等专属文案经
          // setupMessage 映射）→ Banner danger +「重试安装」原样重发。
          setFailure({ message, payload });
        }
      } else {
        setFailure({ message: setupMessage('internal'), payload });
      }
    } finally {
      setSubmittingBoth(false);
    }
  }

  // Semi Form 仅在全量校验通过后触发 onSubmit（S-3：submit 全量校验）。
  async function handleSubmit(values: InstallFormState): Promise<void> {
    await doInstall({
      // wire 契约不变（§13.3）：六字段拼装为单个 dbDsn 再提交。
      dbDsn: buildMysqlDsn(formToDbDsnFields(values)),
      redisAddr: (values.redisAddr || '').trim(),
      redisPassword: values.redisPassword,
      redisDb: Number.parseInt(values.redisDb, 10) || 0,
      root: values.root.trim(),
      rpId: values.rpId.trim(),
      adminUsername: values.adminUsername.trim(),
      adminPassword: values.adminPassword,
    });
  }

  return (
    <div className={styles.stack}>
      <Typography.Title heading={3}>{t('setup.installTitle')}</Typography.Title>
      <Typography.Paragraph type="secondary">
        {t('setup.installIntro')}
      </Typography.Paragraph>
      {failure ? (
        <>
          <Banner type="danger" description={failure.message} />
          <Button
            theme="solid"
            block
            disabled={submitting}
            onClick={() => void doInstall(failure.payload)}
          >
            {t('setup.retryInstall')}
          </Button>
        </>
      ) : null}
      <Form
        initValues={initialFormState()}
        getFormApi={(api: InstallFormApi) => {
          formApi.current = api;
        }}
        onSubmit={handleSubmit}
        labelPosition="top"
      >
        <Form.Input
          field="dbHost"
          label={{ text: t('setup.fieldDbHost'), required: true }}
          trigger="blur"
          validator={dsnFieldValidator('host')}
          autoComplete="off"
        />
        <Form.Input
          field="dbPort"
          label={{ text: t('setup.fieldDbPort'), required: true }}
          trigger="blur"
          validator={dsnFieldValidator('port')}
          extraText={t('setup.hintDbPort')}
          autoComplete="off"
        />
        <Form.Input
          field="dbUser"
          label={{ text: t('setup.fieldDbUser'), required: true }}
          trigger="blur"
          validator={dsnFieldValidator('user')}
          autoComplete="off"
        />
        <Form.Input
          field="dbPassword"
          mode="password"
          label={{ text: t('setup.fieldDbPassword'), required: true }}
          trigger="blur"
          validator={dsnFieldValidator('password')}
          autoComplete="off"
        />
        <Form.Input
          field="dbName"
          label={{ text: t('setup.fieldDbName'), required: true }}
          trigger="blur"
          validator={dsnFieldValidator('database')}
          autoComplete="off"
        />
        <Form.Input
          field="dbParams"
          label={t('setup.fieldDbParams')}
          extraText={t('setup.hintDbParams')}
          autoComplete="off"
        />
        <Form.Input
          field="redisAddr"
          label={{ text: t('setup.fieldRedisAddr'), required: true }}
          trigger="blur"
          validator={requiredTrimValidator('setup.error.redisAddrRequired')}
          autoComplete="off"
        />
        <Form.Input
          field="redisPassword"
          mode="password"
          label={t('setup.fieldRedisPassword')}
          autoComplete="off"
        />
        <Form.Input
          field="redisDb"
          label={t('setup.fieldRedisDb')}
          extraText={t('setup.hintRedisDb')}
          autoComplete="off"
        />
        <Form.Input
          field="root"
          label={{ text: t('setup.fieldRoot'), required: true }}
          trigger="blur"
          validator={rootValidator}
          extraText={t('setup.hintRoot')}
          autoComplete="off"
        />
        <Form.Input
          field="rpId"
          label={t('setup.fieldRpId')}
          extraText={t('setup.hintRpId')}
          autoComplete="off"
        />
        <Form.Input
          field="adminUsername"
          label={{ text: t('setup.fieldAdminUsername'), required: true }}
          trigger="blur"
          validator={requiredTrimValidator('setup.error.adminUsernameRequired')}
          autoComplete="username"
        />
        <Form.Input
          field="adminPassword"
          mode="password"
          label={{ text: t('setup.fieldAdminPassword'), required: true }}
          trigger="blur"
          validator={adminPasswordValidator}
          autoComplete="new-password"
        />
        <Button
          htmlType="submit"
          theme="solid"
          block
          loading={submitting}
          disabled={submitting}
        >
          {submitting ? t('setup.installing') : t('setup.startInstall')}
        </Button>
      </Form>
    </div>
  );
}
