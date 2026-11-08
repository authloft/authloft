/**
 * 全新安装页（路径 B，docs/前端架构.md §6b / 接口文档 §13.3）：
 * DB（六字段，../dsn 拼装为单个 dbDsn，wire 契约不变）/ Redis（UI 拆
 * host + port 两栏对齐 DB，提交拼 `host:port` 为单个 redisAddr，
 * 接口字段名不动）、主域名与 RP ID（自动读取默认值）、管理员账号密码。
 * §9 第 13 条 setup 例外：Semi Form 化——label 自动关联 +
 * 必填星号 + onBlur 单字段 / submit 全量校验（trigger="blur"，校验
 * 复用 ../dsn 与 ../wizard 纯函数，语义不变）。
 * 请求层迁移：提交改 ahooks useRequest（manual，按钮 loading 绑
 * hook loading）；错误统一进集中 onError——分派接 ../wizard.classifyInstallError
 * 纯函数（requestOptions 的 classify 注入点，§5.4-#4 样板）：命中 §13 字段
 * 映射的留行内（formApi.setError），其余走 Semi Toast。
 * 约束（§6b）：密码字段不回显；成功（restarting:true）进入重启流程。
 */
import { useEffect, useRef } from 'react';
import { useRequest } from 'ahooks';
import { Button, Form, Typography } from '@douyinfe/semi-ui';
import { requestInstall } from '../api';
import {
  buildMysqlDsn,
  validateDbDsnFields,
  type DbDsnFieldError,
  type DbDsnFieldKey,
  type DbDsnFormFields,
} from '../dsn';
import {
  checkRoot,
  classifyInstallError,
  joinRedisAddr,
  prefillRoot,
  ROOT_ERROR_KEYS,
  validateRedisFields,
  type InstallFormState,
} from '../wizard';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import styles from './InstallPage.module.less';

interface InstallPageProps {
  onRestarting: () => void;
  /** Steps 推进用：提交态上抛给 SetupPage（「执行安装」步 + 锁步骤跳转）。 */
  onSubmittingChange?: (submitting: boolean) => void;
}

/**
 * Semi FormApi 类型未从大包入口转出（§9 第 21 条禁子路径），按本页用到的
 * 方法做结构建模。
 */
interface InstallFormApi {
  setError: (field: keyof InstallFormState, fieldError: string) => void;
}

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

/** Semi 回调 values 为 Record<string, any>：按字段取字符串零值兜底，不做 as 断言。 */
function pickString(
  values: Record<string, unknown>,
  name: keyof InstallFormState,
): string {
  const fieldValue = values[name];
  return typeof fieldValue === 'string' ? fieldValue : '';
}

/**
 * dsn.ts 六字段纯函数接 Semi Form 校验——拿全量 values 跑
 * validateDbDsnFields、只取本字段结果，纯函数语义不变。
 */
function dsnFieldValidator(key: DbDsnFieldKey) {
  return (_value: unknown, values: Record<string, unknown>): string => {
    const error = validateDbDsnFields({
      host: pickString(values, 'dbHost'),
      port: pickString(values, 'dbPort'),
      user: pickString(values, 'dbUser'),
      password: pickString(values, 'dbPassword'),
      database: pickString(values, 'dbName'),
      params: pickString(values, 'dbParams'),
    })[key];
    if (error === undefined) {
      return '';
    }
    return error === 'required'
      ? t(DB_REQUIRED_KEYS[key] ?? 'setup.error.unknown')
      : t(DB_ERROR_KEYS[error]);
  };
}

/** Redis host / port 接 Semi Form（复用 ../wizard.validateRedisFields，语义不变）。 */
function redisFieldValidator(key: 'host' | 'port') {
  return (_value: unknown, values: Record<string, unknown>): string => {
    const error = validateRedisFields(
      pickString(values, 'redisHost'),
      pickString(values, 'redisPort'),
    )[key];
    if (error === undefined) {
      return '';
    }
    if (error === 'portInvalid') {
      // 与 DB 端口同款文案（1-65535 数字口径一致）。
      return t('setup.error.dbPortInvalid');
    }
    return t(
      key === 'host'
        ? 'setup.error.redisHostRequired'
        : 'setup.error.redisPortRequired',
    );
  };
}

/** root 前置校验接 Semi Form（复用 ../wizard.checkRoot，含必填 / 拒 IP / 域名格式）。 */
function rootValidator(value: string): string {
  const error = checkRoot(value);
  return error === null ? '' : t(ROOT_ERROR_KEYS[error]);
}

/** trim 后必填（adminUsername 沿用原 requiredFilled 的 trim 口径）。 */
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
 * rp_id 取当前 Host 去掉端口；均可显式覆盖。Redis 端口预填 6379（与 dbPort
 * 预填 3306 同款惯例，host/port 对齐）。
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
    redisHost: '',
    redisPort: '6379',
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
  // 提交改 ahooks manual + 集中 onError（§5.4-#4 样板）——分派接
  // classifyInstallError（纯函数不动，经 requestOptions classify 注入）：
  // 字段级留行内，其余 Toast；成功经 onSuccess 进入重启流程。
  const { run: installRun, loading: submitting } = useRequest(requestInstall, {
    manual: true,
    onSuccess: () => {
      // §13.3 ⑤：成功响应 restarting:true，进入与上传配置一致的重启流程。
      onRestarting();
    },
    ...requestOptions({
      classify: classifyInstallError,
      // field 由 INSTALL_FIELD_BY_CODE 收敛（取值域即 keyof InstallFormState）。
      onFieldError: (field, message) =>
        formApi.current?.setError(field as keyof InstallFormState, message),
    }),
  });

  // 提交态上抛（Steps current 推进 + 锁步骤跳转），随请求状态联动。
  useEffect(() => {
    onSubmittingChange?.(submitting);
  }, [submitting, onSubmittingChange]);

  // Semi Form 仅在全量校验通过后触发 onSubmit（submit 全量校验；
  // Redis host/port 非法在本层被拦下，不会发请求）。
  function handleSubmit(values: InstallFormState): void {
    installRun({
      // wire 契约不变（§13.3）：DB 六字段拼 dbDsn、Redis host:port 拼 redisAddr。
      dbDsn: buildMysqlDsn(formToDbDsnFields(values)),
      redisAddr: joinRedisAddr(values.redisHost, values.redisPort),
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
          field="redisHost"
          label={{ text: t('setup.fieldRedisHost'), required: true }}
          trigger="blur"
          validator={redisFieldValidator('host')}
          autoComplete="off"
        />
        <Form.Input
          field="redisPort"
          label={{ text: t('setup.fieldRedisPort'), required: true }}
          trigger="blur"
          validator={redisFieldValidator('port')}
          extraText={t('setup.hintRedisPort')}
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
          extraText={t('setup.hintAdminPassword')}
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
