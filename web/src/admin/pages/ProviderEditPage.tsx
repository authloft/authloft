/**
 * 提供方新建 / 编辑页（docs/前端架构.md §6 行 516；docs/接口文档.md
 * §5.2 行 1164-1179 / §5.3）——/admin/providers/new 与
 * /admin/providers/{provider_key}/edit。
 *
 * 页面级职责（§6 行 516）：
 * - `type` 下拉从 Registry 的 metas 动态拉取（GetProviderTypes 真调，
 *   后端已实装）；选定后拉 GetProviderSchema 驱动 SchemaForm；
 *   编辑模式 type / provider_key 锁定（§5.3 行 1192 创建后不可改、行 1195
 *   category 由注册表决定只读）；
 * - 保存前校验 provider_key 唯一性（新建模式全量列表预检，失败放行由后端
 *   already_exists 兜底）与字符集（pattern ^[a-z0-9_]+$，validateSchemaValues）；
 * - `icon_url` 手填绝对 URL + ProviderIcon 实时预览（空则占位，
 *   SchemaForm fieldExtra 注入）；
 * - 短信 / 邮件类型（category sms|email）提供「发送测试」（TestProvider
 *   {providerKey, target}——按已保存配置发送，编辑模式才有 key）。
 *
 * 编辑回填：GetProvider → AdminProvider（全站唯一明文凭证出口）→
 * adminProviderToValues；提交体 buildProviderStruct（type 顶层恒带，
 * 后端从提交体取 type 定位注册表）。成功后整页跳回列表。
 *
 * 401 统一跳登录（§6 行 501，列表页同模式）；其余错误走页面错误帧
 * （Semi Banner）/ 写操作失败 Toast 提示（Semi 回归）。渲染壳薄
 * （工具链 blocker）：逻辑全在 ./api 与 schema/schemaLogic（node 可测）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { create, type JsonObject } from '@bufbuild/protobuf';
import { Banner, Button, Input, Select, Spin, Toast, Typography } from '@douyinfe/semi-ui-19';
import { useLocation, useNavigate } from '@modern-js/runtime/router';
import { ProviderIcon } from '../../shared/components/ProviderIcon';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import {
  GetProviderRequestSchema,
  TestProviderRequestSchema,
} from '../../gen/proto/api/admin/v1/provider_pb';
import { GetProviderSchemaRequestSchema } from '../../gen/proto/api/admin/v1/schema_pb';
import {
  adminReturnTo,
  apiErrorText,
  buildListProvidersRequest,
  createProvider,
  getProvider,
  getProviderSchema,
  getProviderTypes,
  isUnauthenticatedError,
  listProviders,
  testProvider,
  updateProvider,
} from '../api';
import { loginUrl } from '../bootstrap';
import { ProviderCallbackHint } from '../components/ProviderCallbackHint';
import { adminNavPath } from '../paths';
import { SchemaForm } from '../schema/SchemaForm';
import {
  adminProviderToValues,
  buildProviderStruct,
  initialCreateValues,
  isProviderKeyTaken,
  validateSchemaValues,
} from '../schema/schemaLogic';
import type { SchemaField } from '../../gen/proto/api/admin/v1/schema_pb';
import styles from './ProviderEditPage.module.less';

/** 表单值形态（schemaLogic 值模型：键 → JSON 值 / json 文本态）。 */
type FormValues = Record<string, unknown>;

/**
 * 提供方新建 / 编辑页。providerKey 缺省 = 新建（type 下拉可选）；
 * 给定 = 编辑（type / provider_key 锁定，回填明文凭证）。
 */
export function ProviderEditPage(props: {
  /** 归一后 al_root（401 跳登录前缀 / 回调地址前缀）。 */
  readonly alRoot: string;
  /** 编辑目标 provider_key；缺省 = 新建。 */
  readonly providerKey?: string;
}): ReactNode {
  const editing = props.providerKey !== undefined;
  // 保存成功跳回列表改 router 导航（HashRouter SPA 内跳）。
  const navigate = useNavigate();

  const typesReq = useRequest(getProviderTypes);
  const providerReq = useRequest(getProvider);
  const schemaReq = useRequest(getProviderSchema);
  const submitReq = useRequest(
    editing
      ? (values: JsonObject) => updateProvider(values)
      : (values: JsonObject) => createProvider(values),
  );
  const testReq = useRequest(testProvider);

  const [type, setType] = useState('');
  const [values, setValues] = useState<FormValues>({});
  const [issues, setIssues] = useState<Record<string, string>>({});
  // 提交失败 / 测试发送成败反馈改走 Semi Toast（原 actionError 就地
  // 文字随 Semi 回归移除）；testFeedback 仅保留本地校验（target 必填）行内提示。
  const [testTarget, setTestTarget] = useState('');
  const [testFeedback, setTestFeedback] = useState<string | null>(null);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），吞掉防 unhandled
    // rejection；错误呈现 / 401 跳转由下方 effect 与错误分支处理。
    typesReq.run().catch(() => {});
    if (!editing) {
      return;
    }
    providerReq
      .run(create(GetProviderRequestSchema, { providerKey: props.providerKey }))
      .then((provider) => {
        if (provider === undefined) {
          return; // 竞态丢弃。
        }
        setType(provider.type);
        return schemaReq
          .run(create(GetProviderSchemaRequestSchema, { type: provider.type }))
          .then((schema) => {
            if (schema !== undefined) {
              setValues(adminProviderToValues(schema.fields, provider));
            }
          });
      })
      .catch(() => {});
    // 挂载期一次性加载（providerKey / editing 由路由层决定，不随渲染变化）。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 401 统一跳登录（§6 行 501；replace：管理面不留回退占位）。
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  useEffect(() => {
    const errors = [
      typesReq.error,
      providerReq.error,
      schemaReq.error,
      submitReq.error,
      testReq.error,
    ];
    if (errors.some((error) => isUnauthenticatedError(error))) {
      window.location.replace(
        loginUrl(props.alRoot, adminReturnTo(location.pathname, location.search)),
      );
    }
  }, [
    typesReq.error,
    providerReq.error,
    schemaReq.error,
    submitReq.error,
    testReq.error,
    props.alRoot,
    location,
  ]);

  /** 新建模式切换 type → 重拉 schema 重置表单（编辑模式下拉锁定）。 */
  function handleTypeChange(next: string): void {
    setType(next);
    setIssues({});
    schemaReq
      .run(create(GetProviderSchemaRequestSchema, { type: next }))
      .then((schema) => {
        if (schema !== undefined) {
          // category 用顶层 category 预填（注册表权威）——
          // applySchemaDefaults 的零值 '' 会被 required + 锁定键死锁。
          setValues(initialCreateValues(schema));
        }
      })
      .catch(() => {});
  }

  function handleChange(key: string, value: unknown): void {
    setValues((prev) => ({ ...prev, [key]: value }));
  }

  /** icon_url 实时预览（§6 行 516：手填绝对 URL，空则占位）。 */
  function iconPreview(field: SchemaField): ReactNode {
    if (field.key !== 'icon_url') {
      return null;
    }
    const icon = typeof values.icon_url === 'string' ? values.icon_url : '';
    return <ProviderIcon icon={icon} alt={t('admin.iconPreviewAlt')} />;
  }

  async function handleSubmit(): Promise<void> {
    const schema = schemaReq.data;
    if (schema === undefined) {
      return;
    }
    const nextIssues = validateSchemaValues(schema.fields, values);
    // provider_key 唯一性预检（仅新建；列表请求失败放行——后端 uk 冲突
    // already_exists 权威兜底）。
    if (!editing && nextIssues.provider_key === undefined) {
      const key = typeof values.provider_key === 'string' ? values.provider_key : '';
      if (key !== '') {
        try {
          const list = await listProviders(buildListProvidersRequest());
          if (isProviderKeyTaken(key, list.items)) {
            nextIssues.provider_key = t('admin.providerKeyTaken');
          }
        } catch {
          // 预检失败不阻塞提交。
        }
      }
    }
    if (Object.keys(nextIssues).length > 0) {
      setIssues(nextIssues);
      return;
    }
    setIssues({});
    // run 失败会 rethrow（状态已入 state），吞掉防 unhandled rejection；
    // 竞态丢弃（undefined）不触发跳转。
    submitReq
      .run(buildProviderStruct(type, schema.fields, values))
      .then((result) => {
        if (result !== undefined) {
          // 列表页路径取 ADMIN_NAV_ROUTES 单一来源（paths.adminNavPath）。
          void navigate(adminNavPath('admin.navProviders'));
        }
      })
      .catch((error) => {
        Toast.error(apiErrorText(error));
      });
  }

  /** 发送测试（§5.2 行 1177 TestProvider {providerKey, target}）。 */
  function handleTest(): void {
    if (testTarget.trim() === '') {
      setTestFeedback(t('admin.testTargetRequired'));
      return;
    }
    setTestFeedback(null);
    testReq
      .run(
        create(TestProviderRequestSchema, {
          providerKey: props.providerKey ?? '',
          target: testTarget.trim(),
        }),
      )
      .then((result) => {
        if (result !== undefined) {
          Toast.success(t('admin.testSent'));
        }
      })
      .catch((error) => {
        Toast.error(apiErrorText(error));
      });
  }

  // —— 错误 / 加载帧（自绘文字换 Semi Banner / Spin）——

  if (editing && providerReq.status === 'error') {
    return (
      <Banner type="danger" fullMode={false} description={t('admin.providerLoadFailed')} />
    );
  }
  if (schemaReq.status === 'error') {
    return (
      <Banner type="danger" fullMode={false} description={t('admin.schemaLoadFailed')} />
    );
  }
  const loading =
    typesReq.status === 'loading' ||
    (editing && (providerReq.data === undefined || schemaReq.data === undefined));
  if (loading) {
    return (
      <div className={styles.stateCenter} role="status">
        <Spin size="large" />
      </div>
    );
  }

  const provider = providerReq.data;
  const schema = schemaReq.data;
  const submitting = submitReq.status === 'loading';
  // category 恒只读（§5.3 行 1195 由注册表决定）；provider_key 编辑锁定
  //（§5.3 行 1192 创建后不可改）。
  const lockedKeys = editing ? ['category', 'provider_key'] : ['category'];
  const canTest =
    editing &&
    schema !== undefined &&
    (schema.category === 'sms' || schema.category === 'email');

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>
        {editing ? t('admin.editProviderTitle') : t('admin.createProviderTitle')}
      </Typography.Title>
      <ProviderCallbackHint
        alRoot={props.alRoot}
        providerKey={provider?.providerKey}
        type={provider?.type}
      />
      {typesReq.status === 'error' ? (
        // 类型清单加载失败自绘文字换 Semi Banner（表单缺类型不可用，页级口径）。
        <Banner
          type="danger"
          fullMode={false}
          className={styles.actionBanner}
          description={t('admin.providerTypesLoadFailed')}
        />
      ) : null}
      <form
        className={styles.form}
        onSubmit={(event) => {
          event.preventDefault();
          handleSubmit().catch(() => {});
        }}
      >
        <div className={styles.typeField}>
          <label className={styles.typeLabel} htmlFor="provider-type">
            {t('admin.providerTypeLabel')}
          </label>
          <Select
            id="provider-type"
            className={styles.typeSelect}
            value={type}
            optionList={typesReq.data?.items.map((item) => ({
              value: item.type,
              label: item.displayName !== '' ? item.displayName : item.type,
            }))}
            onChange={(value) => handleTypeChange(String(value))}
            disabled={editing}
            placeholder={t('admin.selectTypePlaceholder')}
          />
        </div>
        {schema !== undefined ? (
          <SchemaForm
            schema={schema}
            values={values}
            issues={issues}
            lockedKeys={lockedKeys}
            disabled={submitting}
            onChange={handleChange}
            fieldExtra={iconPreview}
          />
        ) : (
          <p role="status" className={styles.typeRequired}>
            {t('admin.providerTypeRequired')}
          </p>
        )}
        <Button
          theme="solid"
          htmlType="submit"
          loading={submitting}
          disabled={schema === undefined || submitting}
        >
          {t('admin.saveAction')}
        </Button>
      </form>
      {canTest ? (
        <section className={styles.testSection}>
          <h4 className={styles.testTitle}>{t('admin.sendTestAction')}</h4>
          <p className={styles.testNote}>{t('admin.testNote')}</p>
          <div className={styles.testRow}>
            <Input
              className={styles.testTarget}
              value={testTarget}
              onChange={(value) => setTestTarget(value)}
              placeholder={
                schema?.category === 'sms' ? t('admin.phoneLabel') : t('admin.emailLabel')
              }
              disabled={testReq.status === 'loading'}
              aria-label={t('admin.testTargetAriaLabel')}
            />
            <Button
              onClick={handleTest}
              loading={testReq.status === 'loading'}
              disabled={testReq.status === 'loading'}
            >
              {t('admin.sendTestAction')}
            </Button>
          </div>
          {testFeedback !== null ? (
            // 仅本地校验（target 必填）行内；发送成败已改走 Toast。
            <p role="status" className={styles.testFeedback}>
              {testFeedback}
            </p>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
