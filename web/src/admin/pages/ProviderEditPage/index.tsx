/**
 * 提供商新建 / 编辑页（docs/前端架构.md §6 行 516；docs/接口文档.md
 * §5.2 行 1164-1179 / §5.3）——/admin/providers/new 与
 * /admin/providers/{provider_key}/edit。
 *
 * 页面级职责（§6 行 516）：
 * - `type` 下拉从 Registry 的 metas 动态拉取；选定后拉 GetProviderSchema
 *   驱动 SchemaForm；编辑模式 type / provider_key 锁定；
 * - 保存前校验 provider_key 唯一性（新建模式全量列表预检，失败放行由后端
 *   already_exists 兜底）与字符集（validateSchemaValues）；
 * - `icon_url` 手填绝对 URL + ProviderIcon 实时预览（空则占位）；
 * - 短信 / 邮件类型（category sms|email）提供「发送测试」。
 *
 * 【Semi Form 化】页壳用 PageLayout；表单整体交给一个 Semi `<Form>`：
 * - 值、label 关联、必填星号、校验文案全部由 Form / Form.* 字段组件托管，
 *   页面不再自持 values / issues / testTarget / testFeedback 等受控 state；
 *   `type` 仅作为请求链驱动量（选型 → 拉 schema）保留为 state；
 * - Form 采用 Row + Col 两栏（类型选择与回调提示并排，SchemaForm 内
 *   每字段 span=12）；区块标题用 Form.Section，折叠用 Semi Collapse
 *   （见 schema/SchemaForm.tsx），不再有手写 section / details；
 * - 校验沿用 schemaLogic.validateSchemaValues 纯函数，接 Form 级
 *   `validator`（提交时一次性跑；trigger="custom" 避免失焦重复触发
 *   provider_key 唯一性预检）。校验失败由 Form 把错误注入对应字段。
 *
 * 编辑回填：GetProvider → AdminProvider（全站唯一明文凭证出口）→
 * adminProviderToValues 作为 Form.initValues；type / schema / provider
 * 变更通过 Form 的 key 重建，值态与错误态一并重置（initValues 只在
 * 挂载时生效）。提交体 buildProviderStruct（type 顶层恒带），
 * 成功后整页跳回列表。
 *
 * 401 统一跳登录（§6 行 501）；其余错误走页面错误帧（Semi Banner）/
 * 写操作失败 Toast。样式（§1.7）：同目录同名 module less。
 */
import { useMemo, useRef, useState, type ReactNode } from 'react';
import { create, type JsonObject } from '@bufbuild/protobuf';
import {
  Banner,
  Button,
  Col,
  Form,
  Row,
  Spin,
  Toast,
  Typography,
} from '@douyinfe/semi-ui';
import { useLocation, useNavigate } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { last } from 'lodash-es';
import { PageLayout } from '@/shared/components/PageLayout';
import { ProviderIcon } from '@/shared/components/ProviderIcon';
import { requestOptions } from '@/shared/hooks/requestOptions';
import { t } from '@/shared/i18n';
import {
  GetProviderRequestSchema,
  TestProviderRequestSchema,
} from '@/gen/proto/api/admin/v1/provider_pb';
import { GetProviderSchemaRequestSchema } from '@/gen/proto/api/admin/v1/schema_pb';
import {
  adminReturnTo,
  buildListProvidersRequest,
  createProvider,
  getProvider,
  getProviderSchema,
  getProviderTypes,
  listProviders,
  testProvider,
  updateProvider,
} from '../../api';
import {
  ProviderCallbackHint,
  showsCallbackHint,
} from '../../components/ProviderCallbackHint';
import { adminNavPath } from '../../paths';
import { SchemaForm } from '../../schema/SchemaForm';
import {
  adminProviderToValues,
  buildProviderStruct,
  initialCreateValues,
  isProviderKeyTaken,
  validateSchemaValues,
} from '../../schema/schemaLogic';
import type { SchemaField } from '@/gen/proto/api/admin/v1/schema_pb';
import styles from './index.module.less';

/** 表单值形态（schemaLogic 值模型：键 → JSON 值 / json 文本态）。 */
type FormValues = Record<string, unknown>;

/**
 * Semi FormApi 类型未从大包入口转出（CODE_GUIDE §2.4 禁子路径），
 * 按本页用到的方法做结构建模（setup/InstallPage 同款口径）。
 */
interface ProviderFormApi {
  getValue: (field: string) => unknown;
  setError: (field: string, message: string) => void;
}

/** 新建 / 编辑共用：providerKey 缺省 = 新建，给定 = 编辑。 */
export function ProviderEditPage(props: {
  /** 归一后 al_root（401 跳登录前缀 / 回调地址前缀）。 */
  alRoot: string;
  /** 编辑目标 provider_key；缺省 = 新建。 */
  providerKey?: string;
}): ReactNode {
  const editing = props.providerKey !== undefined;
  // 保存成功跳回列表改 router 导航（HashRouter SPA 内跳）。
  const navigate = useNavigate();
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  const title = editing
    ? t('admin.editProviderTitle')
    : t('admin.createProviderTitle');
  // Form 托管全部字段值 / 错误；这里只留取测试目标与就地错误所需的 API。
  const formApi = useRef<ProviderFormApi | null>(null);
  // type 不是表单值，而是请求链驱动量：选型或编辑回填后拉 GetProviderSchema。
  const [type, setType] = useState('');

  // 五请求实例（§5 映射）：首取（types / 编辑链 provider → schema）自动，
  // 提交 / 测试 manual + 集中 onError（401 跳登录、其余 Toast），
  // 成功副作用走 onSuccess。
  const typesReq = useRequest(
    getProviderTypes,
    requestOptions({
      toast: false,
      returnTo: () => adminReturnTo(location.pathname, location.search),
    }),
  );
  const providerReq = useRequest(
    () =>
      getProvider(
        create(GetProviderRequestSchema, {
          providerKey: props.providerKey ?? '',
        }),
      ),
    {
      ready: editing,
      onSuccess: (provider) => {
        // type 落地即驱动下方 schema 自动请求（refreshDeps）。
        setType(provider.type);
      },
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );
  const schemaReq = useRequest(
    () => getProviderSchema(create(GetProviderSchemaRequestSchema, { type })),
    {
      ready: type !== '',
      refreshDeps: [type],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );
  const submitReq = useRequest(
    editing
      ? (values: JsonObject) => updateProvider(values)
      : (values: JsonObject) => createProvider(values),
    {
      manual: true,
      onSuccess: () => {
        void navigate(adminNavPath('admin.navProviders'));
      },
      ...requestOptions({
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );
  const testReq = useRequest(testProvider, {
    manual: true,
    onSuccess: () => {
      Toast.success(t('admin.testSent'));
    },
    ...requestOptions({
      returnTo: () => adminReturnTo(location.pathname, location.search),
    }),
  });

  const treeData = useMemo(() => {
    const items = typesReq.data?.items || [];
    if (items.length === 0) {
      return [];
    }
    const categories = [...new Set(items.map((x) => x.category))];
    return categories.map((x) => ({
      label: x,
      value: x,
      children: items
        .filter((y) => y.category === x)
        .map((y) => ({ label: y.displayName, value: y.type })),
    }));
  }, [typesReq.data]);
  const treeValue = useMemo(() => {
    if (!type) {
      return undefined;
    }
    const items = typesReq.data?.items || [];
    if (items.length === 0) {
      return [];
    }
    return [items.find((x) => x.type === type)?.category || '', type];
  }, [typesReq.data, type]);

  // 切型期间 ahooks 会短暂保留上一次 schema：只接受与当前 type 一致的响应，
  // 避免用旧类型的字段渲染 / 校验新类型。
  const schema =
    schemaReq.data !== undefined && schemaReq.data.type === type
      ? schemaReq.data
      : undefined;
  const provider = providerReq.data;

  // Form.initValues（编辑回填 / 新建默认值）+ 两个非 schema 字段。
  // Cascader 的值形态是 [category, type] 路径，同样交 Form 托管。
  const initValues = useMemo<FormValues>(() => {
    const fieldValues: Record<string, unknown> =
      schema === undefined
        ? {}
        : editing && provider !== undefined
          ? adminProviderToValues(schema.fields, provider)
          : initialCreateValues(schema);
    return {
      ...fieldValues,
      providerTypePath: treeValue ?? [],
      testTarget: '',
    };
  }, [schema, provider, editing, treeValue]);

  // initValues 只在 Form 挂载时生效：type / schema / 编辑回填落地时重建
  // Form，顺带清掉上一类型的字段值与校验错误（不用自持 issues state）。
  const formKey = `${type}:${schema?.type ?? ''}:${provider?.providerKey ?? ''}`;

  /** 新建模式切换 type → 自动重拉 schema（编辑模式下拉锁定）。 */
  function handleTypeChange(value: unknown): void {
    const path = Array.isArray(value) ? (value as string[]) : [];
    setType(last(path) ?? '');
  }

  /** icon_url 实时预览（§6 行 516：手填绝对 URL，空则占位）。 */
  function iconPreview(field: SchemaField, values: FormValues): ReactNode {
    if (field.key !== 'icon_url') {
      return null;
    }
    const icon = typeof values.icon_url === 'string' ? values.icon_url : '';
    return <ProviderIcon icon={icon} alt={t('admin.iconPreviewAlt')} />;
  }

  /**
   * Form 级校验（替代原 issues state）：复用 schemaLogic 纯函数，
   * provider_key 唯一性预检失败放行（后端 already_exists 权威兜底）。
   * 返回空串 = 通过；返回 { field: 文案 } = 由 Form 注入对应字段。
   */
  async function validateProvider(
    values: FormValues,
  ): Promise<string | Record<string, string>> {
    if (schema === undefined) {
      return { providerTypePath: t('admin.providerTypeRequired') };
    }
    const issues = validateSchemaValues(schema.fields, values);
    if (!editing && issues.provider_key === undefined) {
      const key =
        typeof values.provider_key === 'string' ? values.provider_key : '';
      if (key !== '') {
        try {
          const list = await listProviders(buildListProvidersRequest());
          if (isProviderKeyTaken(key, list.items)) {
            issues.provider_key = t('admin.providerKeyTaken');
          }
        } catch {
          // 预检失败不阻塞提交。
        }
      }
    }
    return Object.keys(issues).length > 0 ? issues : '';
  }

  /** 校验通过才触发（Semi Form.submit）：成功跳列表走 submitReq.onSuccess。 */
  function handleSubmit(values: FormValues): void {
    if (schema === undefined) {
      return;
    }
    submitReq.run(buildProviderStruct(type, schema.fields, values));
  }

  /** 发送测试（§5.2 行 1177 TestProvider {providerKey, target}）。 */
  function handleTest(): void {
    const api = formApi.current;
    if (api === null) {
      return;
    }
    const raw = api.getValue('testTarget');
    const target = typeof raw === 'string' ? raw.trim() : '';
    if (target === '') {
      // 本地必填校验落 Form 行内错误（发送成败走 Toast）。
      api.setError('testTarget', t('admin.testTargetRequired'));
      return;
    }
    api.setError('testTarget', '');
    testReq.run(
      create(TestProviderRequestSchema, {
        providerKey: props.providerKey ?? '',
        target,
      }),
    );
  }

  // —— 错误 / 加载帧（PageLayout 统一页壳）——

  if (editing && providerReq.error !== undefined) {
    return (
      <PageLayout title={title}>
        <Banner
          type="danger"
          fullMode={false}
          description={t('admin.providerLoadFailed')}
        />
      </PageLayout>
    );
  }
  if (schemaReq.error !== undefined) {
    return (
      <PageLayout title={title}>
        <Banner
          type="danger"
          fullMode={false}
          description={t('admin.schemaLoadFailed')}
        />
      </PageLayout>
    );
  }
  const loading =
    typesReq.loading ||
    (editing && (provider === undefined || schema === undefined));
  if (loading) {
    return (
      <PageLayout title={title}>
        <div className={styles.stateCenter} role="status">
          <Spin size="large" />
        </div>
      </PageLayout>
    );
  }

  const submitting = submitReq.loading;
  // category 恒只读（§5.3 行 1195）；provider_key 编辑锁定（行 1192）。
  const lockedKeys = editing ? ['category', 'provider_key'] : ['category'];
  const canTest =
    editing &&
    schema !== undefined &&
    (schema.category === 'sms' || schema.category === 'email');

  return (
    <PageLayout title={title}>
      {typesReq.error !== undefined ? (
        <Banner
          type="danger"
          fullMode={false}
          className={styles.actionBanner}
          description={t('admin.providerTypesLoadFailed')}
        />
      ) : null}
      <Form
        key={formKey}
        className={styles.form}
        getFormApi={(api: ProviderFormApi) => {
          formApi.current = api;
        }}
        initValues={initValues}
        validator={validateProvider}
        onSubmit={handleSubmit}
        trigger="custom"
        labelPosition="top"
      >
        {({ values }: { values: FormValues }) => (
          <>
            <Row gutter={16}>
              <Col span={12} xs={24} sm={24} md={12}>
                <Form.Cascader
                  field="providerTypePath"
                  label={{ text: t('admin.providerTypeLabel'), required: true }}
                  treeData={treeData}
                  onChange={handleTypeChange}
                  disabled={editing}
                  placeholder={t('admin.selectTypePlaceholder')}
                />
              </Col>
              <Col span={12} xs={24} sm={24} md={12}>
                {showsCallbackHint(schema?.category) ? (
                  <div className={styles.callbackHint}>
                    <ProviderCallbackHint
                      alRoot={props.alRoot}
                      providerKey={
                        typeof values.provider_key === 'string' &&
                        values.provider_key !== ''
                          ? values.provider_key
                          : undefined
                      }
                      type={type}
                    />
                  </div>
                ) : null}
              </Col>
            </Row>
            {schema !== undefined ? (
              <SchemaForm
                schema={schema}
                lockedKeys={lockedKeys}
                disabled={submitting}
                fieldExtra={(field) => iconPreview(field, values)}
              />
            ) : type !== '' && schemaReq.loading ? (
              // 切型重拉 schema 期间不闪「请先选择类型」。
              <div className={styles.stateCenter} role="status">
                <Spin />
              </div>
            ) : (
              <Typography.Text type="tertiary" className={styles.typeRequired}>
                {t('admin.providerTypeRequired')}
              </Typography.Text>
            )}
            <div className={styles.actions}>
              <Button
                theme="solid"
                htmlType="submit"
                loading={submitting}
                disabled={schema === undefined || submitting}
              >
                {t('admin.saveAction')}
              </Button>
            </div>
            {canTest ? (
              <>
                <Form.Section text={t('admin.sendTestAction')} />
                <Row gutter={16}>
                  <Col span={12} xs={24} sm={24} md={12}>
                    <Form.Input
                      field="testTarget"
                      label={{
                        text: t('admin.testTargetAriaLabel'),
                        required: true,
                      }}
                      helpText={t('admin.testNote')}
                      placeholder={
                        schema?.category === 'sms'
                          ? t('admin.phoneLabel')
                          : t('admin.emailLabel')
                      }
                      disabled={testReq.loading}
                      aria-label={t('admin.testTargetAriaLabel')}
                      allowEmptyString
                    />
                  </Col>
                  <Col span={12} xs={24} sm={24} md={12}>
                    <Button
                      className={styles.testButton}
                      htmlType="button"
                      onClick={handleTest}
                      loading={testReq.loading}
                      disabled={testReq.loading}
                    >
                      {t('admin.sendTestAction')}
                    </Button>
                  </Col>
                </Row>
              </>
            ) : null}
          </>
        )}
      </Form>
    </PageLayout>
  );
}
