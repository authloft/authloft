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
 * 401 统一跳登录（§6 行 501，列表页同模式）；其余错误走页面错误帧 /
 * actionError 就地展示。渲染壳薄（工具链 blocker）：逻辑全在 ./api 与
 * schema/schemaLogic（node 可测）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { create, type JsonObject } from '@bufbuild/protobuf';
import { Button, Input, Select, Typography } from '@douyinfe/semi-ui-19';
import { ProviderIcon } from '../../shared/components/ProviderIcon';
import { useRequest } from '../../shared/hooks/useRequest';
import {
  GetProviderRequestSchema,
  TestProviderRequestSchema,
} from '../../gen/proto/api/admin/v1/provider_pb';
import { GetProviderSchemaRequestSchema } from '../../gen/proto/api/admin/v1/schema_pb';
import {
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

/** 列表页地址（保存成功后整页跳回，刷新列表数据）。 */
const PROVIDERS_LIST_PATH = '/admin/providers';

/** 表单值形态（schemaLogic 值模型：键 → JSON 值 / json 文本态）。 */
type FormValues = Record<string, unknown>;

/** provider_key 唯一性预检冲突文案（前端架构 §6 行 516；后端权威兜底）。 */
const KEY_TAKEN_TEXT = '唯一标识已被占用，请换一个';

/** type 未选定提示（新建模式）。 */
const TYPE_REQUIRED_TEXT = '请先选择提供方类型';

/** 测试目标未填提示。 */
const TEST_TARGET_REQUIRED_TEXT = '请输入测试接收目标';

/** 测试成功反馈（OkResponse 空应答 → 只提示已发送）。 */
const TEST_SENT_TEXT = '已发送，请查收';

/** 测试区说明（TestProvider 按已保存配置现构发送，不经 60s 缓存）。 */
const TEST_NOTE_TEXT = '使用已保存的配置发送一条测试消息';

/** icon_url 预览无障碍标签。 */
const ICON_PREVIEW_ALT = '图标预览';

/** type 下拉数据源加载失败提示（新建模式阻塞选择；编辑模式 type 锁定不阻塞）。 */
const TYPES_LOAD_ERROR_TEXT = '提供方类型列表加载失败，请刷新重试';

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
  const [actionError, setActionError] = useState<string | null>(null);
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
  useEffect(() => {
    const errors = [
      typesReq.error,
      providerReq.error,
      schemaReq.error,
      submitReq.error,
      testReq.error,
    ];
    if (errors.some((error) => isUnauthenticatedError(error))) {
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [
    typesReq.error,
    providerReq.error,
    schemaReq.error,
    submitReq.error,
    testReq.error,
    props.alRoot,
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
    return <ProviderIcon icon={icon} alt={ICON_PREVIEW_ALT} />;
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
            nextIssues.provider_key = KEY_TAKEN_TEXT;
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
    setActionError(null);
    // run 失败会 rethrow（状态已入 state），吞掉防 unhandled rejection；
    // 竞态丢弃（undefined）不触发跳转。
    submitReq
      .run(buildProviderStruct(type, schema.fields, values))
      .then((result) => {
        if (result !== undefined) {
          window.location.assign(PROVIDERS_LIST_PATH);
        }
      })
      .catch((error) => {
        setActionError(apiErrorText(error));
      });
  }

  /** 发送测试（§5.2 行 1177 TestProvider {providerKey, target}）。 */
  function handleTest(): void {
    if (testTarget.trim() === '') {
      setTestFeedback(TEST_TARGET_REQUIRED_TEXT);
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
          setTestFeedback(TEST_SENT_TEXT);
        }
      })
      .catch((error) => {
        setTestFeedback(apiErrorText(error));
      });
  }

  // —— 错误 / 加载帧 ——

  if (editing && providerReq.status === 'error') {
    return (
      <p role="alert" className={styles.loadError}>
        提供方加载失败，请刷新重试
      </p>
    );
  }
  if (schemaReq.status === 'error') {
    return (
      <p role="alert" className={styles.loadError}>
        表单结构加载失败，请刷新重试
      </p>
    );
  }
  const loading =
    typesReq.status === 'loading' ||
    (editing && (providerReq.data === undefined || schemaReq.data === undefined));
  if (loading) {
    return (
      <p role="status" className={styles.loading}>
        加载中…
      </p>
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
        {editing ? '编辑提供方' : '新建提供方'}
      </Typography.Title>
      <ProviderCallbackHint
        alRoot={props.alRoot}
        providerKey={provider?.providerKey}
        type={provider?.type}
      />
      {actionError !== null ? (
        <p role="alert" className={styles.actionError}>
          {actionError}
        </p>
      ) : null}
      {typesReq.status === 'error' ? (
        <p role="alert" className={styles.actionError}>
          {TYPES_LOAD_ERROR_TEXT}
        </p>
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
            类型
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
            placeholder="请选择类型"
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
            {TYPE_REQUIRED_TEXT}
          </p>
        )}
        <Button
          theme="solid"
          htmlType="submit"
          loading={submitting}
          disabled={schema === undefined || submitting}
        >
          保存
        </Button>
      </form>
      {canTest ? (
        <section className={styles.testSection}>
          <h4 className={styles.testTitle}>发送测试</h4>
          <p className={styles.testNote}>{TEST_NOTE_TEXT}</p>
          <div className={styles.testRow}>
            <Input
              className={styles.testTarget}
              value={testTarget}
              onChange={(value) => setTestTarget(value)}
              placeholder={schema?.category === 'sms' ? '手机号' : '邮箱'}
              disabled={testReq.status === 'loading'}
              aria-label="测试接收目标"
            />
            <Button
              onClick={handleTest}
              loading={testReq.status === 'loading'}
              disabled={testReq.status === 'loading'}
            >
              发送测试
            </Button>
          </div>
          {testFeedback !== null ? (
            <p role="status" className={styles.testFeedback}>
              {testFeedback}
            </p>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
