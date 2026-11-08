/**
 * 提供商新建 / 编辑页（docs/前端架构.md §6 行 516；docs/接口文档.md
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
import { useMemo, useState, type ReactNode } from "react";
import { create, type JsonObject } from "@bufbuild/protobuf";
import {
  Banner,
  Button,
  Cascader,
  Input,
  Select,
  Spin,
  Toast,
  Typography,
} from "@douyinfe/semi-ui";
import { useLocation, useNavigate } from "@modern-js/runtime/router";
import { useRequest } from "ahooks";
import { ProviderIcon } from "../../shared/components/ProviderIcon";
import { requestOptions } from "../../shared/hooks/requestOptions";
import { t } from "../../shared/i18n";
import {
  GetProviderRequestSchema,
  TestProviderRequestSchema,
} from "../../gen/proto/api/admin/v1/provider_pb";
import { GetProviderSchemaRequestSchema } from "../../gen/proto/api/admin/v1/schema_pb";
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
} from "../api";
import {
  ProviderCallbackHint,
  showsCallbackHint,
} from "../components/ProviderCallbackHint";
import { adminNavPath } from "../paths";
import { SchemaForm } from "../schema/SchemaForm";
import {
  adminProviderToValues,
  buildProviderStruct,
  initialCreateValues,
  isProviderKeyTaken,
  validateSchemaValues,
} from "../schema/schemaLogic";
import type { SchemaField } from "../../gen/proto/api/admin/v1/schema_pb";
import styles from "./ProviderEditPage.module.less";
import { last } from "lodash-es";

/** 表单值形态（schemaLogic 值模型：键 → JSON 值 / json 文本态）。 */
type FormValues = Record<string, unknown>;

/**
 * 提供商新建 / 编辑页。providerKey 缺省 = 新建（type 下拉可选）；
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
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();

  const [category, setCategory] = useState("");
  const [type, setType] = useState("");
  const [values, setValues] = useState<FormValues>({});
  const [issues, setIssues] = useState<Record<string, string>>({});
  // 提交失败 / 测试发送成败反馈改走 Semi Toast（原 actionError 就地
  // 文字随 Semi 回归移除）；testFeedback 仅保留本地校验（target 必填）行内提示。
  const [testTarget, setTestTarget] = useState("");
  const [testFeedback, setTestFeedback] = useState<string | null>(null);

  // 五请求实例迁 ahooks（§5 映射）——首取（types / 编辑链
  // provider → schema）改自动请求（ready / refreshDeps 驱动，旧挂载 effect
  // 删除），提交 / 测试改 manual + 集中 onError（失败 Toast 与原 catch 等价
  // 〔§5.4-#3〕，401 集中跳登录）；成功副作用（编辑回填 / 跳列表 / 测试提示）
  // 走 onSuccess，均用 run 不用 runAsync（无调用方降级场景，§0-④）。
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
          providerKey: props.providerKey ?? "",
        }),
      ),
    {
      // 编辑模式挂载即取（ready 门控；providerKey 由路由层给定，不随渲染变化）。
      ready: editing,
      onSuccess: (provider) => {
        // 编辑回填链第一步：type 落地即驱动下方 schema 自动请求（refreshDeps）。
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
      // type 非空即取（编辑链回填 / 新建选型两入口同源）；type 变更重取，
      // 连击 stale 由 ahooks latest-only 保证（旧竞态令牌语义）。
      ready: type !== "",
      refreshDeps: [type],
      onSuccess: (schema) => {
        // 编辑：按 provider 明文回填；新建：按 schema 默认值初始化
        // （category 用顶层 category 预填——applySchemaDefaults
        // 的零值 '' 会被 required + 锁定键死锁）。
        const provider = providerReq.data;
        setValues(
          editing && provider !== undefined
            ? adminProviderToValues(schema.fields, provider)
            : initialCreateValues(schema),
        );
      },
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
        // 列表页路径取 ADMIN_NAV_ROUTES 单一来源（paths.adminNavPath）。
        void navigate(adminNavPath("admin.navProviders"));
      },
      ...requestOptions({
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );
  const testReq = useRequest(testProvider, {
    manual: true,
    onSuccess: () => {
      Toast.success(t("admin.testSent"));
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
    return [items.find(x => x.type === type)?.category || "", type];
  }, [typesReq.data, type]);

  /** 新建模式切换 type → 自动重拉 schema 并重置表单（编辑模式下拉锁定）。 */
  function handleTypeChange(next: string): void {
    setType(next);
    setIssues({});
  }

  function handleChange(key: string, value: unknown): void {
    setValues((prev) => ({ ...prev, [key]: value }));
  }

  /** icon_url 实时预览（§6 行 516：手填绝对 URL，空则占位）。 */
  function iconPreview(field: SchemaField): ReactNode {
    if (field.key !== "icon_url") {
      return null;
    }
    const icon = typeof values.icon_url === "string" ? values.icon_url : "";
    return <ProviderIcon icon={icon} alt={t("admin.iconPreviewAlt")} />;
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
      const key =
        typeof values.provider_key === "string" ? values.provider_key : "";
      if (key !== "") {
        try {
          const list = await listProviders(buildListProvidersRequest());
          if (isProviderKeyTaken(key, list.items)) {
            nextIssues.provider_key = t("admin.providerKeyTaken");
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
    // 成功跳列表走 onSuccess，失败 Toast 走集中 onError（§5.4-#3 等价替换，
    // 本地 then/catch 删除）；竞态 / 错误态由 ahooks 实例承载。
    submitReq.run(buildProviderStruct(type, schema.fields, values));
  }

  /** 发送测试（§5.2 行 1177 TestProvider {providerKey, target}）。 */
  function handleTest(): void {
    if (testTarget.trim() === "") {
      setTestFeedback(t("admin.testTargetRequired"));
      return;
    }
    setTestFeedback(null);
    // 成功 / 失败反馈均走 hook 回调（onSuccess Toast + 集中 onError Toast）。
    testReq.run(
      create(TestProviderRequestSchema, {
        providerKey: props.providerKey ?? "",
        target: testTarget.trim(),
      }),
    );
  }

  // —— 错误 / 加载帧（自绘文字换 Semi Banner / Spin）——

  if (editing && providerReq.error !== undefined) {
    return (
      <Banner
        type="danger"
        fullMode={false}
        description={t("admin.providerLoadFailed")}
      />
    );
  }
  if (schemaReq.error !== undefined) {
    return (
      <Banner
        type="danger"
        fullMode={false}
        description={t("admin.schemaLoadFailed")}
      />
    );
  }
  const loading =
    typesReq.loading ||
    (editing &&
      (providerReq.data === undefined || schemaReq.data === undefined));
  if (loading) {
    return (
      <div className={styles.stateCenter} role="status">
        <Spin size="large" />
      </div>
    );
  }

  const schema = schemaReq.data;
  const submitting = submitReq.loading;
  // category 恒只读（§5.3 行 1195 由注册表决定）；provider_key 编辑锁定
  //（§5.3 行 1192 创建后不可改）。
  const lockedKeys = editing ? ["category", "provider_key"] : ["category"];
  const canTest =
    editing &&
    schema !== undefined &&
    (schema.category === "sms" || schema.category === "email");

  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className="page-title">
        {editing
          ? t("admin.editProviderTitle")
          : t("admin.createProviderTitle")}
      </Typography.Title>
      {typesReq.error !== undefined ? (
        // 类型清单加载失败自绘文字换 Semi Banner（表单缺类型不可用，页级口径）。
        <Banner
          type="danger"
          fullMode={false}
          className={styles.actionBanner}
          description={t("admin.providerTypesLoadFailed")}
        />
      ) : null}
      <div className={styles.typeField}>
        <label className={styles.typeLabel} htmlFor="provider-type">
          {t("admin.providerTypeLabel")}
        </label>
        <Cascader
          id="provider-type"
          className={styles.typeSelect}
          value={treeValue}
          treeData={treeData}
          onChange={(value) => handleTypeChange(String(last(value as string[])))}
          disabled={editing}
          placeholder={t("admin.selectTypePlaceholder")}
        />
      </div>
      {showsCallbackHint(schema?.category) ? (
        <ProviderCallbackHint
          alRoot={props.alRoot}
          providerKey={(values?.provider_key as string) || undefined}
          type={type}
        />
      ) : null}
      <form
        className={styles.form}
        onSubmit={(event) => {
          event.preventDefault();
          handleSubmit().catch(() => {});
        }}
      >
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
            {t("admin.providerTypeRequired")}
          </p>
        )}
        <Button
          theme="solid"
          htmlType="submit"
          loading={submitting}
          disabled={schema === undefined || submitting}
        >
          {t("admin.saveAction")}
        </Button>
      </form>
      {canTest ? (
        <section className={styles.testSection}>
          <h4 className={styles.testTitle}>{t("admin.sendTestAction")}</h4>
          <p className={styles.testNote}>{t("admin.testNote")}</p>
          <div className={styles.testRow}>
            <Input
              className={styles.testTarget}
              value={testTarget}
              onChange={(value) => setTestTarget(value)}
              placeholder={
                schema?.category === "sms"
                  ? t("admin.phoneLabel")
                  : t("admin.emailLabel")
              }
              disabled={testReq.loading}
              aria-label={t("admin.testTargetAriaLabel")}
            />
            <Button
              onClick={handleTest}
              loading={testReq.loading}
              disabled={testReq.loading}
            >
              {t("admin.sendTestAction")}
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
