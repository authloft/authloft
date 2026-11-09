/**
 * 系统设置页（docs/前端架构.md §6 行 520 SettingsPage；docs/接口文档.md §5.6
 * 行 1287 GetSettings / SetSettings；docs/需求.md §4.6 行 259）——/admin/settings
 * （§5.6 四张表全量键，生成物现状 36 字段）的大表单。
 *
 * ⚠️ SetSettings 按 has 位部分更新（PATCH）：未设置不修改、显式零值
 * 覆盖；四个 repeated 键带 has_* 伴生标志，置 true 时列表在场、空数组
 * 即清空。36 键按 getSettingsTabs() 分 4 个 Tab 展示（账号与密码 /
 * 登录与验证 / 会话与域名 / 系统与集成），草稿仍是单一完整键集
 * （draftFromSettings），切 Tab 不丢未保存改动、Tab 标签上落脏点。
 * 保存作用域二选一：「保存本页签」只提交该 Tab 的改动键、「保存全部改动」
 * 提交所有改动键——均经 api.buildSettingsPatchRequest 构造，**未改动的键
 * 不进 wire**；成功后只前移已提交键的快照，其他 Tab 的改动保持 dirty。
 * 保存前变更预览：先弹确认 Modal（diff = 草稿 vs 已保存快照的键级比对，
 * 按作用域过滤），逐键列出 旧值 → 新值（gateway Tokens 脱敏）并显示
 * 「将变更 N 项」，确认才提交；零改动时按钮禁用。
 *
 * 键集 / 分区 / Tab / 默认值 / 交叉校验全部收口在 ./settingsLogic
 * （零 Semi 可测）；
 * 本组件为渲染壳薄层（渲染不可测见 admin.test.tsx 头注 Blocker）。固定规则
 * （§5.6 行 1302-1306：>64、与用户名 / 邮箱相同、含空白）写死在服务端、不在
 * 表单暴露。https_deployment（=36，行 1354/1356 三态文案定稿）随本实现建键
 * （双端 proto / 生成物已刷入）；static_base 改后提示刷新页面生效（行 1353）。
 *
 * 401 统一跳登录（§6 行 501）；保存成功 / 失败反馈统一走 Semi Toast
 * （Semi 回归，原就地 notice / actionError 文字已移除）——成功
 * 文案沿用现成键 settingsSaved；交叉校验不通过的内联校验错误保持行内
 * 不动。未保存保护（P1-8）：draft 与已保存快照键级比对出
 * dirty；admin 为零路由库 MPA（Nav / 登出 / 刷新 / 关标签全部整页卸载），
 * dirty 时经 beforeunload 触发浏览器原生二次确认（非自造弹层——硬导航
 * 无法被 Modal.confirm 拦截，浏览器也不允许自定义文案，故零新增 i18n
 * 键）；无改动时正常离开。样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import {
  Banner,
  Button,
  Card,
  Checkbox,
  Input,
  InputNumber,
  List,
  Modal,
  Select,
  Spin,
  Switch,
  TabPane,
  Tabs,
  Toast,
  Typography,
} from '@douyinfe/semi-ui';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import { StringListEditor } from '../components/StringListEditor';
import {
  adminReturnTo,
  apiErrorText,
  buildSettingsPatchRequest,
  getSettings,
  isUnauthenticatedError,
  setSettings,
} from '../api';
import {
  getSettingsSections,
  getSettingsTabs,
  draftFromSettings,
  mergeSavedSettings,
  settingsDraftIssue,
  type SettingsDraft,
  type SettingsFieldMeta,
} from '../settingsLogic';
import { loginUrl } from '../bootstrap';
import styles from './SettingsPage.module.less';

const { Group: CheckboxGroup } = Checkbox;

/**
 * 单字段渲染（判别联合按 kind 收窄 → key 类型随之收窄，零类型断言）。
 * InputNumber 空态给 ''：收敛 number（NaN → 0，非法值由 settingsDraftIssue 兜文案）。
 */
function FieldView(props: {
  field: SettingsFieldMeta;
  draft: SettingsDraft;
  disabled: boolean;
  onChange: <K extends keyof SettingsDraft>(
    key: K,
    value: SettingsDraft[K],
  ) => void;
}): ReactNode {
  const { field, draft, disabled, onChange } = props;
  switch (field.kind) {
    case 'number':
      return (
        <InputNumber
          className={styles.numberInput}
          value={draft[field.key]}
          min={0}
          precision={0}
          onChange={(raw: number | string) => {
            const next = typeof raw === 'number' ? raw : Number(raw);
            onChange(field.key, Number.isNaN(next) ? 0 : next);
          }}
          disabled={disabled}
        />
      );
    case 'switch':
      return (
        <Switch
          checked={draft[field.key]}
          onChange={(checked: boolean) => onChange(field.key, checked)}
          disabled={disabled}
        />
      );
    case 'text':
      return (
        <Input
          className={styles.textInput}
          value={draft[field.key]}
          onChange={(next: string) => onChange(field.key, next)}
          disabled={disabled}
        />
      );
    case 'select':
      return (
        <Select
          className={styles.selectInput}
          value={draft[field.key]}
          optionList={[...field.options]}
          onChange={(next: string | string[] | undefined) => {
            // 单选模式实际下发 string；清空 / 多值形态非本表单路径，空串
            // 交由 settingsDraftIssue 三态校验兜文案。
            onChange(field.key, typeof next === 'string' ? next : '');
          }}
          disabled={disabled}
        />
      );
    case 'multiSelect':
      return (
        <Select
          multiple
          className={styles.multiSelectInput}
          value={[...draft[field.key]]}
          optionList={[...field.options]}
          onChange={(next) => onChange(field.key, next as string[])}
          disabled={disabled}
        />
      );
    case 'stringList':
      return (
        <StringListEditor
          className={styles.stringListInput}
          values={draft[field.key]}
          onChange={(next) => onChange(field.key, next)}
          disabled={disabled}
          ariaLabel={field.label}
          addText={field.addText}
          placeholder={field.placeholder}
        />
      );
  }
}

/**
 * 变更预览单条（保存前确认 Modal）：label 取分区元数据当前语言文案，
 * before / after 为已格式化的展示值（敏感键脱敏，见 SENSITIVE_DIFF_KEYS）。
 */
interface SettingsDiffItem {
  key: keyof SettingsDraft;
  label: string;
  before: string;
  after: string;
}

/** 变更预览中脱敏的键（网关 Token 不明文回显，防误截图外泄）。 */
const SENSITIVE_DIFF_KEYS: ReadonlySet<keyof SettingsDraft> = new Set([
  'gatewayTokens',
]);

/** 脱敏占位（符号无语言差异，不占 i18n 键）。 */
const MASKED_VALUE = '••••••';

/** 单键展示值格式化（与 FieldView 的控件形态对齐：布尔→是/否、空→（空）、下拉→选项文案）。 */
function formatSettingsValue(
  field: SettingsFieldMeta,
  draft: SettingsDraft,
): string {
  switch (field.kind) {
    case 'number':
      return String(draft[field.key]);
    case 'switch':
      return draft[field.key] ? t('admin.yesText') : t('admin.noText');
    case 'text': {
      const value = draft[field.key];
      return value === '' ? t('admin.settingsDiffEmptyValue') : value;
    }
    case 'select': {
      const value = draft[field.key];
      const hit = field.options.find((option) => option.value === value);
      if (hit !== undefined) {
        return hit.label;
      }
      return value === '' ? t('admin.settingsDiffEmptyValue') : value;
    }
    case 'multiSelect':
    case 'stringList': {
      const list = draft[field.key];
      if (list.length === 0) {
        return t('admin.settingsDiffEmptyValue');
      }
      if (SENSITIVE_DIFF_KEYS.has(field.key)) {
        return MASKED_VALUE;
      }
      return list.join(', ');
    }
  }
}

/**
 * 草稿 vs 已保存快照的键级 diff（dirty / Tab 脏点 / 保存作用域 / 变更预览
 * 的唯一数据源）：36 键按分区表序遍历，数组键序敏感（与控件可见顺序
 * 一致，不按集合归一）。渲染期调用 getSettingsSections() 取当前语言
 * 文案，不作模块级常量以免 locale 冻结。
 */
function buildSettingsDiff(
  saved: SettingsDraft,
  draft: SettingsDraft,
): SettingsDiffItem[] {
  const items: SettingsDiffItem[] = [];
  for (const section of getSettingsSections()) {
    for (const field of section.fields) {
      const before: number | boolean | string | string[] = saved[field.key];
      const after: number | boolean | string | string[] = draft[field.key];
      const equal =
        Array.isArray(before) && Array.isArray(after)
          ? before.length === after.length &&
            before.every((item, index) => item === after[index])
          : before === after;
      if (!equal) {
        items.push({
          key: field.key,
          label: field.label,
          before: formatSettingsValue(field, saved),
          after: formatSettingsValue(field, draft),
        });
      }
    }
  }
  return items;
}

/** 系统设置页：加载 → 全键草稿 → 多 Tab 分区表单 → 变更预览确认 → 部分提交。 */
export function SettingsPage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  alRoot: string;
}): ReactNode {
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // GetSettings 首取改 ahooks 自动请求；401 由集中 onError 跳登录，
  // 其余错误走页面错误帧（toast:false 静默防双报）。
  const { data, error } = useRequest(
    getSettings,
    requestOptions({
      toast: false,
      returnTo: () => adminReturnTo(location.pathname, location.search),
    }),
  );
  const [draft, setDraft] = useState<SettingsDraft | null>(null);
  // 当前 Tab（key 为 settingsLogic 的稳定 slug，locale 切换不影响选中态）。
  const [activeTab, setActiveTab] = useState('account');
  // 已保存快照（加载初始化 / 保存成功前移），dirty 判定基准。
  // draft 更新走不可变 set（updateField 展开 / 编辑器下发新数组），与快照
  // 共享初始引用互不污染。
  const [savedDraft, setSavedDraft] = useState<SettingsDraft | null>(null);
  // 保存前变更预览：点保存先弹确认 Modal 列出将变更键（旧值 → 新值），
  // 确认才提交；items 在点击时快照，弹窗期间草稿冻结（Modal 遮罩阻断编辑）。
  const [diffItems, setDiffItems] = useState<SettingsDiffItem[]>([]);
  const [diffOpen, setDiffOpen] = useState(false);

  useEffect(() => {
    // 草稿恒为 36 键完整快照；Tab 只切展示与保存作用域，不拆草稿。
    if (data !== undefined) {
      const initial = draftFromSettings(data);
      setDraft(initial);
      // 同份快照作 dirty 基准（后续改动全走不可变更新）。
      setSavedDraft(initial);
    }
  }, [data]);

  // 渲染期取当前语言文案（模块级常量会冻结 locale）；Tab 元数据由分区表
  // 自动摊平，dirty / 保存作用域 / 变更预览共用这一份键级 diff。
  const tabs = getSettingsTabs();
  const allDiff: SettingsDiffItem[] =
    draft !== null && savedDraft !== null
      ? buildSettingsDiff(savedDraft, draft)
      : [];
  const changedKeys = new Set<keyof SettingsDraft>(
    allDiff.map((item) => item.key),
  );
  // 未保存改动（P1-8）= 草稿与已保存快照键级不等。
  const dirty = changedKeys.size > 0;
  const activeTabMeta = tabs.find((tab) => tab.key === activeTab) ?? tabs[0];
  const tabDirtyKeys = activeTabMeta.keys.filter((key) => changedKeys.has(key));

  // 未保存保护（P1-8）：dirty 时挂 beforeunload——admin 为零路由库
  // MPA，Nav / 登出 / 刷新 / 关标签一律整页卸载，这是唯一可拦截点；确认弹层
  // 为浏览器原生（非自造，preventDefault 即触发，文案由浏览器托管不允许
  // 自定义）。无改动时不挂监听，正常离开。
  useEffect(() => {
    if (!dirty) {
      return;
    }
    function handleBeforeUnload(event: BeforeUnloadEvent): void {
      event.preventDefault();
    }
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [dirty]);

  /** 草稿单键更新（不可变；泛型保证 key / value 类型对齐）。 */
  function updateField<K extends keyof SettingsDraft>(
    key: K,
    value: SettingsDraft[K],
  ): void {
    setDraft((prev) => (prev === null ? prev : { ...prev, [key]: value }));
  }

  /**
   * 点保存（变更预览入口）：交叉校验前置（全键草稿，跨 Tab 约束不漏）→
   * 按作用域过滤键级 diff 并弹确认 Modal；零 diff 不弹（按钮已禁用，此处
   * 兜底）。确认后由 Modal onOk 调 submit 真正提交，提交键集 = diffItems。
   */
  function requestSave(): void {
    const current = draft;
    if (current === null || savedDraft === null || submitting) {
      return;
    }
    const issue = settingsDraftIssue(current);
    if (issue !== null) {
      Toast.error(issue);
      return;
    }
    // 校验通过即清行内校验槽；写失败反馈走 Toast，不回填本槽。
    const items = allDiff.filter((item) =>
      activeTabMeta.keys.includes(item.key),
    );
    if (items.length === 0) {
      return;
    }
    setDiffItems(items);
    setDiffOpen(true);
  }

  /** 保存（§5.6 行 1287 PATCH）：确认 Modal 的 onOk，只提交 diffItems 的键。 */
  const { run: submit, loading: submitting } = useRequest(
    async () => {
      const current = draft;
      if (current === null || diffItems.length === 0) {
        return;
      }
      const keys = diffItems.map((item) => item.key);
      await setSettings(buildSettingsPatchRequest(current, keys));
      // 只前移已提交键：其他 Tab 的未保存改动仍 dirty（不能被误标已保存）。
      setSavedDraft((prev) =>
        prev === null ? prev : mergeSavedSettings(prev, current, keys),
      );
    },
    {
      manual: true,
      onSuccess: () => {
        setDiffOpen(false);
        Toast.success(t('admin.settingsSaved'));
      },
      onError: (err: unknown) => {
        if (isUnauthenticatedError(err)) {
          window.location.replace(
            loginUrl(
              props.alRoot,
              adminReturnTo(location.pathname, location.search),
            ),
          );
          return;
        }
        Toast.error(apiErrorText(err));
      },
    },
  );

  // 页级错误态（404 掩护等其余错误；401 由集中 onError 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (error !== undefined && !isUnauthenticatedError(error)) {
    return (
      <Banner
        type="danger"
        fullMode={false}
        description={t('admin.settingsLoadFailed')}
      />
    );
  }
  // idle / loading（草稿尚未初始化）：不渲染表单。
  // 裸文字换 Semi Spin。
  if (draft === null) {
    return (
      <div className={styles.stateCenter} role="status">
        <Spin size="large" />
      </div>
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className="page-title">
        {t('admin.settingsTitle')}
      </Typography.Title>
      <Tabs
        className={styles.tabs}
        type="line"
        activeKey={activeTabMeta.key}
        onChange={(key: string) => setActiveTab(key)}
      >
        {tabs.map((tab) => {
          const tabDirty = tab.keys.some((key) => changedKeys.has(key));
          return (
            <TabPane
              key={tab.key}
              itemKey={tab.key}
              tab={
                <span className={styles.tabLabel}>
                  {tab.title}
                  {tabDirty ? (
                    <span
                      className={styles.tabDirtyDot}
                      title={t('admin.settingsTabUnsaved')}
                    />
                  ) : null}
                </span>
              }
            >
              <div className={styles.sections}>
                {tab.sections.map((section) => (
                  <div key={section.key} className={styles.sectionCard}>
                    <Typography.Title heading={5}>
                      {section.title}
                    </Typography.Title>
                    <div className={styles.sectionBody}>
                      <List>
                        {section.fields.map((field) => (
                          <List.Item
                            className={styles.field}
                            key={field.key}
                            main={
                              <div className={styles.fieldLabelRow}>
                                <Typography.Text className={styles.fieldLabel}>
                                  {field.label}
                                  {field.kind === 'number' &&
                                  field.unit !== undefined
                                    ? `（${field.unit}）`
                                    : ''}
                                </Typography.Text>
                                {field.hint ? (
                                  <Typography.Text type="tertiary">
                                    {field.hint}
                                  </Typography.Text>
                                ) : null}
                              </div>
                            }
                            extra={
                              <FieldView
                                field={field}
                                draft={draft}
                                disabled={submitting}
                                onChange={updateField}
                              />
                            }
                          />
                        ))}
                      </List>
                    </div>
                  </div>
                ))}
              </div>
            </TabPane>
          );
        })}
      </Tabs>
      <Button
        theme="solid"
        loading={submitting}
        disabled={submitting || tabDirtyKeys.length === 0}
        onClick={requestSave}
      >
        {t('admin.settingsTabSaveAction')}
      </Button>
      {/* 保存前变更预览：逐键列出 旧值 → 新值（敏感键脱敏），确认才提交；
          失败 Modal 保持打开（Toast 报错后可修正重试），成功在 submit 内关闭。 */}
      <Modal
        title={t('admin.settingsDiffTitle')}
        visible={diffOpen}
        onCancel={() => setDiffOpen(false)}
        onOk={() => {
          void submit();
        }}
        okText={t('admin.saveSettingsAction')}
        cancelText={t('admin.cancelAction')}
        confirmLoading={submitting}
        maskClosable={false}
      >
        <p>{t('admin.settingsDiffSummary', { count: diffItems.length })}</p>
        <List
          size="small"
          dataSource={diffItems}
          renderItem={(item) => (
            <List.Item key={item.key}>
              {item.label}：{item.before} → {item.after}
            </List.Item>
          )}
        />
      </Modal>
    </section>
  );
}
