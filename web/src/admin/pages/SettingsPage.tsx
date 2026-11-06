/**
 * 系统设置页（docs/前端架构.md §6 行 520 SettingsPage；docs/接口文档.md §5.6
 * 行 1287 GetSettings / SetSettings；docs/需求.md §4.6 行 259）——/admin/settings
 * （§5.6 四张表全量键，生成物现状 36 字段）的大表单。
 *
 * ⚠️ SetSettings 全量替换语义：零值也会被写入——
 * 表单以 GetSettings 响应初始化完整键集（settingsLogic.draftFromSettings），
 * 保存时经 api.buildSetSettingsRequest 全量提交全部键（不能只提交改动字段）；
 * 保存按钮旁固定提示「保存将覆盖全部设置」，顶部 Banner 展开说明。
 *
 * 键集 / 分区 / 默认值 / 交叉校验全部收口在 ./settingsLogic（零 Semi 可测）；
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
  Select,
  Spin,
  Switch,
  Toast,
  Typography,
} from '@douyinfe/semi-ui-19';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import { StringListEditor } from '../components/StringListEditor';
import {
  apiErrorText,
  buildSetSettingsRequest,
  getSettings,
  isUnauthenticatedError,
  setSettings,
} from '../api';
import {
  getSettingsSections,
  draftFromSettings,
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
  readonly field: SettingsFieldMeta;
  readonly draft: SettingsDraft;
  readonly disabled: boolean;
  readonly onChange: <K extends keyof SettingsDraft>(key: K, value: SettingsDraft[K]) => void;
}): ReactNode {
  const { field, draft, disabled, onChange } = props;
  switch (field.kind) {
    case 'number':
      return (
        <label className={styles.field} key={field.key}>
          <span className={styles.fieldLabel}>
            {field.label}
            {field.unit !== undefined ? `（${field.unit}）` : ''}
          </span>
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
          {field.hint !== undefined ? (
            <span className={styles.fieldHint}>{field.hint}</span>
          ) : null}
        </label>
      );
    case 'switch':
      return (
        <div className={styles.switchRow} key={field.key}>
          <Switch
            checked={draft[field.key]}
            onChange={(checked: boolean) => onChange(field.key, checked)}
            disabled={disabled}
          />
          <span className={styles.switchLabel}>{field.label}</span>
          {field.hint !== undefined ? (
            <span className={styles.fieldHint}>{field.hint}</span>
          ) : null}
        </div>
      );
    case 'text':
      return (
        <label className={styles.field} key={field.key}>
          <span className={styles.fieldLabel}>{field.label}</span>
          <Input
            className={styles.textInput}
            value={draft[field.key]}
            onChange={(next: string) => onChange(field.key, next)}
            disabled={disabled}
          />
          {field.hint !== undefined ? (
            <span className={styles.fieldHint}>{field.hint}</span>
          ) : null}
        </label>
      );
    case 'select':
      return (
        <label className={styles.field} key={field.key}>
          <span className={styles.fieldLabel}>{field.label}</span>
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
          {field.hint !== undefined ? (
            <span className={styles.fieldHint}>{field.hint}</span>
          ) : null}
        </label>
      );
    case 'multiSelect':
      return (
        <div className={styles.field} key={field.key}>
          <span className={styles.fieldLabel}>{field.label}</span>
          <CheckboxGroup
            options={[...field.options]}
            value={[...draft[field.key]]}
            onChange={(next: string[]) => onChange(field.key, next)}
            disabled={disabled}
          />
          {field.hint !== undefined ? (
            <span className={styles.fieldHint}>{field.hint}</span>
          ) : null}
        </div>
      );
    case 'stringList':
      return (
        <div className={styles.field} key={field.key}>
          <span className={styles.fieldLabel}>{field.label}</span>
          <StringListEditor
            values={draft[field.key]}
            onChange={(next) => onChange(field.key, next)}
            disabled={disabled}
            ariaLabel={field.label}
            addText={field.addText}
            placeholder={field.placeholder}
          />
          {field.hint !== undefined ? (
            <span className={styles.fieldHint}>{field.hint}</span>
          ) : null}
        </div>
      );
  }
}

/**
 * 草稿等价判定：36 键扁平结构键级浅比较，数组键（loginMethods /
 * mfaMethods / ssoDomains / gatewayTokens）按键序逐项比对——数组序对
 * StringListEditor 可见且向保存语义回传，不按集合归一；误报方向安全
 * （多弹一次离开确认，不致丢改动）。
 */
function draftEquals(a: SettingsDraft, b: SettingsDraft): boolean {
  for (const key of Object.keys(a) as (keyof SettingsDraft)[]) {
    const va: number | boolean | string | readonly string[] = a[key];
    const vb: number | boolean | string | readonly string[] = b[key];
    if (Array.isArray(va) && Array.isArray(vb)) {
      if (va.length !== vb.length || va.some((item, index) => item !== vb[index])) {
        return false;
      }
    } else if (va !== vb) {
      return false;
    }
  }
  return true;
}

/** 系统设置页：加载 → 草稿初始化（全键集）→ 分区表单 → 全量保存。 */
export function SettingsPage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  const { status, data, error, run } = useRequest(getSettings);
  const [draft, setDraft] = useState<SettingsDraft | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // 行内校验错误槽（settingsDraftIssue 交叉校验文案，保持行内）；写操作
  // 成功 / 失败反馈归 Semi Toast，不占本槽。
  const [actionError, setActionError] = useState<string | null>(null);
  // 已保存快照（加载初始化 / 保存成功前移），dirty 判定基准。
  // draft 更新走不可变 set（updateField 展开 / 编辑器下发新数组），与快照
  // 共享初始引用互不污染。
  const [savedDraft, setSavedDraft] = useState<SettingsDraft | null>(null);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run().catch(() => {});
  }, [run]);

  useEffect(() => {
    // 全量替换语义：草稿以响应初始化完整键集，保存整体回写。
    if (data !== undefined) {
      const initial = draftFromSettings(data);
      setDraft(initial);
      // 同份快照作 dirty 基准（后续改动全走不可变更新）。
      setSavedDraft(initial);
    }
  }, [data]);

  useEffect(() => {
    // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
    if (isUnauthenticatedError(error)) {
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, props.alRoot]);

  // 未保存改动（P1-8）= 草稿与已保存快照键级不等。
  const dirty = draft !== null && savedDraft !== null && !draftEquals(draft, savedDraft);

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
  function updateField<K extends keyof SettingsDraft>(key: K, value: SettingsDraft[K]): void {
    setDraft((prev) => (prev === null ? prev : { ...prev, [key]: value }));
  }

  /** 保存（§5.6 行 1287 全量替换）：交叉校验前置，全部 36 键整体提交。 */
  async function submit(): Promise<void> {
    const current = draft;
    if (current === null || submitting) {
      return;
    }
    const issue = settingsDraftIssue(current);
    if (issue !== null) {
      setActionError(issue);
      return;
    }
    // 校验通过即清行内校验槽；写失败反馈走 Toast，不回填本槽。
    setActionError(null);
    setSubmitting(true);
    try {
      await setSettings(buildSetSettingsRequest(current));
      // 保存成功即快照前移（dirty 清零，离开不再二次确认）。
      setSavedDraft(current);
      Toast.success(t('admin.settingsSaved'));
    } catch (err) {
      if (isUnauthenticatedError(err)) {
        window.location.replace(loginUrl(props.alRoot));
        return;
      }
      Toast.error(apiErrorText(err));
    } finally {
      setSubmitting(false);
    }
  }

  // 页级错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
    return (
      <Banner type="danger" fullMode={false} description={t('admin.settingsLoadFailed')} />
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
      <Typography.Title heading={3}>{t('admin.settingsTitle')}</Typography.Title>
      <Banner
        type="warning"
        className={styles.overwriteBanner}
        closeIcon={null}
        description={t('admin.settingsOverwriteBanner')}
      />
      {actionError !== null ? (
        <p role="alert" className={styles.actionError}>
          {actionError}
        </p>
      ) : null}
      <div className={styles.sections}>
        {/* 渲染期调用取当前语言文案（模块级常量会冻结 locale）。 */}
        {getSettingsSections().map((section) => (
          <Card key={section.title} title={section.title} className={styles.sectionCard}>
            <div className={styles.sectionBody}>
              {section.fields.map((field) => (
                <FieldView
                  key={field.key}
                  field={field}
                  draft={draft}
                  disabled={submitting}
                  onChange={updateField}
                />
              ))}
            </div>
          </Card>
        ))}
      </div>
      <div className={styles.footer}>
        <span className={styles.overwriteNote}>{t('admin.settingsOverwriteNotice')}</span>
        <Button
          theme="solid"
          loading={submitting}
          disabled={submitting}
          onClick={() => {
            void submit();
          }}
        >
          {t('admin.saveSettingsAction')}
        </Button>
      </div>
    </section>
  );
}
