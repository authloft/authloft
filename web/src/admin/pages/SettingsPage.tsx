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
 * 401 统一跳登录（§6 行 501）；保存失败就地提示；保存成功 notice 展示
 * 「全部设置已整体覆盖」。样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
// 子路径 import（同 AdminLayout 口径：避免全量入口，测试链 / 产物见其注释）。
import Banner from '@douyinfe/semi-ui/lib/es/banner';
import Button from '@douyinfe/semi-ui/lib/es/button';
import Card from '@douyinfe/semi-ui/lib/es/card';
import Checkbox from '@douyinfe/semi-ui/lib/es/checkbox';
import Input from '@douyinfe/semi-ui/lib/es/input';
import InputNumber from '@douyinfe/semi-ui/lib/es/inputNumber';
import Select from '@douyinfe/semi-ui/lib/es/select';
import Switch from '@douyinfe/semi-ui/lib/es/switch';
import Typography from '@douyinfe/semi-ui/lib/es/typography';
import { useRequest } from '../../shared/hooks/useRequest';
import { StringListEditor } from '../components/StringListEditor';
import {
  apiErrorText,
  buildSetSettingsRequest,
  getSettings,
  isUnauthenticatedError,
  setSettings,
} from '../api';
import {
  SETTINGS_SECTIONS,
  draftFromSettings,
  settingsDraftIssue,
  type SettingsDraft,
  type SettingsFieldMeta,
} from '../settingsLogic';
import { loginUrl } from '../bootstrap';
import styles from './SettingsPage.module.less';

const { Group: CheckboxGroup } = Checkbox;

/** 全量替换警示（§5.6 行 1287 SetSettings 的 UI 明示文案）。 */
const OVERWRITE_NOTICE_TEXT = '保存将覆盖全部设置';

/** 顶部 Banner 展开说明（热更新口径 §5.6 行 1287/1363）。 */
const OVERWRITE_BANNER_TEXT =
  'SetSettings 为全量替换：保存时表单内全部设置将整体提交并覆盖（包括未改动的键），改动热更新、只对后续请求生效';

/** 保存成功文案。 */
const SAVED_TEXT = '设置已保存：全部设置已整体覆盖，热更新对后续请求生效';

/** 加载 / 失败态文案（无 i18n 键，最简中文字面量，归 i18n 收口卡）。 */
const LOADING_TEXT = '加载中…';
const LOAD_ERROR_TEXT = '系统设置加载失败，请刷新重试';

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

/** 系统设置页：加载 → 草稿初始化（全键集）→ 分区表单 → 全量保存。 */
export function SettingsPage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  const { status, data, error, run } = useRequest(getSettings);
  const [draft, setDraft] = useState<SettingsDraft | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run().catch(() => {});
  }, [run]);

  useEffect(() => {
    // 全量替换语义：草稿以响应初始化完整键集，保存整体回写。
    if (data !== undefined) {
      setDraft(draftFromSettings(data));
    }
  }, [data]);

  useEffect(() => {
    // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
    if (isUnauthenticatedError(error)) {
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, props.alRoot]);

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
    setSubmitting(true);
    try {
      await setSettings(buildSetSettingsRequest(current));
      setActionError(null);
      setNotice(SAVED_TEXT);
    } catch (err) {
      if (isUnauthenticatedError(err)) {
        window.location.replace(loginUrl(props.alRoot));
        return;
      }
      setActionError(apiErrorText(err));
    } finally {
      setSubmitting(false);
    }
  }

  // 列表错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
    return (
      <p role="alert" className={styles.loadError}>
        {LOAD_ERROR_TEXT}
      </p>
    );
  }
  // idle / loading（草稿尚未初始化）：不渲染表单。
  if (draft === null) {
    return (
      <p role="status" className={styles.loading}>
        {LOADING_TEXT}
      </p>
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>系统设置</Typography.Title>
      <Banner
        type="warning"
        className={styles.overwriteBanner}
        closeIcon={null}
        description={OVERWRITE_BANNER_TEXT}
      />
      {actionError !== null ? (
        <p role="alert" className={styles.actionError}>
          {actionError}
        </p>
      ) : null}
      {notice !== null ? (
        <p role="status" className={styles.notice}>
          {notice}
        </p>
      ) : null}
      <div className={styles.sections}>
        {SETTINGS_SECTIONS.map((section) => (
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
        <span className={styles.overwriteNote}>{OVERWRITE_NOTICE_TEXT}</span>
        <Button
          theme="solid"
          loading={submitting}
          disabled={submitting}
          onClick={() => {
            void submit();
          }}
        >
          保存设置
        </Button>
      </div>
    </section>
  );
}
