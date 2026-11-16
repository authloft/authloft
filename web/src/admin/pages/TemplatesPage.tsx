/**
 * 模板管理页（接口文档 §5.7；前端架构 §6）——/admin/templates。
 *
 * DB 自定义模板 CRUD：列表只含自定义模板行（内置模板由后端启动扫描全集
 * 常驻内存、不进本接口），新建 / 编辑 / 删除三个 Modal。content 是 HTML
 * 原文，用 Semi TextArea 编辑（autosize + 等宽，非富文本）；template_key
 * 创建后不可改（编辑只读，对齐 client_id 口径），提交前经 api 层纯函数
 * 预检非空 / 长度 / 不与内置或既有 key 同名。删除走 Popconfirm 二次确认。
 *
 * 401 统一跳登录（集中 requestOptions onError），其余错误走页面 Banner；
 * 写操作反馈走 Toast。组件壳 import Semi 后不可在 node 测试，可测逻辑
 * 全部收口在 ../api（请求构造 / 校验 / 展示纯函数）。
 * 样式（前端架构 §1.7）：同目录同名 module less。
 */
import { useState, type ReactNode } from 'react';
import {
  Banner,
  Button,
  Empty,
  Input,
  Modal,
  SideSheet,
  TextArea,
  Toast,
  Typography,
} from '@douyinfe/semi-ui';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import {
  initialTableQuery,
  type TableQueryState,
} from '../../shared/app-ui/dataTableLogic';
import { deriveRequestStatus } from '../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import type { Template } from '../../gen/proto/api/admin/v1/template_pb';
import { ConfirmActionButton } from '../components/ConfirmActionButton';
import {
  adminReturnTo,
  apiErrorText,
  buildCreateTemplateRequest,
  buildDeleteTemplateRequest,
  buildListTemplatesRequest,
  buildUpdateTemplateRequest,
  createTemplate,
  deleteTemplate,
  formatUnixTime,
  isUnauthenticatedError,
  listTemplates,
  templateDraftFromRow,
  templateKeyIssue,
  updateTemplate,
  TEMPLATE_KEY_MAX_LEN,
  type TemplateDraft,
} from '../api';
import styles from './TemplatesPage.module.less';

/** 零值占位（protojson 省略零值 → 解码为空串）。 */
const EMPTY_TEXT = '—';

/** 新建草稿初值（模板 key / 显示名 / HTML 原文均空）。 */
function initialDraft(): TemplateDraft {
  return { templateKey: '', name: '', content: '' };
}

/** 行键（Template.id int64 → 十进制字符串）。 */
function templateRowKey(row: Template): string {
  return row.id.toString();
}

/** 模板管理列表页：DataTable + 新建 / 编辑 / 删除弹窗。 */
export function TemplatesPage(_props: {
  /** 归一后 al_root（路由传参保留；401 跳登录收敛集中 onError）。 */
  alRoot: string;
}): ReactNode {
  const [query, setQuery] = useState<TableQueryState>(initialTableQuery);
  const [qDraft, setQDraft] = useState('');
  const [appliedQ, setAppliedQ] = useState('');
  const location = useLocation();
  // 列表：ahooks 自动请求 + refreshDeps；401 由集中 onError 跳登录，
  // 其余错误走页面错误帧（toast:false 静默防双报）。
  const { data, error, loading, refresh } = useRequest(
    () => listTemplates(buildListTemplatesRequest(appliedQ, query)),
    {
      refreshDeps: [appliedQ, query],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );

  const [createOpen, setCreateOpen] = useState(false);
  const [createDraft, setCreateDraft] = useState<TemplateDraft>(initialDraft);
  const [editTarget, setEditTarget] = useState<Template | null>(null);
  const [editDraft, setEditDraft] = useState<TemplateDraft>(initialDraft);
  const [editBaseline, setEditBaseline] = useState<TemplateDraft | null>(null);

  /** 当前页既有 key（新建时唯一性预检；后端 UK 为最终权威）。 */
  const existingKeys: string[] = (data?.items ?? []).map(
    (item) => item.templateKey,
  );

  /** 写操作后就地刷新当前页（ahooks refresh：按末次入参重发）。 */
  function refreshList(): void {
    refresh();
  }

  /** 应用搜索：按显示名模糊筛选，回第 1 页。 */
  function applySearch(): void {
    setAppliedQ(qDraft.trim());
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  function openCreate(): void {
    setCreateDraft(initialDraft());
    setCreateOpen(true);
  }

  /** 未保存改动确认（SsoClientsPage 同口径：基线序列化对比）。 */
  function confirmCloseIfDirty(dirty: boolean, close: () => void): void {
    if (dirty) {
      Modal.confirm({
        title: t('admin.unsavedChangesTitle'),
        content: t('admin.unsavedChangesContent'),
        onOk: close,
      });
      return;
    }
    close();
  }

  function closeCreate(): void {
    confirmCloseIfDirty(
      JSON.stringify(createDraft) !== JSON.stringify(initialDraft()),
      () => setCreateOpen(false),
    );
  }

  function closeEdit(): void {
    confirmCloseIfDirty(
      editBaseline !== null &&
        JSON.stringify(editDraft) !== JSON.stringify(editBaseline),
      () => setEditTarget(null),
    );
  }

  function openEdit(row: Template): void {
    const baseline = templateDraftFromRow(row);
    setEditTarget(row);
    setEditDraft(baseline);
    setEditBaseline(baseline);
  }

  /** 表单必填项（HTML 原文按原文提交，空白视为未提供）。 */
  function checkContent(draft: TemplateDraft): boolean {
    return draft.name.trim() !== '' && draft.content.trim() !== '';
  }

  /** 提交新建：key 预检 + 必填项前置，校验文案经 throw 进 onError 出 Toast。 */
  const { run: submitCreate, loading: createSubmitting } = useRequest(
    async () => {
      const issue = templateKeyIssue(createDraft.templateKey, existingKeys);
      if (issue !== null) {
        throw new Error(issue);
      }
      if (!checkContent(createDraft)) {
        throw new Error(t('admin.validateRequired'));
      }
      await createTemplate(buildCreateTemplateRequest(createDraft));
    },
    {
      manual: true,
      onSuccess: () => {
        Toast.success(t('admin.templateCreateSuccess'));
        setCreateOpen(false);
        setQuery((prev) => ({ ...prev, page: 1 }));
      },
      onError: (err) => Toast.error(apiErrorText(err)),
    },
  );

  /** 提交编辑（PATCH）：key 只读不下发，name / content 必填。 */
  const { run: submitEdit, loading: editSubmitting } = useRequest(
    async () => {
      if (!checkContent(editDraft)) {
        throw new Error(t('admin.validateRequired'));
      }
      await updateTemplate(
        buildUpdateTemplateRequest(editTarget?.id ?? BigInt(0), editDraft),
      );
      return editDraft.name.trim();
    },
    {
      manual: true,
      onSuccess: (name) => {
        setEditTarget(null);
        Toast.success(t('admin.templateUpdateSuccess', { name }));
        refreshList();
      },
      onError: (err) => Toast.error(apiErrorText(err)),
    },
  );

  const columns: DataTableColumn<Template>[] = [
    {
      dataIndex: 'template_key',
      title: t('admin.templateKeyLabel'),
      sorter: true,
      render: (_text: unknown, row: Template) => (
        <code className={styles.idCode}>{row.templateKey}</code>
      ),
    },
    {
      dataIndex: 'name',
      title: t('admin.templateNameLabel'),
      sorter: true,
      render: (_text: unknown, row: Template) => row.name || EMPTY_TEXT,
    },
    {
      dataIndex: 'created_at',
      title: t('admin.createdAtLabel'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: Template) => formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'updated_at',
      title: t('admin.updatedAtLabel'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: Template) => formatUnixTime(row.updatedAt),
    },
    {
      dataIndex: 'actions',
      title: t('admin.actionsLabel'),
      render: (_text: unknown, row: Template) => (
        <span className={styles.actions}>
          <Button size="small" onClick={() => openEdit(row)}>
            {t('admin.editAction')}
          </Button>
          <ConfirmActionButton
            title={t('admin.templateDeleteConfirm', { name: row.name })}
            action={() => deleteTemplate(buildDeleteTemplateRequest(row.id))}
            onSuccess={() => {
              Toast.success(
                t('admin.templateDeleteSuccess', { name: row.name }),
              );
              refreshList();
            }}
          >
            {t('admin.removeAction')}
          </ConfirmActionButton>
        </span>
      ),
    },
  ];

  // 列表错误态（401 由集中 onError 跳登录，其余错误走页面 Banner）。
  if (error !== undefined && !isUnauthenticatedError(error)) {
    return (
      <Banner
        type="danger"
        fullMode={false}
        description={t('admin.templatesLoadFailed')}
      />
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className="page-title">
        {t('admin.navTemplates')}
      </Typography.Title>
      <div className={styles.toolbar}>
        <Input
          className={styles.searchInput}
          value={qDraft}
          onChange={setQDraft}
          onEnterPress={applySearch}
          placeholder={t('admin.templateSearchPlaceholder')}
          aria-label={t('admin.templateSearchAriaLabel')}
          disabled={loading}
        />
        <Button onClick={applySearch} disabled={loading}>
          {t('admin.searchAction')}
        </Button>
        <Button theme="solid" onClick={openCreate}>
          {t('admin.createTemplateAction')}
        </Button>
      </div>
      <DataTable<Template>
        columns={columns}
        rows={data?.items ?? []}
        rowKey={templateRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={loading}
        empty={
          deriveRequestStatus(loading, error, data) === 'success' ? (
            <Empty description={t('admin.noTemplates')} />
          ) : undefined
        }
      />
      <SideSheet
        title={t('admin.createTemplateTitle')}
        visible={createOpen}
        onCancel={closeCreate}
        maskClosable={false}
        footer={
          <div className={styles.formFooter}>
            <Button
              type="tertiary"
              onClick={closeCreate}
              disabled={createSubmitting}
            >
              {t('admin.cancelAction')}
            </Button>
            <Button
              theme="solid"
              loading={createSubmitting}
              disabled={createSubmitting}
              onClick={() => {
                submitCreate();
              }}
            >
              {t('admin.createAction')}
            </Button>
          </div>
        }
      >
        <div className={styles.formBody}>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.templateKeyLabel')}
            </span>
            <Input
              value={createDraft.templateKey}
              onChange={(value) =>
                setCreateDraft({ ...createDraft, templateKey: value })
              }
              maxLength={TEMPLATE_KEY_MAX_LEN}
              placeholder={t('admin.templateKeyPlaceholder')}
              aria-label={t('admin.templateKeyLabel')}
              disabled={createSubmitting}
            />
            <span className={styles.fieldHint}>
              {t('admin.templateContentHint')}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.templateNameLabel')}
            </span>
            <Input
              value={createDraft.name}
              onChange={(value) =>
                setCreateDraft({ ...createDraft, name: value })
              }
              placeholder={t('admin.templateNamePlaceholder')}
              aria-label={t('admin.templateNameLabel')}
              disabled={createSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.templateContentLabel')}
            </span>
            <TextArea
              className={styles.contentArea}
              value={createDraft.content}
              onChange={(value) =>
                setCreateDraft({ ...createDraft, content: value })
              }
              autosize={{ minRows: 8, maxRows: 24 }}
              aria-label={t('admin.templateContentLabel')}
              disabled={createSubmitting}
            />
          </div>
        </div>
      </SideSheet>
      <SideSheet
        title={t('admin.editTemplateTitle', {
          name: editTarget?.name ?? EMPTY_TEXT,
        })}
        visible={editTarget !== null}
        onCancel={closeEdit}
        maskClosable={false}
        footer={
          <div className={styles.formFooter}>
            <Button
              type="tertiary"
              onClick={closeEdit}
              disabled={editSubmitting}
            >
              {t('admin.cancelAction')}
            </Button>
            <Button
              theme="solid"
              loading={editSubmitting}
              disabled={editSubmitting}
              onClick={() => {
                submitEdit();
              }}
            >
              {t('admin.saveAction')}
            </Button>
          </div>
        }
      >
        <div className={styles.formBody}>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.templateKeyLabel')}
            </span>
            <Input
              value={editDraft.templateKey}
              disabled
              aria-label={t('admin.templateKeyLabel')}
            />
            <span className={styles.fieldHint}>
              {t('admin.templateKeyImmutable')}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.templateNameLabel')}
            </span>
            <Input
              value={editDraft.name}
              onChange={(value) => setEditDraft({ ...editDraft, name: value })}
              placeholder={t('admin.templateNamePlaceholder')}
              aria-label={t('admin.templateNameLabel')}
              disabled={editSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.templateContentLabel')}
            </span>
            <TextArea
              className={styles.contentArea}
              value={editDraft.content}
              onChange={(value) =>
                setEditDraft({ ...editDraft, content: value })
              }
              autosize={{ minRows: 8, maxRows: 24 }}
              aria-label={t('admin.templateContentLabel')}
              disabled={editSubmitting}
            />
          </div>
        </div>
      </SideSheet>
    </section>
  );
}
