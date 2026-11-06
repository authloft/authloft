/**
 * SSO 客户端列表页（docs/前端架构.md §6 行 519；docs/接口文档.md §5.5 行
 * 1257-1268；docs/需求.md §4.6 行 257）——/admin/clients/sso。
 *
 * SSO 客户端 CRUD + 回调白名单管理（redirectUris[] 支持 * 通配、整段匹配
 * §12.3；仅后台手动创建 §5.5 行 1266）：
 * - 列表：DataTable 服务端分页 + 排序（可排序列 dataIndex 即 wire 列名，
 *   §1.7 sort 由前端限定 + 后端 orderClause ^[a-z0-9_]+$，既定口径）；
 * - 新建：clientId 留空服务端生成；clientSecret 由服务端生成（请求不带，
 *   后端忽略同名字段），成功后回第 1 页（后端缺省序 id DESC）；
 * - 查看：GetSsoClient 返回明文 client_secret（§5.2 行 1170 凭证口径，
 *   全站唯一明文出口），详情弹窗内 CopyButton 可复制；
 * - 编辑：PATCH 缺省保留——clientId 创建后不可改（只读展示）、新密钥留空
 *   保留 / 非空轮换、回调白名单空组 = 保留原值（前端阻断防误解）；
 * - 删除：Popconfirm 确认，硬删不可恢复。
 *
 * 401 统一跳登录（§6 行 501，UsersPage 同模式；详情读取同口径）；404 掩护
 * 等其余错误走页面错误态（Semi Banner）。写操作成功 / 失败 Toast 提示
 * （Modal 内表单错误保持行内）。组件壳 import Semi 后不可在 node
 * 测试（工具链 blocker），可测逻辑
 * 全部收口在 ./api（请求构造 / 校验 / 展示纯函数）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Banner, Button, Empty, Input, Modal, Popconfirm, Spin, Toast, Typography } from '@douyinfe/semi-ui-19';
import { CopyButton } from '../../shared/components/CopyButton';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import { initialTableQuery, type TableQueryState } from '../../shared/app-ui/dataTableLogic';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import { StringListEditor } from '../components/StringListEditor';
import type { SsoClient } from '../../gen/proto/api/admin/v1/client_pb';
import {
  CLIENT_ID_MAX_LEN,
  CLIENT_NAME_MAX_LEN,
  apiErrorText,
  buildCreateSsoClientRequest,
  buildDeleteSsoClientRequest,
  buildGetSsoClientRequest,
  buildListSsoClientsRequest,
  buildUpdateSsoClientRequest,
  cleanStringList,
  createSsoClient,
  deleteSsoClient,
  formatUnixTime,
  getSsoClient,
  isUnauthenticatedError,
  listSsoClients,
  redirectUrisIssue,
  summarizeList,
  updateSsoClient,
  type SsoClientDraft,
  type SsoClientPatchDraft,
} from '../api';
import { loginUrl } from '../bootstrap';
import styles from './SsoClientsPage.module.less';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/** 行键（SsoClient.id int64 → 十进制字符串，§1.12）。 */
function ssoClientRowKey(row: SsoClient): string {
  return row.id.toString();
}

/** SSO 客户端列表页：DataTable + 新建 / 查看 / 编辑 / 删除弹窗。 */
export function SsoClientsPage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  // §1.7 受控查询状态：分页 / 排序由 DataTable 上报更新。
  const [query, setQuery] = useState<TableQueryState>(initialTableQuery);
  const { status, data, error, run } = useRequest(listSsoClients);
  // 写操作成功 / 删除失败反馈统一走 Semi Toast（原就地 notice /
  // actionError 文字已随 Semi 回归移除）；Modal 内表单错误保持行内。
  // 新建弹窗（§5.5 行 1261：clientSecret 服务端生成，表单无密钥项）。
  const [createOpen, setCreateOpen] = useState(false);
  const [createDraft, setCreateDraft] = useState<SsoClientDraft>({
    clientId: '',
    name: '',
    redirectUris: [],
  });
  const [createError, setCreateError] = useState<string | null>(null);
  const [createSubmitting, setCreateSubmitting] = useState(false);
  // 查看弹窗（GetSsoClient 明文密钥的唯一展示位）。
  const [viewId, setViewId] = useState<bigint | null>(null);
  const [viewDetail, setViewDetail] = useState<SsoClient | null>(null);
  const [viewLoading, setViewLoading] = useState(false);
  const [viewError, setViewError] = useState<string | null>(null);
  // 编辑弹窗（§5.5 行 1262 PATCH 缺省保留）。
  const [editTarget, setEditTarget] = useState<SsoClient | null>(null);
  const [editDraft, setEditDraft] = useState<SsoClientPatchDraft>({
    newSecret: '',
    name: '',
    redirectUris: [],
  });
  // 打开编辑时的基线快照（dirty = 现值偏离基线，见 closeEdit）。
  const [editBaseline, setEditBaseline] = useState<SsoClientPatchDraft | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const [editSubmitting, setEditSubmitting] = useState(false);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run(buildListSsoClientsRequest(query)).catch(() => {});
  }, [run, query]);

  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, props.alRoot]);

  /** 写操作后就地刷新当前页列表。 */
  function refreshList(): void {
    run(buildListSsoClientsRequest(query)).catch(() => {});
  }

  /** 打开新建弹窗：清空上次草稿 / 错误。 */
  function openCreate(): void {
    setCreateDraft({ clientId: '', name: '', redirectUris: [] });
    setCreateError(null);
    setCreateOpen(true);
  }

  /**
   * 编辑未保存保护：有未保存改动（dirty）时经 Semi Modal.confirm
   * 二次确认后执行 close；无改动直接关闭。dirty 由现值与打开时基线的
   * 序列化对比判定（表单为扁平字符串 / 字符串数组结构，对比无损）。
   */
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

  /** 关闭新建弹窗（草稿有任一改动时需确认；基线 = 打开时的空草稿）。 */
  function closeCreate(): void {
    confirmCloseIfDirty(
      JSON.stringify(createDraft) !==
        JSON.stringify({ clientId: '', name: '', redirectUris: [] }),
      () => setCreateOpen(false),
    );
  }

  /** 关闭编辑弹窗（现值相对打开时基线有改动时需确认）。 */
  function closeEdit(): void {
    confirmCloseIfDirty(
      editBaseline !== null && JSON.stringify(editDraft) !== JSON.stringify(editBaseline),
      () => setEditTarget(null),
    );
  }

  /** 提交新建（§5.5 行 1261）：redirectUris 条目校验前置（§1.7 前端自律）。 */
  async function submitCreate(): Promise<void> {
    if (createSubmitting) {
      return;
    }
    const issue = redirectUrisIssue(createDraft.redirectUris);
    if (issue !== null) {
      setCreateError(issue);
      return;
    }
    setCreateSubmitting(true);
    try {
      await createSsoClient(buildCreateSsoClientRequest(createDraft));
      setCreateOpen(false);
      Toast.success(t('admin.clientCreateSuccess'));
      // 后端缺省序 id DESC（orderClause 回落）：新行在第 1 页，回页可见。
      setQuery((prev) => ({ ...prev, page: 1 }));
    } catch (err) {
      setCreateError(apiErrorText(err));
    } finally {
      setCreateSubmitting(false);
    }
  }

  /**
   * 打开查看（§5.5 行 1262 GetSsoClient）：读取明文密钥；401 与列表同口径
   * 跳登录，其余错误在弹窗内提示。
   */
  function openView(row: SsoClient): void {
    setViewId(row.id);
    setViewDetail(null);
    setViewError(null);
    setViewLoading(true);
    getSsoClient(buildGetSsoClientRequest(row.id))
      .then((detail) => {
        setViewDetail(detail);
      })
      .catch((err) => {
        if (isUnauthenticatedError(err)) {
          window.location.replace(loginUrl(props.alRoot));
          return;
        }
        setViewError(apiErrorText(err));
      })
      .finally(() => {
        setViewLoading(false);
      });
  }

  /** 打开编辑弹窗：clientId 只读展示（创建后不可改），草稿按行现值回填。 */
  function openEdit(row: SsoClient): void {
    const baseline: SsoClientPatchDraft = {
      newSecret: '',
      name: row.name,
      redirectUris: [...row.redirectUris],
    };
    setEditTarget(row);
    setEditDraft(baseline);
    setEditBaseline(baseline); // dirty 判定基线。
    setEditError(null);
  }

  /**
   * 提交编辑（§5.5 行 1262 PATCH）：空白名单阻断（后端空组 = 保留原值，
   * 清空提交不生效，前端自律拦截防误解）；密钥留空保留 / 非空轮换。
   */
  async function submitEdit(): Promise<void> {
    const target = editTarget;
    if (target === null || editSubmitting) {
      return;
    }
    const uris = cleanStringList(editDraft.redirectUris);
    if (uris.length === 0) {
      setEditError(t('admin.redirectUrisRequired'));
      return;
    }
    const issue = redirectUrisIssue(uris);
    if (issue !== null) {
      setEditError(issue);
      return;
    }
    setEditSubmitting(true);
    try {
      await updateSsoClient(
        buildUpdateSsoClientRequest(target.id, { ...editDraft, redirectUris: uris }),
      );
      setEditTarget(null);
      Toast.success(t('admin.clientUpdateSuccess', { clientId: target.clientId }));
      refreshList();
    } catch (err) {
      setEditError(apiErrorText(err));
    } finally {
      setEditSubmitting(false);
    }
  }

  /** 删除（§5.5 行 1262 硬删）：Popconfirm 确认后调用。 */
  async function handleDelete(row: SsoClient): Promise<void> {
    try {
      await deleteSsoClient(buildDeleteSsoClientRequest(row.id));
      Toast.success(t('admin.clientDeleteSuccess', { clientId: row.clientId }));
      refreshList();
    } catch (err) {
      Toast.error(apiErrorText(err));
    }
  }

  // 列口径（§6 行 519 客户端 CRUD / 回调白名单）：客户端标识（可复制 + 可
  // 排序）/ 展示名 / 回调白名单（摘要，全量在详情）/ 创建 / 更新时间（可
  // 排序）/ 操作；可排序列 dataIndex 即 wire 列名（§1.7 sort 前端限定）。
  const columns: readonly DataTableColumn<SsoClient>[] = [
    {
      dataIndex: 'client_id',
      title: t('admin.clientIdLabel'),
      sorter: true,
      render: (_text: unknown, row: SsoClient) => (
        <span className={styles.idCell}>
          <code className={styles.idCode}>{row.clientId}</code>
          <CopyButton text={row.clientId} />
        </span>
      ),
    },
    {
      dataIndex: 'name',
      title: t('admin.clientNameLabel'),
      render: (_text: unknown, row: SsoClient) => row.name || EMPTY_TEXT,
    },
    {
      dataIndex: 'redirect_uris',
      title: t('admin.redirectUrisLabel'),
      render: (_text: unknown, row: SsoClient) => summarizeList(row.redirectUris),
    },
    {
      dataIndex: 'created_at',
      title: t('admin.createdAtLabel'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: SsoClient) => formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'updated_at',
      title: t('admin.updatedAtLabel'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: SsoClient) => formatUnixTime(row.updatedAt),
    },
    {
      dataIndex: 'actions',
      title: t('admin.actionsLabel'),
      render: (_text: unknown, row: SsoClient) => (
        <span className={styles.actions}>
          <Button size="small" onClick={() => openView(row)}>
            {t('admin.viewAction')}
          </Button>
          <Button size="small" onClick={() => openEdit(row)}>
            {t('admin.editAction')}
          </Button>
          <Popconfirm
            title={t('admin.clientDeleteConfirm', { clientId: row.clientId })}
            onConfirm={() => {
              void handleDelete(row);
            }}
          >
            <Button size="small">{t('admin.removeAction')}</Button>
          </Popconfirm>
        </span>
      ),
    },
  ];

  // 列表错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
    return <Banner type="danger" fullMode={false} description={t('admin.clientsLoadFailed')} />;
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>{t('admin.navSsoClients')}</Typography.Title>
      <div className={styles.toolbar}>
        <Button theme="solid" onClick={openCreate}>
          {t('admin.createClientAction')}
        </Button>
      </div>
      <DataTable<SsoClient>
        columns={columns}
        rows={data?.items ?? []}
        rowKey={ssoClientRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={status === 'loading'}
        // 空态裸文字换 Semi Empty（默认插图 + 文案）。
        empty={status === 'success' ? <Empty description={t('admin.noClients')} /> : undefined}
      />
      <Modal
        title={t('admin.createSsoClientTitle')}
        visible={createOpen}
        onCancel={closeCreate}
        maskClosable={false}
        footer={null}
      >
        <div className={styles.formBody}>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.clientIdLabel')}</span>
            <Input
              value={createDraft.clientId}
              onChange={(value) => setCreateDraft({ ...createDraft, clientId: value })}
              maxLength={CLIENT_ID_MAX_LEN}
              placeholder={t('admin.clientIdAutoGenPlaceholder')}
              aria-label={t('admin.clientIdLabel')}
              disabled={createSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.clientNameLabel')}</span>
            <Input
              value={createDraft.name}
              onChange={(value) => setCreateDraft({ ...createDraft, name: value })}
              maxLength={CLIENT_NAME_MAX_LEN}
              placeholder={t('admin.clientNamePlaceholder')}
              aria-label={t('admin.clientNameLabel')}
              disabled={createSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.redirectUrisLabel')}</span>
            <span className={styles.fieldHint}>{t('admin.redirectUriEntryHint')}</span>
            <StringListEditor
              values={createDraft.redirectUris}
              onChange={(next) => setCreateDraft({ ...createDraft, redirectUris: next })}
              disabled={createSubmitting}
              ariaLabel={t('admin.redirectUriAriaLabel')}
              addText={t('admin.addRedirectUri')}
              placeholder={t('admin.redirectUriPlaceholder')}
              emptyHint={t('admin.noRedirectUrisHint')}
            />
          </div>
          {createError !== null ? (
            <p role="alert" className={styles.actionError}>
              {createError}
            </p>
          ) : null}
          <div className={styles.formFooter}>
            <Button onClick={closeCreate} disabled={createSubmitting}>
              {t('admin.cancelAction')}
            </Button>
            <Button
              theme="solid"
              onClick={() => {
                void submitCreate();
              }}
              disabled={createSubmitting}
              loading={createSubmitting}
            >
              {t('admin.createAction')}
            </Button>
          </div>
        </div>
      </Modal>
      <Modal
        title={t('admin.clientDetailTitle')}
        visible={viewId !== null}
        onCancel={() => setViewId(null)}
        footer={null}
      >
        {viewLoading ? (
          // 弹窗内加载裸文字换 Semi Spin。
          <div className={styles.stateCenter} role="status">
            <Spin />
          </div>
        ) : viewError !== null ? (
          <p role="alert" className={styles.actionError}>
            {viewError}
          </p>
        ) : viewDetail !== null ? (
          <dl className={styles.detailList}>
            <dt>{t('admin.clientIdLabel')}</dt>
            <dd className={styles.detailValue}>
              <code className={styles.idCode}>{viewDetail.clientId}</code>
              <CopyButton text={viewDetail.clientId} />
            </dd>
            <dt>{t('admin.clientSecretLabel')}</dt>
            <dd className={styles.detailValue}>
              <code className={styles.idCode}>{viewDetail.clientSecret}</code>
              <CopyButton text={viewDetail.clientSecret} />
            </dd>
            <dt>{t('admin.clientNameLabel')}</dt>
            <dd>{viewDetail.name || EMPTY_TEXT}</dd>
            <dt>{t('admin.redirectUrisLabel')}</dt>
            <dd>
              {viewDetail.redirectUris.length > 0 ? (
                <ul className={styles.uriList}>
                  {viewDetail.redirectUris.map((uri) => (
                    <li key={uri}>
                      <code>{uri}</code>
                    </li>
                  ))}
                </ul>
              ) : (
                EMPTY_TEXT
              )}
            </dd>
            <dt>{t('admin.createdAtLabel')}</dt>
            <dd>{formatUnixTime(viewDetail.createdAt)}</dd>
            <dt>{t('admin.updatedAtLabel')}</dt>
            <dd>{formatUnixTime(viewDetail.updatedAt)}</dd>
          </dl>
        ) : null}
      </Modal>
      <Modal
        title={
          editTarget !== null
            ? t('admin.editClientTitle', { clientId: editTarget.clientId })
            : t('admin.editClientFallbackTitle')
        }
        visible={editTarget !== null}
        onCancel={closeEdit}
        maskClosable={false}
        footer={null}
      >
        <div className={styles.formBody}>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.clientIdLabel')}</span>
            <Input value={editTarget?.clientId ?? ''} disabled aria-label={t('admin.clientIdLabel')} />
            <span className={styles.fieldHint}>{t('admin.clientIdImmutable')}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.clientNameLabel')}</span>
            <Input
              value={editDraft.name}
              onChange={(value) => setEditDraft({ ...editDraft, name: value })}
              maxLength={CLIENT_NAME_MAX_LEN}
              placeholder={t('admin.clientNamePlaceholder')}
              aria-label={t('admin.clientNameLabel')}
              disabled={editSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.newSecretLabel')}</span>
            <Input
              mode="password"
              value={editDraft.newSecret}
              onChange={(value) => setEditDraft({ ...editDraft, newSecret: value })}
              placeholder={t('admin.newSecretPlaceholder')}
              aria-label={t('admin.newSecretLabel')}
              autoComplete="new-password"
              disabled={editSubmitting}
            />
            <span className={styles.fieldHint}>{t('admin.secretRotateHint')}</span>
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.redirectUrisLabel')}</span>
            <span className={styles.fieldHint}>{t('admin.redirectUriEntryHint')}</span>
            <StringListEditor
              values={editDraft.redirectUris}
              onChange={(next) => setEditDraft({ ...editDraft, redirectUris: next })}
              disabled={editSubmitting}
              ariaLabel={t('admin.redirectUriAriaLabel')}
              addText={t('admin.addRedirectUri')}
              placeholder={t('admin.redirectUriPlaceholder')}
            />
          </div>
          {editError !== null ? (
            <p role="alert" className={styles.actionError}>
              {editError}
            </p>
          ) : null}
          <div className={styles.formFooter}>
            <Button onClick={closeEdit} disabled={editSubmitting}>
              {t('admin.cancelAction')}
            </Button>
            <Button
              theme="solid"
              onClick={() => {
                void submitEdit();
              }}
              disabled={editSubmitting}
              loading={editSubmitting}
            >
              {t('admin.saveAction')}
            </Button>
          </div>
        </div>
      </Modal>
    </section>
  );
}
