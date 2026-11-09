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
import { useState, type ReactNode } from 'react';
import {
  Banner,
  Button,
  Empty,
  Input,
  Modal,
  SideSheet,
  Spin,
  Toast,
  Typography,
} from '@douyinfe/semi-ui';
import { CopyButton } from '../../shared/components/CopyButton';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import {
  initialTableQuery,
  type TableQueryState,
} from '../../shared/app-ui/dataTableLogic';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { deriveRequestStatus } from '../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import { ConfirmActionButton } from '../components/ConfirmActionButton';
import { StringListEditor } from '../components/StringListEditor';
import type { SsoClient } from '../../gen/proto/api/admin/v1/client_pb';
import {
  adminReturnTo,
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
import styles from './SsoClientsPage.module.less';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/** 行键（SsoClient.id int64 → 十进制字符串，§1.12）。 */
function ssoClientRowKey(row: SsoClient): string {
  return row.id.toString();
}

/** SSO 客户端列表页：DataTable + 新建 / 查看 / 编辑 / 删除弹窗。 */
export function SsoClientsPage(_props: {
  /** 归一后 al_root（路由传参保留；401 跳登录收敛集中 onError，本页不再消费）。 */
  alRoot: string;
}): ReactNode {
  // §1.7 受控查询状态：分页 / 排序由 DataTable 上报更新。
  const [query, setQuery] = useState<TableQueryState>(initialTableQuery);
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // 列表取数改 ahooks 自动请求 + refreshDeps；401 由集中 onError
  // 跳登录，其余错误走页面错误帧（toast:false 静默防双报）。
  const { data, error, loading, refresh } = useRequest(
    () => listSsoClients(buildListSsoClientsRequest(query)),
    {
      refreshDeps: [query],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );
  // 写操作成功 / 失败反馈统一走 Semi Toast（校验文案经 throw 进 onError）；
  // 弹窗内不再自持错误态。
  // 新建弹窗（§5.5 行 1261：clientSecret 服务端生成，表单无密钥项）。
  const [createOpen, setCreateOpen] = useState(false);
  const [createDraft, setCreateDraft] = useState<SsoClientDraft>({
    clientId: '',
    name: '',
    redirectUris: [],
  });
  // 查看弹窗（GetSsoClient 明文密钥的唯一展示位）。
  const [viewId, setViewId] = useState<bigint | null>(null);
  // 弹窗详情手写三态收编 ahooks（manual，开弹窗即 run）；401 由集中
  // onError 跳登录，其余错误读 error 态行内呈现（toast:false 不弹 Toast）。
  // 重开旧数据残留用「data.id === viewId」条件渲染兜住（孪生口径，
  // OidcClientsPage 同改）。
  const viewReq = useRequest(getSsoClient, {
    manual: true,
    ...requestOptions({
      toast: false,
      returnTo: () => adminReturnTo(location.pathname, location.search),
    }),
  });
  // 编辑弹窗（§5.5 行 1262 PATCH 缺省保留）。
  const [editTarget, setEditTarget] = useState<SsoClient | null>(null);
  const [editDraft, setEditDraft] = useState<SsoClientPatchDraft>({
    newSecret: '',
    name: '',
    redirectUris: [],
  });
  // 打开编辑时的基线快照（dirty = 现值偏离基线，见 closeEdit）。
  const [editBaseline, setEditBaseline] = useState<SsoClientPatchDraft | null>(
    null,
  );

  /** 写操作后就地刷新当前页列表（ahooks refresh：按末次入参重发）。 */
  function refreshList(): void {
    refresh();
  }

  /** 打开新建弹窗：清空上次草稿。 */
  function openCreate(): void {
    setCreateDraft({ clientId: '', name: '', redirectUris: [] });
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
      editBaseline !== null &&
        JSON.stringify(editDraft) !== JSON.stringify(editBaseline),
      () => setEditTarget(null),
    );
  }

  /** 提交新建（§5.5 行 1261）：redirectUris 条目校验前置（§1.7 前端自律）。 */
  const { run: submitCreate, loading: createSubmitting } = useRequest(
    async () => {
      const issue = redirectUrisIssue(createDraft.redirectUris);
      if (issue !== null) {
        throw new Error(issue);
      }
      await createSsoClient(buildCreateSsoClientRequest(createDraft));
      setCreateOpen(false);
    },
    {
      manual: true,
      onSuccess: () => {
        Toast.success(t('admin.clientCreateSuccess'));
        // 后端缺省序 id DESC（orderClause 回落）：新行在第 1 页，回页可见。
        setQuery((prev) => ({ ...prev, page: 1 }));
      },
      onError: (err) => Toast.error(apiErrorText(err)),
    },
  );

  /**
   * 打开查看（§5.5 行 1262 GetSsoClient）：读取明文密钥；401 由集中 onError
   * 跳登录，其余错误在弹窗内行内提示（viewReq.error）。
   */
  function openView(row: SsoClient): void {
    setViewId(row.id);
    viewReq.run(buildGetSsoClientRequest(row.id));
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
  }

  /**
   * 提交编辑（§5.5 行 1262 PATCH）：空白名单阻断（后端空组 = 保留原值，
   * 清空提交不生效，前端自律拦截防误解）；密钥留空保留 / 非空轮换。
   * 校验 issue 经 throw 进 onError 出 Toast（与新建同口径）。
   */
  const { run: submitEdit, loading: editSubmitting } = useRequest(
    async (target: SsoClient) => {
      const uris = cleanStringList(editDraft.redirectUris);
      if (uris.length === 0) {
        throw new Error(t('admin.redirectUrisRequired'));
      }
      const issue = redirectUrisIssue(uris);
      if (issue !== null) {
        throw new Error(issue);
      }
      await updateSsoClient(
        buildUpdateSsoClientRequest(target.id, {
          ...editDraft,
          redirectUris: uris,
        }),
      );
      return target.clientId;
    },
    {
      manual: true,
      onSuccess: (clientId) => {
        setEditTarget(null);
        Toast.success(t('admin.clientUpdateSuccess', { clientId }));
        refreshList();
      },
      onError: (err) => Toast.error(apiErrorText(err)),
    },
  );

  // 列口径（§6 行 519 客户端 CRUD / 回调白名单）：客户端标识（可复制 + 可
  // 排序）/ 展示名 / 回调白名单（摘要，全量在详情）/ 创建 / 更新时间（可
  // 排序）/ 操作；可排序列 dataIndex 即 wire 列名（§1.7 sort 前端限定）。
  const columns: DataTableColumn<SsoClient>[] = [
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
      render: (_text: unknown, row: SsoClient) =>
        summarizeList(row.redirectUris),
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
          <ConfirmActionButton
            title={t('admin.clientDeleteConfirm', { clientId: row.clientId })}
            action={() => deleteSsoClient(buildDeleteSsoClientRequest(row.id))}
            onSuccess={() => {
              Toast.success(
                t('admin.clientDeleteSuccess', { clientId: row.clientId }),
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

  // 列表错误态（404 掩护等其余错误；401 由集中 onError 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (error !== undefined && !isUnauthenticatedError(error)) {
    return (
      <Banner
        type="danger"
        fullMode={false}
        description={t('admin.clientsLoadFailed')}
      />
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className="page-title">
        {t('admin.navSsoClients')}
      </Typography.Title>
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
        loading={loading}
        // 空态裸文字换 Semi Empty（默认插图 + 文案）；success 空态
        // 判定走 deriveRequestStatus 派生（§5.3，禁手写三条件）。
        empty={
          deriveRequestStatus(loading, error, data) === 'success' ? (
            <Empty description={t('admin.noClients')} />
          ) : undefined
        }
      />
      {/* SideSheet 无 Modal 的 onOk / okText / confirmLoading 族 props，
          只有 footer?: ReactNode → 提交 / 取消钮在此自管。 */}
      <SideSheet
        title={t('admin.createSsoClientTitle')}
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
              {t('admin.clientIdLabel')}
            </span>
            <Input
              value={createDraft.clientId}
              onChange={(value) =>
                setCreateDraft({ ...createDraft, clientId: value })
              }
              maxLength={CLIENT_ID_MAX_LEN}
              placeholder={t('admin.clientIdAutoGenPlaceholder')}
              aria-label={t('admin.clientIdLabel')}
              disabled={createSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.clientNameLabel')}
            </span>
            <Input
              value={createDraft.name}
              onChange={(value) =>
                setCreateDraft({ ...createDraft, name: value })
              }
              maxLength={CLIENT_NAME_MAX_LEN}
              placeholder={t('admin.clientNamePlaceholder')}
              aria-label={t('admin.clientNameLabel')}
              disabled={createSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.redirectUrisLabel')}
            </span>
            <span className={styles.fieldHint}>
              {t('admin.redirectUriEntryHint')}
            </span>
            <StringListEditor
              values={createDraft.redirectUris}
              onChange={(next) =>
                setCreateDraft({ ...createDraft, redirectUris: next })
              }
              disabled={createSubmitting}
              ariaLabel={t('admin.redirectUriAriaLabel')}
              addText={t('admin.addRedirectUri')}
              placeholder={t('admin.redirectUriPlaceholder')}
              emptyHint={t('admin.noRedirectUrisHint')}
            />
          </div>
        </div>
      </SideSheet>
      <Modal
        title={t('admin.clientDetailTitle')}
        visible={viewId !== null}
        onCancel={() => setViewId(null)}
        okButtonProps={{ style: { display: 'none' } }}
        cancelText={t('admin.cancelAction')}
      >
        {/* 三态帧：错误行内（非在途时）→ 加载 / 跨行重开旧数据
            残留兜 Spin（loading 或 data 非当前 viewId）→ 详情。 */}
        {viewReq.error !== undefined && !viewReq.loading ? (
          <p role="alert" className={styles.actionError}>
            {apiErrorText(viewReq.error)}
          </p>
        ) : viewReq.loading ||
          viewReq.data === undefined ||
          viewReq.data.id !== viewId ? (
          // 弹窗内加载裸文字换 Semi Spin。
          <div className={styles.stateCenter} role="status">
            <Spin />
          </div>
        ) : (
          <dl className={styles.detailList}>
            <dt>{t('admin.clientIdLabel')}</dt>
            <dd className={styles.detailValue}>
              <code className={styles.idCode}>{viewReq.data.clientId}</code>
              <CopyButton text={viewReq.data.clientId} />
            </dd>
            <dt>{t('admin.clientSecretLabel')}</dt>
            <dd className={styles.detailValue}>
              <code className={styles.idCode}>{viewReq.data.clientSecret}</code>
              <CopyButton text={viewReq.data.clientSecret} />
            </dd>
            <dt>{t('admin.clientNameLabel')}</dt>
            <dd>{viewReq.data.name || EMPTY_TEXT}</dd>
            <dt>{t('admin.redirectUrisLabel')}</dt>
            <dd>
              {viewReq.data.redirectUris.length > 0 ? (
                <ul className={styles.uriList}>
                  {viewReq.data.redirectUris.map((uri) => (
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
            <dd>{formatUnixTime(viewReq.data.createdAt)}</dd>
            <dt>{t('admin.updatedAtLabel')}</dt>
            <dd>{formatUnixTime(viewReq.data.updatedAt)}</dd>
          </dl>
        )}
      </Modal>
      <Modal
        title={
          editTarget !== null
            ? t('admin.editClientTitle', { clientId: editTarget.clientId })
            : t('admin.editClientFallbackTitle')
        }
        visible={editTarget !== null}
        onCancel={closeEdit}
        onOk={() => {
          if (editTarget !== null) {
            submitEdit(editTarget);
          }
        }}
        okText={t('admin.saveAction')}
        cancelText={t('admin.cancelAction')}
        confirmLoading={editSubmitting}
        cancelButtonProps={{ disabled: editSubmitting }}
        maskClosable={false}
      >
        <div className={styles.formBody}>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.clientIdLabel')}
            </span>
            <Input
              value={editTarget?.clientId ?? ''}
              disabled
              aria-label={t('admin.clientIdLabel')}
            />
            <span className={styles.fieldHint}>
              {t('admin.clientIdImmutable')}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.clientNameLabel')}
            </span>
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
            <span className={styles.fieldLabel}>
              {t('admin.newSecretLabel')}
            </span>
            <Input
              mode="password"
              value={editDraft.newSecret}
              onChange={(value) =>
                setEditDraft({ ...editDraft, newSecret: value })
              }
              placeholder={t('admin.newSecretPlaceholder')}
              aria-label={t('admin.newSecretLabel')}
              autoComplete="new-password"
              disabled={editSubmitting}
            />
            <span className={styles.fieldHint}>
              {t('admin.secretRotateHint')}
            </span>
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>
              {t('admin.redirectUrisLabel')}
            </span>
            <span className={styles.fieldHint}>
              {t('admin.redirectUriEntryHint')}
            </span>
            <StringListEditor
              values={editDraft.redirectUris}
              onChange={(next) =>
                setEditDraft({ ...editDraft, redirectUris: next })
              }
              disabled={editSubmitting}
              ariaLabel={t('admin.redirectUriAriaLabel')}
              addText={t('admin.addRedirectUri')}
              placeholder={t('admin.redirectUriPlaceholder')}
            />
          </div>
        </div>
      </Modal>
    </section>
  );
}
