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
 * 等其余错误走页面错误态。写操作失败就地提示（UsersPage 消费方口径）。
 * 组件壳 import Semi 后不可在 node 测试（工具链 blocker），可测逻辑
 * 全部收口在 ./api（请求构造 / 校验 / 展示纯函数）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Button, Input, Modal, Popconfirm, Typography } from '@douyinfe/semi-ui-19';
import { CopyButton } from '../../shared/components/CopyButton';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import { initialTableQuery, type TableQueryState } from '../../shared/app-ui/dataTableLogic';
import { useRequest } from '../../shared/hooks/useRequest';
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

/** 详情加载态文案。 */
const VIEW_LOADING_TEXT = '加载中…';

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
  // 写操作反馈就地展示（删除 / 新建 / 编辑的失败与成功提示）。
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
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
      setNotice('客户端创建成功，密钥由服务端生成，点击「查看」即可获取');
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
    setEditTarget(row);
    setEditDraft({
      newSecret: '',
      name: row.name,
      redirectUris: [...row.redirectUris],
    });
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
      setEditError('回调白名单不能为空（清空后保存将保留原值）');
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
      setNotice(`已更新客户端「${target.clientId}」`);
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
      setNotice(`已删除客户端「${row.clientId}」`);
      refreshList();
    } catch (err) {
      setActionError(apiErrorText(err));
    }
  }

  // 列口径（§6 行 519 客户端 CRUD / 回调白名单）：客户端标识（可复制 + 可
  // 排序）/ 展示名 / 回调白名单（摘要，全量在详情）/ 创建 / 更新时间（可
  // 排序）/ 操作；可排序列 dataIndex 即 wire 列名（§1.7 sort 前端限定）。
  const columns: readonly DataTableColumn<SsoClient>[] = [
    {
      dataIndex: 'client_id',
      title: '客户端标识',
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
      title: '展示名',
      render: (_text: unknown, row: SsoClient) => row.name || EMPTY_TEXT,
    },
    {
      dataIndex: 'redirect_uris',
      title: '回调白名单',
      render: (_text: unknown, row: SsoClient) => summarizeList(row.redirectUris),
    },
    {
      dataIndex: 'created_at',
      title: '创建时间',
      width: 170,
      sorter: true,
      render: (_text: unknown, row: SsoClient) => formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'updated_at',
      title: '更新时间',
      width: 170,
      sorter: true,
      render: (_text: unknown, row: SsoClient) => formatUnixTime(row.updatedAt),
    },
    {
      dataIndex: 'actions',
      title: '操作',
      render: (_text: unknown, row: SsoClient) => (
        <span className={styles.actions}>
          <Button size="small" onClick={() => openView(row)}>
            查看
          </Button>
          <Button size="small" onClick={() => openEdit(row)}>
            编辑
          </Button>
          <Popconfirm
            title={`确定删除客户端「${row.clientId}」？删除后不可恢复`}
            onConfirm={() => {
              void handleDelete(row);
            }}
          >
            <Button size="small">删除</Button>
          </Popconfirm>
        </span>
      ),
    },
  ];

  // 列表错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
    return (
      <p role="alert" className={styles.loadError}>
        客户端列表加载失败，请刷新重试
      </p>
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>SSO 客户端</Typography.Title>
      <div className={styles.toolbar}>
        <Button theme="solid" onClick={openCreate}>
          新建客户端
        </Button>
      </div>
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
      <DataTable<SsoClient>
        columns={columns}
        rows={data?.items ?? []}
        rowKey={ssoClientRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={status === 'loading'}
        empty={status === 'success' ? '暂无客户端' : undefined}
      />
      <Modal
        title="新建 SSO 客户端"
        visible={createOpen}
        onCancel={() => setCreateOpen(false)}
        footer={null}
      >
        <div className={styles.formBody}>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>客户端标识</span>
            <Input
              value={createDraft.clientId}
              onChange={(value) => setCreateDraft({ ...createDraft, clientId: value })}
              maxLength={CLIENT_ID_MAX_LEN}
              placeholder="留空自动生成"
              aria-label="客户端标识"
              disabled={createSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>展示名</span>
            <Input
              value={createDraft.name}
              onChange={(value) => setCreateDraft({ ...createDraft, name: value })}
              maxLength={CLIENT_NAME_MAX_LEN}
              placeholder="客户端展示名"
              aria-label="展示名"
              disabled={createSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>回调白名单</span>
            <span className={styles.fieldHint}>每条须为 * 或以 http:// / https:// 开头</span>
            <StringListEditor
              values={createDraft.redirectUris}
              onChange={(next) => setCreateDraft({ ...createDraft, redirectUris: next })}
              disabled={createSubmitting}
              ariaLabel="回调地址"
              addText="添加回调地址"
              placeholder="https://example.com/callback 或 *"
              emptyHint="暂无回调地址，点击下方按钮添加"
            />
          </div>
          {createError !== null ? (
            <p role="alert" className={styles.actionError}>
              {createError}
            </p>
          ) : null}
          <div className={styles.formFooter}>
            <Button onClick={() => setCreateOpen(false)} disabled={createSubmitting}>
              取消
            </Button>
            <Button
              theme="solid"
              onClick={() => {
                void submitCreate();
              }}
              disabled={createSubmitting}
              loading={createSubmitting}
            >
              创建
            </Button>
          </div>
        </div>
      </Modal>
      <Modal
        title="客户端详情"
        visible={viewId !== null}
        onCancel={() => setViewId(null)}
        footer={null}
      >
        {viewLoading ? (
          <p role="status">{VIEW_LOADING_TEXT}</p>
        ) : viewError !== null ? (
          <p role="alert" className={styles.actionError}>
            {viewError}
          </p>
        ) : viewDetail !== null ? (
          <dl className={styles.detailList}>
            <dt>客户端标识</dt>
            <dd className={styles.detailValue}>
              <code className={styles.idCode}>{viewDetail.clientId}</code>
              <CopyButton text={viewDetail.clientId} />
            </dd>
            <dt>客户端密钥</dt>
            <dd className={styles.detailValue}>
              <code className={styles.idCode}>{viewDetail.clientSecret}</code>
              <CopyButton text={viewDetail.clientSecret} />
            </dd>
            <dt>展示名</dt>
            <dd>{viewDetail.name || EMPTY_TEXT}</dd>
            <dt>回调白名单</dt>
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
            <dt>创建时间</dt>
            <dd>{formatUnixTime(viewDetail.createdAt)}</dd>
            <dt>更新时间</dt>
            <dd>{formatUnixTime(viewDetail.updatedAt)}</dd>
          </dl>
        ) : null}
      </Modal>
      <Modal
        title={
          editTarget !== null ? `编辑客户端「${editTarget.clientId}」` : '编辑客户端'
        }
        visible={editTarget !== null}
        onCancel={() => setEditTarget(null)}
        footer={null}
      >
        <div className={styles.formBody}>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>客户端标识</span>
            <Input value={editTarget?.clientId ?? ''} disabled aria-label="客户端标识" />
            <span className={styles.fieldHint}>创建后不可修改</span>
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>展示名</span>
            <Input
              value={editDraft.name}
              onChange={(value) => setEditDraft({ ...editDraft, name: value })}
              maxLength={CLIENT_NAME_MAX_LEN}
              placeholder="客户端展示名"
              aria-label="展示名"
              disabled={editSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>新密钥</span>
            <Input
              mode="password"
              value={editDraft.newSecret}
              onChange={(value) => setEditDraft({ ...editDraft, newSecret: value })}
              placeholder="留空保留原密钥"
              aria-label="新密钥"
              autoComplete="new-password"
              disabled={editSubmitting}
            />
            <span className={styles.fieldHint}>填写后保存将轮换密钥，请同步更新接入方</span>
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>回调白名单</span>
            <span className={styles.fieldHint}>每条须为 * 或以 http:// / https:// 开头</span>
            <StringListEditor
              values={editDraft.redirectUris}
              onChange={(next) => setEditDraft({ ...editDraft, redirectUris: next })}
              disabled={editSubmitting}
              ariaLabel="回调地址"
              addText="添加回调地址"
              placeholder="https://example.com/callback 或 *"
            />
          </div>
          {editError !== null ? (
            <p role="alert" className={styles.actionError}>
              {editError}
            </p>
          ) : null}
          <div className={styles.formFooter}>
            <Button onClick={() => setEditTarget(null)} disabled={editSubmitting}>
              取消
            </Button>
            <Button
              theme="solid"
              onClick={() => {
                void submitEdit();
              }}
              disabled={editSubmitting}
              loading={editSubmitting}
            >
              保存
            </Button>
          </div>
        </div>
      </Modal>
    </section>
  );
}
