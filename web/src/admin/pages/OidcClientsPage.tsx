/**
 * OIDC 客户端列表页（docs/前端架构.md §6 行 519；docs/接口文档.md §5.5 行
 * 1257-1268；docs/需求.md §4.6 行 258）——/admin/clients/oidc。
 *
 * OIDC 客户端 CRUD + 回调白名单 + scopes 管理：SSO 基线（clientId /
 * clientSecret / name / redirectUris[] 支持 *）额外 scopes[] /
 * accessTokenTtl / refreshTokenTtl（§5.5 行 1264「额外」逐字）。OIDC 不设
 * 授权类型字段（§5.5 行 1268：固定 authorization_code + refresh_token，
 * 表单不建模）。仅后台手动创建（§5.5 行 1266）。
 *
 * 与 SsoClientsPage 同构（UsersPage 模式），OIDC 增量：
 * - 列表：权限范围列（摘要）+ 令牌有效期列（tokenTtlSummary）；
 * - 表单：scopes 编辑（StringListEditor，条目非空无逗号）+ 访问 / 刷新
 *   TTL（表单文本态，提交前经 parseTtlField 收敛：空 → 0 = 新建落库端
 *   默认 / 编辑保留原值；值域 [1, 86400] / [1, 2592000]）；
 * - 编辑阻断：scopes 空组 = 保留原值（后端 PATCH），前端阻断防误解。
 *
 * 401 统一跳登录（§6 行 501）；写操作失败就地提示；可测逻辑全部收口在
 * ./api（工具链 blocker 同口径）。样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
// 子路径 import（同 AdminLayout 口径：避免全量入口，测试链 / 产物见其注释）。
import Button from '@douyinfe/semi-ui/lib/es/button';
import Input from '@douyinfe/semi-ui/lib/es/input';
import Modal from '@douyinfe/semi-ui/lib/es/modal';
import Popconfirm from '@douyinfe/semi-ui/lib/es/popconfirm';
import Typography from '@douyinfe/semi-ui/lib/es/typography';
import { CopyButton } from '../../shared/components/CopyButton';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import { initialTableQuery, type TableQueryState } from '../../shared/app-ui/dataTableLogic';
import { useRequest } from '../../shared/hooks/useRequest';
import { toCount } from '../../shared/utils/int';
import { StringListEditor } from '../components/StringListEditor';
import type { OidcClient } from '../../gen/proto/api/admin/v1/client_pb';
import {
  CLIENT_ID_MAX_LEN,
  CLIENT_NAME_MAX_LEN,
  OIDC_ACCESS_TTL_DEFAULT,
  OIDC_ACCESS_TTL_MAX,
  OIDC_REFRESH_TTL_DEFAULT,
  OIDC_REFRESH_TTL_MAX,
  apiErrorText,
  buildCreateOidcClientRequest,
  buildDeleteOidcClientRequest,
  buildGetOidcClientRequest,
  buildListOidcClientsRequest,
  buildUpdateOidcClientRequest,
  cleanStringList,
  createOidcClient,
  deleteOidcClient,
  formatUnixTime,
  getOidcClient,
  isUnauthenticatedError,
  listOidcClients,
  parseTtlField,
  redirectUrisIssue,
  scopesIssue,
  summarizeList,
  tokenTtlSummary,
  ttlDetailText,
  updateOidcClient,
} from '../api';
import { loginUrl } from '../bootstrap';
import styles from './OidcClientsPage.module.less';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/** 详情加载态文案。 */
const VIEW_LOADING_TEXT = '加载中…';

/** 行键（OidcClient.id int64 → 十进制字符串，§1.12）。 */
function oidcClientRowKey(row: OidcClient): string {
  return row.id.toString();
}

/** OIDC 新建表单态（TTL 为表单文本态，提交前经 parseTtlField 收敛）。 */
interface OidcCreateForm {
  readonly clientId: string;
  readonly name: string;
  readonly redirectUris: readonly string[];
  readonly scopes: readonly string[];
  readonly accessTokenTtl: string;
  readonly refreshTokenTtl: string;
}

/** OIDC 编辑表单态（clientId 只读展示不编辑，TTL 文本态）。 */
interface OidcEditForm {
  readonly newSecret: string;
  readonly name: string;
  readonly redirectUris: readonly string[];
  readonly scopes: readonly string[];
  readonly accessTokenTtl: string;
  readonly refreshTokenTtl: string;
}

/** 新建表单初值：TTL 预填库端默认（§4.5：3600 / 2592000）。 */
function initialCreateForm(): OidcCreateForm {
  return {
    clientId: '',
    name: '',
    redirectUris: [],
    scopes: [],
    accessTokenTtl: String(OIDC_ACCESS_TTL_DEFAULT),
    refreshTokenTtl: String(OIDC_REFRESH_TTL_DEFAULT),
  };
}

/** OIDC 客户端列表页：DataTable + 新建 / 查看 / 编辑 / 删除弹窗（含 scopes / TTL）。 */
export function OidcClientsPage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  // §1.7 受控查询状态：分页 / 排序由 DataTable 上报更新。
  const [query, setQuery] = useState<TableQueryState>(initialTableQuery);
  const { status, data, error, run } = useRequest(listOidcClients);
  // 写操作反馈就地展示。
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // 新建弹窗。
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState<OidcCreateForm>(initialCreateForm);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createSubmitting, setCreateSubmitting] = useState(false);
  // 查看弹窗（GetOidcClient 明文密钥的唯一展示位）。
  const [viewId, setViewId] = useState<bigint | null>(null);
  const [viewDetail, setViewDetail] = useState<OidcClient | null>(null);
  const [viewLoading, setViewLoading] = useState(false);
  const [viewError, setViewError] = useState<string | null>(null);
  // 编辑弹窗。
  const [editTarget, setEditTarget] = useState<OidcClient | null>(null);
  const [editForm, setEditForm] = useState<OidcEditForm>({
    newSecret: '',
    name: '',
    redirectUris: [],
    scopes: [],
    accessTokenTtl: '',
    refreshTokenTtl: '',
  });
  const [editError, setEditError] = useState<string | null>(null);
  const [editSubmitting, setEditSubmitting] = useState(false);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run(buildListOidcClientsRequest(query)).catch(() => {});
  }, [run, query]);

  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, props.alRoot]);

  /** 写操作后就地刷新当前页列表。 */
  function refreshList(): void {
    run(buildListOidcClientsRequest(query)).catch(() => {});
  }

  /** 打开新建弹窗：清空上次草稿 / 错误。 */
  function openCreate(): void {
    setCreateForm(initialCreateForm());
    setCreateError(null);
    setCreateOpen(true);
  }

  /**
   * 表单态收敛为请求入参：条目校验（回调白名单 / scopes）+ TTL 文本解析；
   * 返回错误文案（null = 通过）。第二段为解析后的 TTL 秒数对。
   */
  function resolveCreateInput(): { error: string | null; accessTokenTtl: number; refreshTokenTtl: number } {
    const uriIssue = redirectUrisIssue(createForm.redirectUris);
    if (uriIssue !== null) {
      return { error: uriIssue, accessTokenTtl: 0, refreshTokenTtl: 0 };
    }
    const scopeIssue = scopesIssue(createForm.scopes);
    if (scopeIssue !== null) {
      return { error: scopeIssue, accessTokenTtl: 0, refreshTokenTtl: 0 };
    }
    const accessTokenTtl = parseTtlField(createForm.accessTokenTtl, OIDC_ACCESS_TTL_MAX);
    if (accessTokenTtl === null) {
      return {
        error: `访问令牌有效期须为 1-${OIDC_ACCESS_TTL_MAX} 的整数秒`,
        accessTokenTtl: 0,
        refreshTokenTtl: 0,
      };
    }
    const refreshTokenTtl = parseTtlField(createForm.refreshTokenTtl, OIDC_REFRESH_TTL_MAX);
    if (refreshTokenTtl === null) {
      return {
        error: `刷新令牌有效期须为 1-${OIDC_REFRESH_TTL_MAX} 的整数秒`,
        accessTokenTtl: 0,
        refreshTokenTtl: 0,
      };
    }
    return { error: null, accessTokenTtl, refreshTokenTtl };
  }

  /** 提交新建（§5.5 行 1263）：校验前置；TTL 0 落库端默认。 */
  async function submitCreate(): Promise<void> {
    if (createSubmitting) {
      return;
    }
    const resolved = resolveCreateInput();
    if (resolved.error !== null) {
      setCreateError(resolved.error);
      return;
    }
    setCreateSubmitting(true);
    try {
      await createOidcClient(
        buildCreateOidcClientRequest({
          clientId: createForm.clientId,
          name: createForm.name,
          redirectUris: cleanStringList(createForm.redirectUris),
          scopes: cleanStringList(createForm.scopes),
          accessTokenTtl: resolved.accessTokenTtl,
          refreshTokenTtl: resolved.refreshTokenTtl,
        }),
      );
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
   * 打开查看（§5.5 行 1264 GetOidcClient）：读取明文密钥；401 与列表同
   * 口径跳登录，其余错误在弹窗内提示。
   */
  function openView(row: OidcClient): void {
    setViewId(row.id);
    setViewDetail(null);
    setViewError(null);
    setViewLoading(true);
    getOidcClient(buildGetOidcClientRequest(row.id))
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
  function openEdit(row: OidcClient): void {
    setEditTarget(row);
    setEditForm({
      newSecret: '',
      name: row.name,
      redirectUris: [...row.redirectUris],
      scopes: [...row.scopes],
      accessTokenTtl: toCount(row.accessTokenTtl).toString(),
      refreshTokenTtl: toCount(row.refreshTokenTtl).toString(),
    });
    setEditError(null);
  }

  /**
   * 提交编辑（§5.5 行 1264 PATCH）：空白名单 / 空 scopes 阻断（后端空组
   * = 保留原值，清空提交不生效，前端自律拦截防误解）；TTL 文本解析
   * （空 → 0 = 保留原值）。
   */
  async function submitEdit(): Promise<void> {
    const target = editTarget;
    if (target === null || editSubmitting) {
      return;
    }
    const uris = cleanStringList(editForm.redirectUris);
    if (uris.length === 0) {
      setEditError('回调白名单不能为空（清空后保存将保留原值）');
      return;
    }
    const scopes = cleanStringList(editForm.scopes);
    if (scopes.length === 0) {
      setEditError('权限范围不能为空（清空后保存将保留原值）');
      return;
    }
    const uriIssue = redirectUrisIssue(uris);
    if (uriIssue !== null) {
      setEditError(uriIssue);
      return;
    }
    const scopeIssue = scopesIssue(scopes);
    if (scopeIssue !== null) {
      setEditError(scopeIssue);
      return;
    }
    const accessTokenTtl = parseTtlField(editForm.accessTokenTtl, OIDC_ACCESS_TTL_MAX);
    if (accessTokenTtl === null) {
      setEditError(`访问令牌有效期须为 1-${OIDC_ACCESS_TTL_MAX} 的整数秒`);
      return;
    }
    const refreshTokenTtl = parseTtlField(editForm.refreshTokenTtl, OIDC_REFRESH_TTL_MAX);
    if (refreshTokenTtl === null) {
      setEditError(`刷新令牌有效期须为 1-${OIDC_REFRESH_TTL_MAX} 的整数秒`);
      return;
    }
    setEditSubmitting(true);
    try {
      await updateOidcClient(
        buildUpdateOidcClientRequest(target.id, {
          newSecret: editForm.newSecret,
          name: editForm.name,
          redirectUris: uris,
          scopes,
          accessTokenTtl,
          refreshTokenTtl,
        }),
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

  /** 删除（§5.5 行 1264 硬删）：Popconfirm 确认后调用。 */
  async function handleDelete(row: OidcClient): Promise<void> {
    try {
      await deleteOidcClient(buildDeleteOidcClientRequest(row.id));
      setNotice(`已删除客户端「${row.clientId}」`);
      refreshList();
    } catch (err) {
      setActionError(apiErrorText(err));
    }
  }

  // 列口径（§6 行 519 客户端 CRUD / 回调白名单 / scopes）：SSO 基线列 +
  // 权限范围（摘要）+ 令牌有效期（tokenTtlSummary）；可排序列 dataIndex
  // 即 wire 列名（§1.7 sort 前端限定）。
  const columns: readonly DataTableColumn<OidcClient>[] = [
    {
      dataIndex: 'client_id',
      title: '客户端标识',
      sorter: true,
      render: (_text: unknown, row: OidcClient) => (
        <span className={styles.idCell}>
          <code className={styles.idCode}>{row.clientId}</code>
          <CopyButton text={row.clientId} />
        </span>
      ),
    },
    {
      dataIndex: 'name',
      title: '展示名',
      render: (_text: unknown, row: OidcClient) => row.name || EMPTY_TEXT,
    },
    {
      dataIndex: 'redirect_uris',
      title: '回调白名单',
      render: (_text: unknown, row: OidcClient) => summarizeList(row.redirectUris),
    },
    {
      dataIndex: 'scopes',
      title: '权限范围',
      render: (_text: unknown, row: OidcClient) => summarizeList(row.scopes),
    },
    {
      dataIndex: 'access_token_ttl',
      title: '令牌有效期',
      render: (_text: unknown, row: OidcClient) =>
        tokenTtlSummary(row.accessTokenTtl, row.refreshTokenTtl),
    },
    {
      dataIndex: 'created_at',
      title: '创建时间',
      width: 170,
      sorter: true,
      render: (_text: unknown, row: OidcClient) => formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'updated_at',
      title: '更新时间',
      width: 170,
      sorter: true,
      render: (_text: unknown, row: OidcClient) => formatUnixTime(row.updatedAt),
    },
    {
      dataIndex: 'actions',
      title: '操作',
      render: (_text: unknown, row: OidcClient) => (
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
      <Typography.Title heading={3}>OIDC 客户端</Typography.Title>
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
      <DataTable<OidcClient>
        columns={columns}
        rows={data?.items ?? []}
        rowKey={oidcClientRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={status === 'loading'}
        empty={status === 'success' ? '暂无客户端' : undefined}
      />
      <Modal
        title="新建 OIDC 客户端"
        visible={createOpen}
        onCancel={() => setCreateOpen(false)}
        footer={null}
      >
        <div className={styles.formBody}>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>客户端标识</span>
            <Input
              value={createForm.clientId}
              onChange={(value) => setCreateForm({ ...createForm, clientId: value })}
              maxLength={CLIENT_ID_MAX_LEN}
              placeholder="留空自动生成"
              aria-label="客户端标识"
              disabled={createSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>展示名</span>
            <Input
              value={createForm.name}
              onChange={(value) => setCreateForm({ ...createForm, name: value })}
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
              values={createForm.redirectUris}
              onChange={(next) => setCreateForm({ ...createForm, redirectUris: next })}
              disabled={createSubmitting}
              ariaLabel="回调地址"
              addText="添加回调地址"
              placeholder="https://example.com/callback 或 *"
              emptyHint="暂无回调地址，点击下方按钮添加"
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>权限范围</span>
            <span className={styles.fieldHint}>留空使用默认 openid,profile,email</span>
            <StringListEditor
              values={createForm.scopes}
              onChange={(next) => setCreateForm({ ...createForm, scopes: next })}
              disabled={createSubmitting}
              ariaLabel="权限范围"
              addText="添加权限范围"
              placeholder="如 openid"
            />
          </div>
          <div className={styles.ttlRow}>
            <div className={styles.ttlField}>
              <span className={styles.fieldLabel}>访问令牌有效期（秒）</span>
              <Input
                value={createForm.accessTokenTtl}
                onChange={(value) => setCreateForm({ ...createForm, accessTokenTtl: value })}
                placeholder={`默认 ${OIDC_ACCESS_TTL_DEFAULT}`}
                aria-label="访问令牌有效期"
                disabled={createSubmitting}
              />
              <span className={styles.fieldHint}>
                1-{OIDC_ACCESS_TTL_MAX}，留空使用默认 {OIDC_ACCESS_TTL_DEFAULT}
              </span>
            </div>
            <div className={styles.ttlField}>
              <span className={styles.fieldLabel}>刷新令牌有效期（秒）</span>
              <Input
                value={createForm.refreshTokenTtl}
                onChange={(value) => setCreateForm({ ...createForm, refreshTokenTtl: value })}
                placeholder={`默认 ${OIDC_REFRESH_TTL_DEFAULT}`}
                aria-label="刷新令牌有效期"
                disabled={createSubmitting}
              />
              <span className={styles.fieldHint}>
                1-{OIDC_REFRESH_TTL_MAX}，留空使用默认 {OIDC_REFRESH_TTL_DEFAULT}
              </span>
            </div>
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
            <dt>权限范围</dt>
            <dd>
              {viewDetail.scopes.length > 0 ? viewDetail.scopes.join(', ') : EMPTY_TEXT}
            </dd>
            <dt>访问令牌有效期</dt>
            <dd>{ttlDetailText(viewDetail.accessTokenTtl)}</dd>
            <dt>刷新令牌有效期</dt>
            <dd>{ttlDetailText(viewDetail.refreshTokenTtl)}</dd>
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
              value={editForm.name}
              onChange={(value) => setEditForm({ ...editForm, name: value })}
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
              value={editForm.newSecret}
              onChange={(value) => setEditForm({ ...editForm, newSecret: value })}
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
              values={editForm.redirectUris}
              onChange={(next) => setEditForm({ ...editForm, redirectUris: next })}
              disabled={editSubmitting}
              ariaLabel="回调地址"
              addText="添加回调地址"
              placeholder="https://example.com/callback 或 *"
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>权限范围</span>
            <span className={styles.fieldHint}>每条不能为空且不能包含逗号</span>
            <StringListEditor
              values={editForm.scopes}
              onChange={(next) => setEditForm({ ...editForm, scopes: next })}
              disabled={editSubmitting}
              ariaLabel="权限范围"
              addText="添加权限范围"
              placeholder="如 openid"
            />
          </div>
          <div className={styles.ttlRow}>
            <div className={styles.ttlField}>
              <span className={styles.fieldLabel}>访问令牌有效期（秒）</span>
              <Input
                value={editForm.accessTokenTtl}
                onChange={(value) => setEditForm({ ...editForm, accessTokenTtl: value })}
                aria-label="访问令牌有效期"
                disabled={editSubmitting}
              />
              <span className={styles.fieldHint}>
                1-{OIDC_ACCESS_TTL_MAX}，留空保存将保留原值
              </span>
            </div>
            <div className={styles.ttlField}>
              <span className={styles.fieldLabel}>刷新令牌有效期（秒）</span>
              <Input
                value={editForm.refreshTokenTtl}
                onChange={(value) => setEditForm({ ...editForm, refreshTokenTtl: value })}
                aria-label="刷新令牌有效期"
                disabled={editSubmitting}
              />
              <span className={styles.fieldHint}>
                1-{OIDC_REFRESH_TTL_MAX}，留空保存将保留原值
              </span>
            </div>
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
