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
 * 401 统一跳登录（§6 行 501）；写操作成功 / 失败 Toast 提示（Modal
 * 内表单错误保持行内）；可测逻辑全部收口在
 * ./api（工具链 blocker 同口径）。样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Banner, Button, Empty, Input, Modal, Popconfirm, Spin, Toast, Typography } from '@douyinfe/semi-ui-19';
import { CopyButton } from '../../shared/components/CopyButton';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import { initialTableQuery, type TableQueryState } from '../../shared/app-ui/dataTableLogic';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import { StringListEditor } from '../components/StringListEditor';
import type { OidcClient } from '../../gen/proto/api/admin/v1/client_pb';
import {
  adminReturnTo,
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
  // 写操作成功 / 删除失败反馈统一走 Semi Toast（原就地 notice /
  // actionError 文字已随 Semi 回归移除）；Modal 内表单错误保持行内。
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
  // 打开编辑时的基线快照（dirty = 现值偏离基线，见 closeEdit）。
  const [editBaseline, setEditBaseline] = useState<OidcEditForm | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const [editSubmitting, setEditSubmitting] = useState(false);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run(buildListOidcClientsRequest(query)).catch(() => {});
  }, [run, query]);

  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
      window.location.replace(
        loginUrl(props.alRoot, adminReturnTo(location.pathname, location.search)),
      );
    }
  }, [error, props.alRoot, location]);

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

  /** 关闭新建弹窗（草稿相对 initialCreateForm 有改动时需确认）。 */
  function closeCreate(): void {
    confirmCloseIfDirty(
      JSON.stringify(createForm) !== JSON.stringify(initialCreateForm()),
      () => setCreateOpen(false),
    );
  }

  /** 关闭编辑弹窗（现值相对打开时基线有改动时需确认）。 */
  function closeEdit(): void {
    confirmCloseIfDirty(
      editBaseline !== null && JSON.stringify(editForm) !== JSON.stringify(editBaseline),
      () => setEditTarget(null),
    );
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
        error: t('admin.accessTtlIssue', { max: OIDC_ACCESS_TTL_MAX }),
        accessTokenTtl: 0,
        refreshTokenTtl: 0,
      };
    }
    const refreshTokenTtl = parseTtlField(createForm.refreshTokenTtl, OIDC_REFRESH_TTL_MAX);
    if (refreshTokenTtl === null) {
      return {
        error: t('admin.refreshTtlIssue', { max: OIDC_REFRESH_TTL_MAX }),
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
          window.location.replace(
            loginUrl(props.alRoot, adminReturnTo(location.pathname, location.search)),
          );
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
    const baseline: OidcEditForm = {
      newSecret: '',
      name: row.name,
      redirectUris: [...row.redirectUris],
      scopes: [...row.scopes],
      accessTokenTtl: toCount(row.accessTokenTtl).toString(),
      refreshTokenTtl: toCount(row.refreshTokenTtl).toString(),
    };
    setEditTarget(row);
    setEditForm(baseline);
    setEditBaseline(baseline); // dirty 判定基线。
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
      setEditError(t('admin.redirectUrisRequired'));
      return;
    }
    const scopes = cleanStringList(editForm.scopes);
    if (scopes.length === 0) {
      setEditError(t('admin.scopesRequired'));
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
      setEditError(t('admin.accessTtlIssue', { max: OIDC_ACCESS_TTL_MAX }));
      return;
    }
    const refreshTokenTtl = parseTtlField(editForm.refreshTokenTtl, OIDC_REFRESH_TTL_MAX);
    if (refreshTokenTtl === null) {
      setEditError(t('admin.refreshTtlIssue', { max: OIDC_REFRESH_TTL_MAX }));
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
      Toast.success(t('admin.clientUpdateSuccess', { clientId: target.clientId }));
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
      Toast.success(t('admin.clientDeleteSuccess', { clientId: row.clientId }));
      refreshList();
    } catch (err) {
      Toast.error(apiErrorText(err));
    }
  }

  // 列口径（§6 行 519 客户端 CRUD / 回调白名单 / scopes）：SSO 基线列 +
  // 权限范围（摘要）+ 令牌有效期（tokenTtlSummary）；可排序列 dataIndex
  // 即 wire 列名（§1.7 sort 前端限定）。
  const columns: readonly DataTableColumn<OidcClient>[] = [
    {
      dataIndex: 'client_id',
      title: t('admin.clientIdLabel'),
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
      title: t('admin.clientNameLabel'),
      render: (_text: unknown, row: OidcClient) => row.name || EMPTY_TEXT,
    },
    {
      dataIndex: 'redirect_uris',
      title: t('admin.redirectUrisLabel'),
      render: (_text: unknown, row: OidcClient) => summarizeList(row.redirectUris),
    },
    {
      dataIndex: 'scopes',
      title: t('admin.scopesLabel'),
      render: (_text: unknown, row: OidcClient) => summarizeList(row.scopes),
    },
    {
      dataIndex: 'access_token_ttl',
      title: t('admin.tokenTtlLabel'),
      render: (_text: unknown, row: OidcClient) =>
        tokenTtlSummary(row.accessTokenTtl, row.refreshTokenTtl),
    },
    {
      dataIndex: 'created_at',
      title: t('admin.createdAtLabel'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: OidcClient) => formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'updated_at',
      title: t('admin.updatedAtLabel'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: OidcClient) => formatUnixTime(row.updatedAt),
    },
    {
      dataIndex: 'actions',
      title: t('admin.actionsLabel'),
      render: (_text: unknown, row: OidcClient) => (
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
      <Typography.Title heading={3}>{t('admin.navOidcClients')}</Typography.Title>
      <div className={styles.toolbar}>
        <Button theme="solid" onClick={openCreate}>
          {t('admin.createClientAction')}
        </Button>
      </div>
      <DataTable<OidcClient>
        columns={columns}
        rows={data?.items ?? []}
        rowKey={oidcClientRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={status === 'loading'}
        // 空态裸文字换 Semi Empty（默认插图 + 文案）。
        empty={status === 'success' ? <Empty description={t('admin.noClients')} /> : undefined}
      />
      <Modal
        title={t('admin.createOidcClientTitle')}
        visible={createOpen}
        onCancel={closeCreate}
        maskClosable={false}
        footer={null}
      >
        <div className={styles.formBody}>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.clientIdLabel')}</span>
            <Input
              value={createForm.clientId}
              onChange={(value) => setCreateForm({ ...createForm, clientId: value })}
              maxLength={CLIENT_ID_MAX_LEN}
              placeholder={t('admin.clientIdAutoGenPlaceholder')}
              aria-label={t('admin.clientIdLabel')}
              disabled={createSubmitting}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.clientNameLabel')}</span>
            <Input
              value={createForm.name}
              onChange={(value) => setCreateForm({ ...createForm, name: value })}
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
              values={createForm.redirectUris}
              onChange={(next) => setCreateForm({ ...createForm, redirectUris: next })}
              disabled={createSubmitting}
              ariaLabel={t('admin.redirectUriAriaLabel')}
              addText={t('admin.addRedirectUri')}
              placeholder={t('admin.redirectUriPlaceholder')}
              emptyHint={t('admin.noRedirectUrisHint')}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.scopesLabel')}</span>
            <span className={styles.fieldHint}>{t('admin.scopesDefaultHint')}</span>
            <StringListEditor
              values={createForm.scopes}
              onChange={(next) => setCreateForm({ ...createForm, scopes: next })}
              disabled={createSubmitting}
              ariaLabel={t('admin.scopesLabel')}
              addText={t('admin.addScope')}
              placeholder={t('admin.scopePlaceholder')}
            />
          </div>
          <div className={styles.ttlRow}>
            <div className={styles.ttlField}>
              <span className={styles.fieldLabel}>{t('admin.accessTokenTtlFieldLabel')}</span>
              <Input
                value={createForm.accessTokenTtl}
                onChange={(value) => setCreateForm({ ...createForm, accessTokenTtl: value })}
                placeholder={t('admin.ttlPlaceholder', { value: OIDC_ACCESS_TTL_DEFAULT })}
                aria-label={t('admin.accessTokenTtlLabel')}
                disabled={createSubmitting}
              />
              <span className={styles.fieldHint}>
                {t('admin.ttlRangeHint', {
                  max: OIDC_ACCESS_TTL_MAX,
                  value: OIDC_ACCESS_TTL_DEFAULT,
                })}
              </span>
            </div>
            <div className={styles.ttlField}>
              <span className={styles.fieldLabel}>{t('admin.refreshTokenTtlFieldLabel')}</span>
              <Input
                value={createForm.refreshTokenTtl}
                onChange={(value) => setCreateForm({ ...createForm, refreshTokenTtl: value })}
                placeholder={t('admin.ttlPlaceholder', { value: OIDC_REFRESH_TTL_DEFAULT })}
                aria-label={t('admin.refreshTokenTtlLabel')}
                disabled={createSubmitting}
              />
              <span className={styles.fieldHint}>
                {t('admin.ttlRangeHint', {
                  max: OIDC_REFRESH_TTL_MAX,
                  value: OIDC_REFRESH_TTL_DEFAULT,
                })}
              </span>
            </div>
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
            <dt>{t('admin.scopesLabel')}</dt>
            <dd>
              {viewDetail.scopes.length > 0 ? viewDetail.scopes.join(', ') : EMPTY_TEXT}
            </dd>
            <dt>{t('admin.accessTokenTtlLabel')}</dt>
            <dd>{ttlDetailText(viewDetail.accessTokenTtl)}</dd>
            <dt>{t('admin.refreshTokenTtlLabel')}</dt>
            <dd>{ttlDetailText(viewDetail.refreshTokenTtl)}</dd>
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
              value={editForm.name}
              onChange={(value) => setEditForm({ ...editForm, name: value })}
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
              value={editForm.newSecret}
              onChange={(value) => setEditForm({ ...editForm, newSecret: value })}
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
              values={editForm.redirectUris}
              onChange={(next) => setEditForm({ ...editForm, redirectUris: next })}
              disabled={editSubmitting}
              ariaLabel={t('admin.redirectUriAriaLabel')}
              addText={t('admin.addRedirectUri')}
              placeholder={t('admin.redirectUriPlaceholder')}
            />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('admin.scopesLabel')}</span>
            <span className={styles.fieldHint}>{t('admin.scopesEntryHint')}</span>
            <StringListEditor
              values={editForm.scopes}
              onChange={(next) => setEditForm({ ...editForm, scopes: next })}
              disabled={editSubmitting}
              ariaLabel={t('admin.scopesLabel')}
              addText={t('admin.addScope')}
              placeholder={t('admin.scopePlaceholder')}
            />
          </div>
          <div className={styles.ttlRow}>
            <div className={styles.ttlField}>
              <span className={styles.fieldLabel}>{t('admin.accessTokenTtlFieldLabel')}</span>
              <Input
                value={editForm.accessTokenTtl}
                onChange={(value) => setEditForm({ ...editForm, accessTokenTtl: value })}
                aria-label={t('admin.accessTokenTtlLabel')}
                disabled={editSubmitting}
              />
              <span className={styles.fieldHint}>
                {t('admin.ttlKeepHint', { max: OIDC_ACCESS_TTL_MAX })}
              </span>
            </div>
            <div className={styles.ttlField}>
              <span className={styles.fieldLabel}>{t('admin.refreshTokenTtlFieldLabel')}</span>
              <Input
                value={editForm.refreshTokenTtl}
                onChange={(value) => setEditForm({ ...editForm, refreshTokenTtl: value })}
                aria-label={t('admin.refreshTokenTtlLabel')}
                disabled={editSubmitting}
              />
              <span className={styles.fieldHint}>
                {t('admin.ttlKeepHint', { max: OIDC_REFRESH_TTL_MAX })}
              </span>
            </div>
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
