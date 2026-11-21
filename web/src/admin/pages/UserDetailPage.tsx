/**
 * 用户详情抽屉内容（UsersPage 点击用户名打开；组件常驻挂载，仅切 visible，
 * 不随 URL 变化）：
 *
 * GetUser（{id} 详情，含凭证概览 / 三方绑定 / MFA 状态 / profile / permissions）
 * 真调（后端已实装）。基本信息为查看 / 编辑双态：编辑态 Semi Form 回填 profile
 * 投影，提交经 api 纯函数校验 + PATCH diff，无改动不提交；改联系方式写入即
 * 置已验证、触发该用户全部会话失效，确认文案明示后果。
 *
 * MFA 区提供开关两步验证 / 救援解绑 TOTP / 重置恢复码；凭证区提供停用 / 启用
 * 与删除（密码凭证不允许停用，服务端权威）；三方绑定保留解绑入口（Union 行
 * 不可单独解绑由服务端兜底 invalid_request）。危险写操作 Popconfirm 二次确认
 * 并明示强制下线后果，成功后统一 refreshAsync() 重取详情 + Toast 反馈。
 *
 * 写按钮展示态按 GetUser.permissions 与当前操作者 GetMe.permissions 分级判定
 * （服务端门禁是唯一真相，前端隐藏仅体验优化）。删除用户入口属相邻切片，
 * 本组件保持可继续在头部追加，不预设结构。
 *
 * 登录日志（GetUserEvents {id} + 分页）：DataTable 消费
 * （分页 / 排序受控 TableQueryState，初始 created_at desc——EventLogTable
 * 同构；列口径沿需求：时间 / 事件 / 方式 / IP / 设备 UA）。
 *
 * 401 统一跳登录（UsersPage 同模式）；404 掩护等其余错误走错误态。
 * 组件壳 import Semi 后不可在 node 测试（工具链口径），
 * 可测逻辑全部收口在 ./api（草稿 / diff / 校验 / 分级显隐 / 请求构造）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import {
  Banner,
  Button,
  Form,
  Input,
  Popconfirm,
  SideSheet,
  Spin,
  Tag,
  Toast,
  Typography,
  Modal,
} from '@douyinfe/semi-ui';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import {
  initialTableQuery,
  type TableQueryState,
} from '../../shared/app-ui/dataTableLogic';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { deriveRequestStatus } from '../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t, type I18nKey } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import type { EventItem } from '../../gen/proto/api/admin/v1/events_pb';
import {
  adminReturnTo,
  apiErrorText,
  boundMfaFactors,
  buildDeleteCredentialRequest,
  buildDeleteUserRequest,
  buildGetUserEventsRequest,
  buildGetUserRequest,
  buildResetUserRecoveryCodesRequest,
  buildSetCredentialEnabledRequest,
  buildSetUserMfaRequest,
  buildUnbindUserThirdpartyRequest,
  buildUnbindUserTOTPRequest,
  buildUpdateUserContactRequest,
  buildUpdateUserProfileRequest,
  credentialKindLabel,
  deleteCredential,
  deleteUser,
  formatUnixTime,
  getMe,
  getUser,
  getUserEvents,
  isDeletedUser,
  isUnauthenticatedError,
  resetUserRecoveryCodes,
  setCredentialEnabled,
  setUserMfa,
  unbindUserThirdparty,
  unbindUserTOTP,
  updateUserContact,
  updateUserProfile,
  userEditDraftFromDetail,
  userEditDraftIssue,
  userStatusLabel,
  userWriteConfirmStrength,
  userWriteVisibility,
  type UserEditDraft,
  type UserWriteVisibility,
} from '../api';
import styles from './UserDetailPage.module.less';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 '' / 0n）。 */
const EMPTY_TEXT = '—';

/** 登录日志排序字段（§1.7 行 277 示例 created_at；sort 值域前端自律）。 */
const EVENTS_SORT_FIELD = 'created_at';

/** 详情页登录日志初始查询：第 1 页、每页 20、按时间倒序（EventLogTable 同构）。 */
const INITIAL_EVENTS_QUERY: TableQueryState = {
  ...initialTableQuery(),
  sort: EVENTS_SORT_FIELD,
  order: 'desc',
};

/** 编辑提交分流（§5.4：联系方式写入即置已验证 + 全部会话失效，须二次确认）。 */
export type UserEditSubmitKind = 'noop' | 'direct' | 'confirm_contact';

/**
 * 提交门槛：confirmKey 仅在 confirm_contact 时非空，供 Modal 标题取用；
 * strength 为确认强度（userWriteConfirmStrength 同源）——≥1 渲染 Modal
 * 二次确认，0 直接提交（控件分级按强度取值，不按 kind 字面硬编码）。
 */
export interface UserEditSubmitGate {
  kind: UserEditSubmitKind;
  confirmKey: I18nKey | null;
  strength: 0 | 1 | 2;
}

/**
 * 编辑提交门槛：联系方式有 diff 必须先二次确认；仅资料 diff 可直接提交；
 * 全无改动不提交。确认强度经 userWriteConfirmStrength 分级（§5.4）。
 * 纯函数，node 可测（组件壳不可测口径）。
 */
export function userEditSubmitGate(
  profileChanged: boolean,
  contactChanged: boolean,
): UserEditSubmitGate {
  if (!profileChanged && !contactChanged) {
    return { kind: 'noop', confirmKey: null, strength: 0 };
  }
  if (contactChanged) {
    return {
      kind: 'confirm_contact',
      confirmKey: 'admin.contactEditConfirm',
      strength: userWriteConfirmStrength('contact'),
    };
  }
  return {
    kind: 'direct',
    confirmKey: null,
    strength: userWriteConfirmStrength('profile'),
  };
}

/**
 * 提交放行判定：confirm_contact 必须确认（confirmed=true）才提交，取消
 * （confirmed=false）一律不放行；direct 不受 confirmed 影响；noop 永不提交。
 */
export function canSubmitUserEdit(
  gate: UserEditSubmitGate,
  confirmed: boolean,
): boolean {
  if (gate.kind === 'noop') {
    return false;
  }
  return gate.kind === 'direct' || confirmed;
}

/**
 * 删除提交门槛：必须逐字输入目标用户名才放行——空输入 / 不一致一律不可
 * 提交（最强确认档，区别于联系方式 / MFA / 凭证的 Modal 二次确认）。
 * 纯函数，node 可测。
 */
export function canSubmitUserDelete(
  targetUsername: string,
  typed: string,
): boolean {
  return targetUsername !== '' && typed === targetUsername;
}

/**
 * 删除确认控件分级（§5.4 危险操作确认强度，userWriteConfirmStrength 驱动）：
 * 强度 ≥2 → Modal 内须逐字输入目标用户名才放行（输入框 / 提交门槛均按此档
 * 渲染）；<2 退化为纯 Modal 二次确认。strength 默认取 delete 档。
 * 纯函数，node 可测（组件壳不可测口径）。
 */
export function deleteConfirmNeedsTypedInput(
  strength: 0 | 1 | 2 = userWriteConfirmStrength('delete'),
): boolean {
  return strength >= 2;
}

/** 已删用户的写按钮一律置灰（体验层；服务端对其任何写请求均拒绝）。 */
function allWritesDisabled(): UserWriteVisibility {
  return {
    editProfile: false,
    editContact: false,
    setMfa: false,
    unbindTotp: false,
    resetRecoveryCodes: false,
    credentialWrite: false,
    unbindThirdparty: false,
    deleteUser: false,
  };
}

/**
 * 登录日志列（需求 §4.2 行 152：时间 / 事件 / 方式 / IP / 设备 UA）。
 * 渲染期函数求值，模块级 t() 会冻结在默认语言。
 */
function getEventsColumns(): DataTableColumn<EventItem>[] {
  return [
    {
      dataIndex: EVENTS_SORT_FIELD,
      title: t('admin.timeColumn'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: EventItem) => formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'event',
      title: t('admin.eventColumn'),
      width: 120,
      render: (_text: unknown, row: EventItem) => row.event || EMPTY_TEXT,
    },
    {
      dataIndex: 'amr',
      title: t('admin.methodColumn'),
      width: 120,
      render: (_text: unknown, row: EventItem) => row.amr || EMPTY_TEXT,
    },
    {
      dataIndex: 'ip',
      title: 'IP',
      width: 120,
      render: (_text: unknown, row: EventItem) => row.ip || EMPTY_TEXT,
    },
    {
      dataIndex: 'ua',
      title: t('admin.deviceUaColumn'),
      width: 160,
      render: (_text: unknown, row: EventItem) => (
        <Typography.Paragraph ellipsis={{ rows: 2, showTooltip: true }}>
          {row.ua || EMPTY_TEXT}
        </Typography.Paragraph>
      ),
    },
  ];
}

/** 登录日志行键（EventItem.id）。 */
function eventRowKey(row: EventItem): string {
  return row.id.toString();
}

/** 用户详情抽屉：基本信息 + 凭证概览 + MFA 状态 + 三方绑定（解绑）+ 登录日志。 */
export function UserDetail(props: {
  /** 归一后 al_root（透传，保持与列表页路由参数一致）。 */
  alRoot: string;
  /** 目标用户 ID；抽屉关闭期间保留上次 id，避免关闭动画闪空。 */
  userId: bigint | null;
  visible: boolean;
  onClose: () => void;
  /** 删除成功后的回调（列表页据此重取列表并关闭抽屉）；可选。 */
  onDeleted?: () => void;
}): ReactNode {
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // 抽屉常驻挂载：仅在可见且有目标 id 时才发请求——ready 拦截关闭后的
  // 残余请求，id 切换经 refreshDeps 重取；0n 仅作未 ready 时的入参兜底。
  // refreshAsync 供解绑成功后串行重取（须待详情重取完成再报成功）。
  const ready = props.visible && props.userId !== null;
  const { data, error, refreshAsync } = useRequest(
    () => getUser(buildGetUserRequest(props.userId ?? BigInt(0))),
    {
      ready,
      refreshDeps: [props.userId],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );
  /**
   * 当前操作者权限（§5.4 门禁矩阵）：与详情下发的目标 permissions 比对，
   * 决定写按钮体验层显隐；服务端门禁是唯一真相。
   */
  const { data: meData } = useRequest(() => getMe(), {
    ...requestOptions({
      toast: false,
      returnTo: () => adminReturnTo(location.pathname, location.search),
    }),
  });

  const [eventsQuery, setEventsQuery] =
    useState<TableQueryState>(INITIAL_EVENTS_QUERY);
  const {
    data: eventsData,
    error: eventsError,
    loading: eventsLoading,
  } = useRequest(
    () =>
      getUserEvents(
        buildGetUserEventsRequest(props.userId ?? BigInt(0), eventsQuery),
      ),
    {
      ready,
      refreshDeps: [props.userId, eventsQuery],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );

  // 查看 / 编辑双态：切 id 或关闭抽屉时归位；formKey 重建 Semi Form 以回填新值。
  const [editing, setEditing] = useState(false);
  const [formKey, setFormKey] = useState(0);
  const [writeBusy, setWriteBusy] = useState(false);
  // 删除用户确认（§5.4 最强确认档，分级由 userWriteConfirmStrength 驱动）：
  // 强度 2 → Modal 内须逐字输入目标用户名才放行。
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [deleteTyped, setDeleteTyped] = useState('');
  const [deleteSubmitting, setDeleteSubmitting] = useState(false);
  const deleteTypedRequired = deleteConfirmNeedsTypedInput();

  // 切换目标 / 关闭抽屉时退出编辑态，避免把上个用户的草稿带到下个用户。
  useEffect(() => {
    setEditing(false);
    setFormKey((key) => key + 1);
    setDeleteModalOpen(false);
    setDeleteTyped('');
  }, [props.userId, props.visible]);

  /** 统一写操作编排：在途禁用靠调用方 Popconfirm 机制 + 本层 busy 文案。 */
  async function runWrite(
    action: () => Promise<unknown>,
    successText: string,
  ): Promise<void> {
    setWriteBusy(true);
    try {
      await action();
      await refreshAsync();
      Toast.success(successText);
      setEditing(false);
      setFormKey((key) => key + 1);
    } catch (writeError) {
      Toast.error(apiErrorText(writeError));
    } finally {
      setWriteBusy(false);
    }
  }

  /** 编辑态提交：先纯函数校验 + diff，无改动不发请求；资料 / 联系方式分两路。 */
  async function handleEditSubmit(values: UserEditDraft): Promise<void> {
    if (props.userId === null || data === undefined) {
      return;
    }
    const issue = userEditDraftIssue(values);
    if (issue !== null) {
      Toast.error(t(issue));
      return;
    }
    const id = props.userId;
    const profileRequest = buildUpdateUserProfileRequest(id, values, data);
    const contactRequest = buildUpdateUserContactRequest(id, values, data);
    const gate = userEditSubmitGate(
      profileRequest !== null,
      contactRequest !== null,
    );
    if (gate.kind === 'noop') {
      Toast.info(t('admin.noEditChanges'));
      setEditing(false);
      return;
    }

    // confirmed=false 为取消路径（不提交）；仅 onOk 传 true 放行。
    const submit = (confirmed: boolean): void => {
      if (!canSubmitUserEdit(gate, confirmed)) {
        return;
      }
      void runWrite(
        async () => {
          if (profileRequest !== null) {
            await updateUserProfile(profileRequest);
          }
          if (contactRequest !== null) {
            await updateUserContact(contactRequest);
          }
        },
        contactRequest !== null && profileRequest === null
          ? t('admin.editContactSuccess')
          : t('admin.editProfileSuccess'),
      );
    };

    if (gate.strength >= 1 && gate.confirmKey !== null) {
      // 确认强度 ≥1（userWriteConfirmStrength 分级）→ Modal 二次确认再提交
      // （§5.4：联系方式写即置已验证 + 全部会话失效）。
      Modal.confirm({
        title: t(gate.confirmKey),
        onOk: () => submit(true),
        onCancel: () => submit(false),
      });
      return;
    }
    submit(false);
  }

  /**
   * 解绑第三方：Union 行不可单独解绑由服务端兜底
   * （invalid_request → 失败经 Toast 展示）；成功后重取详情刷新
   * 绑定列表 + 成功反馈（统一成功通道，新增 admin.unbindSuccess）。
   * 防重：onConfirm 返回本 Promise——Semi Popconfirm 原生机制
   * 在途期间确认钮 loading + 禁用（连点不再触发），落地才关框。
   */
  async function handleUnbind(providerKey: string): Promise<void> {
    try {
      await unbindUserThirdparty(
        buildUnbindUserThirdpartyRequest(
          props.userId ?? BigInt(0),
          providerKey,
        ),
      );
      await refreshAsync();
      Toast.success(t('admin.unbindSuccess', { providerKey }));
    } catch (unbindError) {
      Toast.error(apiErrorText(unbindError));
    }
  }

  /** 删除用户：逐字输入用户名确认后提交；成功关框 + 通知列表重取。 */
  async function submitDelete(targetUsername: string): Promise<void> {
    if (
      deleteTypedRequired &&
      !canSubmitUserDelete(targetUsername, deleteTyped)
    ) {
      return;
    }
    setDeleteSubmitting(true);
    try {
      await deleteUser(buildDeleteUserRequest(props.userId ?? BigInt(0)));
      setDeleteModalOpen(false);
      setDeleteTyped('');
      Toast.success(t('admin.deleteUserSuccess', { username: targetUsername }));
      props.onDeleted?.();
      props.onClose();
    } catch (deleteError) {
      Toast.error(apiErrorText(deleteError));
    } finally {
      setDeleteSubmitting(false);
    }
  }

  // 抽屉内容：错误态 / 加载态 / 五个区块均落在 SideSheet 内，标题由外层
  // title 承载（避免旧独立页的 section 壳与 page-title 重复）。
  let content: ReactNode;
  if (error !== undefined && !isUnauthenticatedError(error)) {
    content = (
      <Banner
        type="danger"
        fullMode={false}
        description={t('admin.userDetailLoadFailed')}
      />
    );
  } else if (data === undefined) {
    content = (
      <div className={styles.stateCenter} role="status">
        <Spin size="large" />
      </div>
    );
  } else {
    const user = data.user;
    const mfaBound = boundMfaFactors(data.mfa);
    const targetUsername = user?.username ?? '';
    const targetId = props.userId ?? BigInt(0);
    const isDeleted = isDeletedUser(targetUsername);
    // 体验层显隐；服务端门禁唯一真相（§5.4）。操作者权限未到达时按无
    // superadmin 处理——写按钮收敛，绝不放宽。已删用户所有写操作置灰；
    // 自删由服务端拒绝，前端同步隐藏删除入口。
    const baseVisibility = userWriteVisibility(
      data.permissions,
      meData?.permissions ?? [],
    );
    const selfDelete = meData !== undefined && meData.id === targetId;
    const visibility = isDeleted
      ? allWritesDisabled()
      : {
          ...baseVisibility,
          deleteUser: baseVisibility.deleteUser && !selfDelete,
        };
    content = (
      <>
        {isDeleted ? (
          <p role="status" style={{ color: '#dc2626', fontSize: 12 }}>
            {t('admin.deletedUserNotice')}
          </p>
        ) : null}
        <section className={styles.block}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <h4 className={styles.blockTitle}>{t('admin.basicInfoSection')}</h4>
            <div style={{ display: 'flex', gap: 8 }}>
              {user !== undefined && visibility.editProfile && !editing ? (
                <Button
                  size="small"
                  onClick={() => {
                    setEditing(true);
                  }}
                >
                  {t('admin.editAction')}
                </Button>
              ) : null}
              {user !== undefined && visibility.deleteUser && !editing ? (
                <Button
                  size="small"
                  type="danger"
                  disabled={writeBusy}
                  onClick={() => {
                    setDeleteTyped('');
                    setDeleteModalOpen(true);
                  }}
                >
                  {t('admin.deleteUserAction')}
                </Button>
              ) : null}
            </div>
          </div>
          {user === undefined ? (
            // user 缺省（protojson 零值省略）：后端不该下发的防御分支。
            <p className={styles.muted}>{t('admin.noUserData')}</p>
          ) : editing ? (
            <Form
              key={formKey}
              initValues={{ ...userEditDraftFromDetail(data) }}
              onSubmit={(values: Record<string, unknown>) => {
                void handleEditSubmit(values as unknown as UserEditDraft);
              }}
              trigger="custom"
              labelPosition="top"
            >
              <Form.Input
                field="nickname"
                label={t('admin.nicknameLabel')}
                disabled={writeBusy}
                allowEmptyString
              />
              <Form.Input
                field="avatarUrl"
                label={t('admin.avatarUrlLabel')}
                disabled={writeBusy}
                allowEmptyString
              />
              <Form.Input
                field="phone"
                label={t('admin.phoneLabel')}
                disabled={writeBusy}
                allowEmptyString
              />
              <Form.Input
                field="email"
                label={t('admin.emailLabel')}
                disabled={writeBusy}
                allowEmptyString
              />
              <Form.Select
                field="gender"
                label={t('admin.genderLabel')}
                optionList={[
                  { value: '0', label: t('admin.genderUnspecified') },
                  { value: '1', label: t('admin.genderMale') },
                  { value: '2', label: t('admin.genderFemale') },
                ]}
                disabled={writeBusy}
                showClear
              />
              <Form.Input
                field="birthday"
                label={t('admin.birthdayLabel')}
                placeholder="YYYY-MM-DD"
                disabled={writeBusy}
                allowEmptyString
              />
              <Form.Input
                field="locale"
                label={t('admin.localeLabel')}
                disabled={writeBusy}
                allowEmptyString
              />
              <Form.Input
                field="timezone"
                label={t('admin.timezoneLabel')}
                disabled={writeBusy}
                allowEmptyString
              />
              <Form.TextArea
                field="extra"
                label={t('admin.extraLabel')}
                placeholder={t('admin.extraPlaceholder')}
                disabled={writeBusy}
                autosize
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                <Button
                  htmlType="submit"
                  theme="solid"
                  type="primary"
                  loading={writeBusy}
                >
                  {t('admin.saveAction')}
                </Button>
                <Button
                  disabled={writeBusy}
                  onClick={() => {
                    setEditing(false);
                  }}
                >
                  {t('admin.cancelAction')}
                </Button>
              </div>
            </Form>
          ) : (
            <dl className={styles.infoGrid}>
              <dt>{t('admin.usernameLabel')}</dt>
              <dd>{user.username || EMPTY_TEXT}</dd>
              <dt>{t('admin.nicknameLabel')}</dt>
              <dd>{user.nickname || EMPTY_TEXT}</dd>
              <dt>{t('admin.phoneLabel')}</dt>
              <dd>
                {user.phone || EMPTY_TEXT}
                {user.phone !== '' && user.phoneVerified === BigInt(1)
                  ? t('admin.verifiedTag')
                  : ''}
              </dd>
              <dt>{t('admin.emailLabel')}</dt>
              <dd>
                {user.email || EMPTY_TEXT}
                {user.email !== '' && user.emailVerified === BigInt(1)
                  ? t('admin.verifiedTag')
                  : ''}
              </dd>
              <dt>{t('admin.statusLabel')}</dt>
              <dd>{userStatusLabel(user.userStatus)}</dd>
              <dt>{t('admin.mfaRequiredLabel')}</dt>
              <dd>
                {user.mfaRequired === BigInt(1)
                  ? t('admin.yesText')
                  : t('admin.noText')}
              </dd>
              <dt>{t('admin.lastLoginLabel')}</dt>
              <dd>{formatUnixTime(user.lastLoginAt)}</dd>
              <dt>{t('admin.createdAtLabel')}</dt>
              <dd>{formatUnixTime(user.createdAt)}</dd>
            </dl>
          )}
        </section>

        <section className={styles.block}>
          <h4 className={styles.blockTitle}>{t('admin.mfaStatusSection')}</h4>
          {user !== undefined && user.mfaRequired === BigInt(1) ? (
            <p className={styles.mfaRequired}>{t('admin.mfaRequiredNotice')}</p>
          ) : null}
          <p className={styles.muted}>
            {mfaBound.length > 0
              ? t('admin.mfaBoundSummary', { factors: mfaBound.join('、') })
              : t('admin.mfaNoneBound')}
          </p>
          {visibility.setMfa ||
          visibility.unbindTotp ||
          visibility.resetRecoveryCodes ? (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {visibility.setMfa ? (
                user?.mfaRequired === BigInt(1) ? (
                  <Popconfirm
                    title={t('admin.mfaDisableConfirm', {
                      username: targetUsername,
                    })}
                    onConfirm={() =>
                      runWrite(
                        () =>
                          setUserMfa(buildSetUserMfaRequest(targetId, false)),
                        t('admin.mfaDisableSuccess'),
                      )
                    }
                  >
                    <Button size="small" type="danger" disabled={writeBusy}>
                      {t('admin.mfaDisableAction')}
                    </Button>
                  </Popconfirm>
                ) : (
                  <Popconfirm
                    title={t('admin.mfaEnableConfirm', {
                      username: targetUsername,
                    })}
                    onConfirm={() =>
                      runWrite(
                        () =>
                          setUserMfa(buildSetUserMfaRequest(targetId, true)),
                        t('admin.mfaEnableSuccess'),
                      )
                    }
                  >
                    <Button size="small" disabled={writeBusy}>
                      {t('admin.mfaEnableAction')}
                    </Button>
                  </Popconfirm>
                )
              ) : null}
              {visibility.unbindTotp &&
              data.credentials.some((item) => item.kind === 'totp') ? (
                <Popconfirm
                  title={t('admin.unbindTotpConfirm', {
                    username: targetUsername,
                  })}
                  onConfirm={() =>
                    runWrite(
                      () =>
                        unbindUserTOTP(buildUnbindUserTOTPRequest(targetId)),
                      t('admin.unbindTotpSuccess'),
                    )
                  }
                >
                  <Button size="small" type="danger" disabled={writeBusy}>
                    {t('admin.unbindTotpAction')}
                  </Button>
                </Popconfirm>
              ) : null}
              {visibility.resetRecoveryCodes ? (
                <Popconfirm
                  title={t('admin.resetRecoveryCodesConfirm', {
                    username: targetUsername,
                  })}
                  onConfirm={() =>
                    runWrite(
                      () =>
                        resetUserRecoveryCodes(
                          buildResetUserRecoveryCodesRequest(targetId),
                        ),
                      t('admin.resetRecoveryCodesSuccess'),
                    )
                  }
                >
                  <Button size="small" disabled={writeBusy}>
                    {t('admin.resetRecoveryCodesAction')}
                  </Button>
                </Popconfirm>
              ) : null}
            </div>
          ) : null}
        </section>

        <section className={styles.block}>
          <h4 className={styles.blockTitle}>{t('admin.credentialsSection')}</h4>
          {data.credentials.length === 0 ? (
            <p className={styles.muted}>{t('admin.noCredentials')}</p>
          ) : (
            <ul className={styles.list}>
              {data.credentials.map((credential) => (
                <li key={credential.id.toString()} className={styles.listRow}>
                  <span className={styles.listMain}>
                    {credentialKindLabel(credential.kind)}
                    {credential.label !== '' ? `（${credential.label}）` : ''}
                  </span>
                  {/* 自绘状态徽章（主色蓝代偿）换 Semi Tag，语义色交 Semi。 */}
                  {credential.isEnabled ? (
                    <Tag color="green">{t('admin.credentialEnabled')}</Tag>
                  ) : (
                    <Tag>{t('admin.credentialDisabled')}</Tag>
                  )}
                  <span className={styles.listMeta}>
                    {t('admin.boundAt', {
                      time: formatUnixTime(credential.createdAt),
                    })}
                    {credential.lastUsedAt > BigInt(0)
                      ? t('admin.credentialLastUsed', {
                          time: formatUnixTime(credential.lastUsedAt),
                        })
                      : ''}
                  </span>
                  {visibility.credentialWrite ? (
                    <div style={{ display: 'flex', gap: 4 }}>
                      {credential.kind ===
                      'password' ? null : credential.isEnabled ? (
                        // 密码凭证不允许停用（§5.4），仅其余类型显示停用入口。
                        <Popconfirm
                          title={t('admin.credentialDisableConfirm', {
                            kind: credentialKindLabel(credential.kind),
                          })}
                          onConfirm={() =>
                            runWrite(
                              () =>
                                setCredentialEnabled(
                                  buildSetCredentialEnabledRequest(
                                    targetId,
                                    credential.id,
                                    false,
                                  ),
                                ),
                              t('admin.credentialDisabledSuccess'),
                            )
                          }
                        >
                          <Button size="small" disabled={writeBusy}>
                            {t('admin.credentialDisableAction')}
                          </Button>
                        </Popconfirm>
                      ) : (
                        <Button
                          size="small"
                          disabled={writeBusy}
                          onClick={() =>
                            runWrite(
                              () =>
                                setCredentialEnabled(
                                  buildSetCredentialEnabledRequest(
                                    targetId,
                                    credential.id,
                                    true,
                                  ),
                                ),
                              t('admin.credentialEnabledSuccess'),
                            )
                          }
                        >
                          {t('admin.credentialEnableAction')}
                        </Button>
                      )}
                      <Popconfirm
                        title={t('admin.credentialDeleteConfirm', {
                          kind: credentialKindLabel(credential.kind),
                        })}
                        onConfirm={() =>
                          runWrite(
                            () =>
                              deleteCredential(
                                buildDeleteCredentialRequest(
                                  targetId,
                                  credential.id,
                                ),
                              ),
                            t('admin.credentialDeletedSuccess'),
                          )
                        }
                      >
                        <Button size="small" type="danger" disabled={writeBusy}>
                          {t('admin.credentialDeleteAction')}
                        </Button>
                      </Popconfirm>
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className={styles.block}>
          <h4 className={styles.blockTitle}>{t('admin.bindingsSection')}</h4>
          {data.bindings.length === 0 ? (
            <p className={styles.muted}>{t('admin.noBindings')}</p>
          ) : (
            <ul className={styles.list}>
              {data.bindings.map((binding) => (
                <li key={binding.id.toString()} className={styles.listRow}>
                  <span className={styles.listMain}>
                    {binding.providerKey}
                    {binding.nickname !== '' ? `（${binding.nickname}）` : ''}
                  </span>
                  <span className={styles.listMeta}>
                    OpenID {binding.openId || EMPTY_TEXT} ·{' '}
                    {t('admin.boundAt', {
                      time: formatUnixTime(binding.createdAt),
                    })}
                  </span>
                  {visibility.unbindThirdparty ? (
                    <Popconfirm
                      title={t('admin.unbindConfirm', {
                        providerKey: binding.providerKey,
                      })}
                      onConfirm={() => handleUnbind(binding.providerKey)}
                    >
                      <Button size="small" type="danger" disabled={writeBusy}>
                        {t('admin.unbindAction')}
                      </Button>
                    </Popconfirm>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className={styles.block}>
          <h4 className={styles.blockTitle}>{t('admin.loginLogSection')}</h4>
          {eventsError !== undefined && !isUnauthenticatedError(eventsError) ? (
            // 区块级错误态换 Semi Banner（自带 role="alert"）。
            <Banner
              type="danger"
              fullMode={false}
              description={t('admin.loginLogLoadFailed')}
            />
          ) : (
            <DataTable<EventItem>
              columns={getEventsColumns()}
              rows={eventsData?.items ?? []}
              rowKey={eventRowKey}
              total={eventsData !== undefined ? toCount(eventsData.total) : 0}
              query={eventsQuery}
              onQueryChange={setEventsQuery}
              loading={eventsLoading}
              // success 空态判定走 deriveRequestStatus 派生（§5.3）。
              empty={
                deriveRequestStatus(eventsLoading, eventsError, eventsData) ===
                'success'
                  ? t('admin.noLoginRecords')
                  : undefined
              }
            />
          )}
        </section>
      </>
    );
  }

  const titleUser = data?.user;
  const deleteTargetName = titleUser?.username ?? '';
  const title =
    titleUser !== undefined
      ? `${t('admin.userDetailTitle')}：${titleUser.username}`
      : t('admin.userDetailTitle');

  return (
    <SideSheet
      title={title}
      visible={props.visible}
      maskClosable={false}
      onCancel={props.onClose}
      size="medium"
    >
      {content}
      <Modal
        title={t('admin.deleteUserTitle', { username: deleteTargetName })}
        visible={deleteModalOpen}
        onCancel={() => {
          if (deleteSubmitting) {
            return;
          }
          setDeleteModalOpen(false);
          setDeleteTyped('');
        }}
        onOk={() => {
          void submitDelete(deleteTargetName);
        }}
        okText={t('admin.deleteUserConfirmAction')}
        cancelText={t('admin.cancelAction')}
        confirmLoading={deleteSubmitting}
        okButtonProps={{
          type: 'danger',
          disabled:
            (deleteTypedRequired &&
              !canSubmitUserDelete(deleteTargetName, deleteTyped)) ||
            deleteSubmitting,
        }}
        cancelButtonProps={{ disabled: deleteSubmitting }}
        maskClosable={false}
      >
        <p style={{ color: '#dc2626', fontSize: 12 }}>
          {t('admin.deleteUserWarning')}
        </p>
        <p>
          {t('admin.deleteUserConfirmLabel', { username: deleteTargetName })}
        </p>
        {deleteTypedRequired && (
          <Input
            value={deleteTyped}
            onChange={(value) => setDeleteTyped(value)}
            placeholder={deleteTargetName}
            aria-label={t('admin.deleteUserInputAriaLabel')}
            autoComplete="off"
          />
        )}
      </Modal>
    </SideSheet>
  );
}
