/**
 * 个人资料页（docs/前端架构.md §5；docs/接口文档.md §3.2）：
 * 用户名（只读）、昵称（展示 + 编辑）、头像（展示 + 上传入口 + 持久化）。
 * 视觉为 Semi Card 卡片包整页（居中 + 窄屏单列），字段分「头像 /
 * 基本信息」两段两列网格，只读项带轻量标签；locale / timezone 展示
 * 可读文案（与编辑下拉选项同源映射）。
 * 头像上传入口 = AvatarUploader（前端架构 §5：组件内部仅调 useUpload，
 * 不感知 proxy / direct；配置加载中渲染禁用按钮，确定未配存储才隐藏），
 * 大头像只在页面渲染一处，上传成功回填 url 刷新本页头像展示
 * （avatarOverride 优先于 profile.avatarUrl，且保存资料时保留不清——见
 * submit onSuccess 注释）。
 *
 * 资料编辑 + UpdateProfile 持久化（docs/接口文档.md §3.2）：
 * - 编辑 / 展示两态：编辑帧 nickname（Input）+ gender（Select 枚举 0/1/2 +
 *   出域现值补项）+ birthday（DatePicker → "YYYY-MM-DD"）+ locale /
 *   timezone（可搜索 Select 预设值，服务端现值不在预设集时补项，防下拉
 *   空白与保存误清空）；
 *   username / phone / email 只读展示不进表单（§3.2 不可修改，掩码服务端
 *   完成前端零处理）；avatarUrl 不进表单（走上传链路 §10.8）；extra 不
 *   暴露编辑入口（契约保留字段，前端不读写）；
 * - 头像持久化接线：AvatarUploader onUploaded 后经 updateProfile {avatarUrl}
 *   提交，纳入 useRequest 管理（与资料保存同层受控，不裸调）；错误先走
 *   requestOptions 集中分派（401 跳登录），其余失败行内专属文案、展示不
 *   回滚（本地已刷新，服务端值以下次 GetProfile 为准）；
 * - 保存成功重取 GetProfile 刷新展示（重取优于乐观更新，服务端权威）；
 *   无改动（diff 为空）不发请求不提示。
 *
 * 结构沿 login 页族模式（ResetPage 等）：View 为纯状态帧视图
 * （renderToStaticMarkup 可测任意 status 帧），Page 为状态壳
 * （ahooks useRequest 发请求 + 集中 onError 分派）。
 *
 * 401 处理（§5）：统一走 shared/hooks/requestOptions 的集中 onError
 * （跳 `{al_root}/sso/login` 带 returnTo）；其余错误静默（toast:false）
 * 就地错误帧呈现。文案经 shared/i18n（account.* 域键）。
 */
import { useState, type ReactNode } from 'react';
import {
  Avatar,
  Banner,
  Button,
  Card,
  DatePicker,
  Divider,
  Input,
  Select,
  Spin,
  Tag,
  Toast,
} from '@douyinfe/semi-ui';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import type { ProfileResponse } from '../../gen/proto/api/account/v1/profile_pb';
import {
  deriveRequestStatus,
  type RequestStatus,
} from '../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import { PageLayout } from '@/shared/components/PageLayout';
import { AvatarUploader } from '../components/AvatarUploader';
import {
  accountReturnTo,
  apiErrorText,
  avatarPersistFailureMessage,
  buildAvatarPersistRequest,
  buildUpdateProfileRequest,
  getProfile,
  isUnauthenticatedError,
  profileGenderOptions,
  profileGenderText,
  profileLocaleOptions,
  profileLocaleText,
  profileTimezoneOptions,
  profileTimezoneText,
  updateProfile,
  type ProfileEditDraft,
  type ProfileEditFieldError,
} from '../api';
import styles from './ProfilePage.module.less';

/** 昵称为空串（protojson 省略零值 → 解码即空串）时的占位（§9 第 18 条零值兜底）。 */
const EMPTY_PLACEHOLDER = '-';

/**
 * locale / timezone 可搜索过滤：预设 label 已可读化（自称 + 分隔空格），
 * 须同时按原值匹配，IANA 名 / 语言码直搜与粘贴才不丢。
 */
const matchByValueOrLabel = (
  inputValue: string,
  option: { value?: unknown; label?: unknown },
): boolean => {
  const needle = inputValue.toLowerCase();
  return (
    String(option.value ?? '')
      .toLowerCase()
      .includes(needle) ||
    String(option.label ?? '')
      .toLowerCase()
      .includes(needle)
  );
};

/**
 * 资料编辑帧视图（纯渲染）：字段全部受控——草稿归 ProfilePage 壳持有，
 * 保存 / 校验语义在 ./api 的 buildUpdateProfileRequest（node 可测）；
 * 校验失败文案按 fieldError 键定位展示。
 */
function ProfileEditView(props: {
  draft: ProfileEditDraft;
  status: RequestStatus;
  fieldError: ProfileEditFieldError | undefined;
  error: unknown;
  onDraftChange: (draft: ProfileEditDraft) => void;
  onSave: () => void;
  onCancel: () => void;
}): ReactNode {
  const submitting = props.status === 'loading';
  const setDraft = (patch: Partial<ProfileEditDraft>): void => {
    props.onDraftChange({ ...props.draft, ...patch });
  };
  // DatePicker 受控值：YYYY-MM-DD 本地 0 点反解（无时区后缀，避免 UTC 解析在
  // 西半球展示回退一天）；'' → undefined（清空）。
  const birthdayDate =
    props.draft.birthday === ''
      ? undefined
      : new Date(`${props.draft.birthday}T00:00:00`);
  return (
    <form
      className={styles.editForm}
      onSubmit={(event) => {
        event.preventDefault();
        props.onSave();
      }}
    >
      <div className={styles.editGrid}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="account-edit-nickname">
            {t('account.nicknameLabel')}
          </label>
          <Input
            id="account-edit-nickname"
            value={props.draft.nickname}
            onChange={(value) => setDraft({ nickname: value })}
            disabled={submitting}
          />
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="account-edit-gender">
            {t('account.genderLabel')}
          </label>
          <Select
            id="account-edit-gender"
            value={props.draft.gender}
            onChange={(value) => setDraft({ gender: Number(value) })}
            optionList={profileGenderOptions(props.draft.gender)}
            disabled={submitting}
          />
        </div>
        <div className={styles.field}>
          <label
            className={styles.label}
            id="account-edit-birthday-label"
            htmlFor="account-edit-birthday"
          >
            {t('account.birthdayLabel')}
          </label>
          {/* Semi DatePickerProps 无 id 透传（触发器 div 只收 aria-*），label
              关联经 aria-labelledby 落到触发器；htmlFor 保留供组件后续透传 id。 */}
          <DatePicker
            aria-labelledby="account-edit-birthday-label"
            type="date"
            format="yyyy-MM-dd"
            value={birthdayDate}
            onChange={(_date, dateString) => {
              // type="date" 单选：dateString 即 format 产物（'YYYY-MM-DD' / 清空 '');
              // dateRange 才是 string[]，typeof 收窄保类型完整。
              setDraft({
                birthday: typeof dateString === 'string' ? dateString : '',
              });
            }}
            disabled={submitting}
            placeholder={t('common.selectPlaceholder')}
          />
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="account-edit-locale">
            {t('account.localeLabel')}
          </label>
          <Select
            id="account-edit-locale"
            filter={matchByValueOrLabel}
            value={props.draft.locale || undefined}
            onChange={(value) => setDraft({ locale: String(value) })}
            optionList={profileLocaleOptions(props.draft.locale)}
            disabled={submitting}
            placeholder={t('common.selectPlaceholder')}
          />
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="account-edit-timezone">
            {t('account.timezoneLabel')}
          </label>
          <Select
            id="account-edit-timezone"
            filter={matchByValueOrLabel}
            value={props.draft.timezone || undefined}
            onChange={(value) => setDraft({ timezone: String(value) })}
            optionList={profileTimezoneOptions(props.draft.timezone)}
            disabled={submitting}
            placeholder={t('common.selectPlaceholder')}
          />
        </div>
      </div>
      {props.fieldError !== undefined ? (
        <p role="alert" className={styles.error}>
          {t('account.birthdayInvalid')}
        </p>
      ) : null}
      {props.status === 'error' ? (
        <p role="alert" className={styles.error}>
          {apiErrorText(props.error)}
        </p>
      ) : null}
      <div className={styles.actions}>
        <Button
          theme="solid"
          htmlType="submit"
          loading={submitting}
          disabled={submitting}
        >
          {t('account.saveAction')}
        </Button>
        <Button type="tertiary" onClick={props.onCancel} disabled={submitting}>
          {t('account.cancelAction')}
        </Button>
      </div>
    </form>
  );
}

/**
 * 资料帧视图（纯渲染，无请求）：
 * - 401 未登录：渲染加载态（页面壳的 effect 随即跳登录，不就地出错误文案）；
 * - 其余请求失败：错误提示（§1.6 词汇外的页面级兜底文案）；
 * - 加载中 / 无数据：Spin；
 * - 成功：Semi Card 卡片内「头像 / 基本信息」两段（细分隔线），头像段 =
 *   单一大头像 + 昵称 + @用户名 + 上传入口（确定未配存储时该行自隐藏）
 *   + 头像持久化失败提示（专属文案，展示不回滚）；基本信息段 = 编辑 /
 *   展示两态：展示态两列网格（username / nickname / phone / email 掩码
 *   零处理 / gender / birthday / locale / timezone，只读项带轻量标签）
 *   + 编辑入口；编辑态渲染 ProfileEditView（同网格重排）。
 */
export function ProfilePageView(props: {
  status: RequestStatus;
  profile: ProfileResponse | undefined;
  error: unknown;
  /** 上传成功后的头像地址（§10.8 流程终点 {url}），优先于 profile.avatarUrl 展示。 */
  avatarOverride?: string;
  /** AvatarUploader 上传成功回调：刷新展示 + 持久化接线（壳内消化）。 */
  onAvatarUploaded?: (url: string) => void;
  /** 头像持久化失败（UpdateProfile {avatarUrl} 非 401 失败；展示不回滚）。 */
  avatarPersistFailed: boolean;
  /** 编辑 / 展示两态开关。 */
  editing: boolean;
  /** 编辑草稿（editing=true 时非 undefined）。 */
  draft: ProfileEditDraft | undefined;
  /** UpdateProfile 提交状态（编辑帧按钮态）。 */
  editStatus: RequestStatus;
  /** 本地校验失败（birthday，键定位展示）。 */
  fieldError: ProfileEditFieldError | undefined;
  /** 服务端提交错误（apiErrorText 归一展示）。 */
  editError: unknown;
  onEdit: () => void;
  onCancelEdit: () => void;
  onSaveEdit: () => void;
  onDraftChange: (draft: ProfileEditDraft) => void;
}): ReactNode {
  const { profile, error } = props;
  if (profile === undefined) {
    if (props.status === 'error' && !isUnauthenticatedError(error)) {
      // 页级加载失败裸文本 → Semi Banner（自带 role="alert"）。
      return (
        <Banner
          type="danger"
          fullMode={false}
          description={t('account.profileLoadFailed')}
        />
      );
    }
    return <Spin />;
  }
  const username = profile.username;
  const avatarUrl = props.avatarOverride ?? profile.avatarUrl;
  // 展示态两列网格行序：只读项（用户名 / 手机号 / 邮箱）带轻量标签；
  // locale / timezone 走可读文案映射，未设置为占位。
  const displayRows = [
    { label: t('account.usernameLabel'), value: username, readonly: true },
    {
      label: t('account.nicknameLabel'),
      value: profile.nickname || EMPTY_PLACEHOLDER,
      readonly: false,
    },
    // 掩码服务端完成（§3.1），前端零处理直接展示。
    {
      label: t('account.phoneLabel'),
      value: profile.phone || EMPTY_PLACEHOLDER,
      readonly: true,
    },
    {
      label: t('account.emailLabel'),
      value: profile.email || EMPTY_PLACEHOLDER,
      readonly: true,
    },
    {
      label: t('account.genderLabel'),
      value: profileGenderText(profile.profile?.gender ?? BigInt(0)),
      readonly: false,
    },
    {
      label: t('account.birthdayLabel'),
      value: profile.profile?.birthday || EMPTY_PLACEHOLDER,
      readonly: false,
    },
    {
      label: t('account.localeLabel'),
      value: profile.profile?.locale
        ? profileLocaleText(profile.profile.locale)
        : EMPTY_PLACEHOLDER,
      readonly: false,
    },
    {
      label: t('account.timezoneLabel'),
      value: profile.profile?.timezone
        ? profileTimezoneText(profile.profile.timezone)
        : EMPTY_PLACEHOLDER,
      readonly: false,
    },
  ];
  return (
    <PageLayout title={t('account.profileTitle')}>
      <div className={styles.pageContent}>
        <Card>
          <div className={styles.avatarSection}>
            <Avatar
              size="extra-large"
              src={avatarUrl || undefined}
              alt={t('account.avatarAlt')}
            >
              {username.charAt(0)}
            </Avatar>
            {profile.nickname ? (
              <div className={styles.nickname}>{profile.nickname}</div>
            ) : null}
            <div className={styles.handle}>@{username}</div>
            <AvatarUploader onUploaded={props.onAvatarUploaded} />
            {props.avatarPersistFailed ? (
              <p role="alert" className={styles.error}>
                {t('account.avatarPersistFailed')}
              </p>
            ) : null}
          </div>
          <Divider margin="16px" />
          <div className={styles.infoSection}>
            <h4 className={styles.sectionTitle}>
              {t('account.basicInfoTitle')}
            </h4>
            {props.editing && props.draft !== undefined ? (
              <ProfileEditView
                draft={props.draft}
                status={props.editStatus}
                fieldError={props.fieldError}
                error={props.editError}
                onDraftChange={props.onDraftChange}
                onSave={props.onSaveEdit}
                onCancel={props.onCancelEdit}
              />
            ) : (
              <>
                <div className={styles.infoGrid}>
                  {displayRows.map((row) => (
                    <div className={styles.infoItem} key={row.label}>
                      <div className={styles.label}>
                        {row.label}
                        {row.readonly ? (
                          <Tag size="small" color="grey">
                            {t('account.readonlyBadge')}
                          </Tag>
                        ) : null}
                      </div>
                      <div className={styles.value}>{row.value}</div>
                    </div>
                  ))}
                </div>
                <div className={styles.actions}>
                  <Button onClick={props.onEdit}>
                    {t('account.profileEditAction')}
                  </Button>
                </div>
              </>
            )}
          </div>
        </Card>
      </div>
    </PageLayout>
  );
}

/** 资料页状态壳：首次进入请求 GetProfile；401 集中 onError 跳登录（§5）。 */
export function ProfilePage(): ReactNode {
  // 自动请求 + 集中 onError（401 跳登录带 returnTo；其余静默，
  // 错误帧呈现防双报）；useLocation 在 HashRouter 下即 hash 内 location。
  const location = useLocation();
  const { data, error, loading, refresh } = useRequest(
    getProfile,
    requestOptions({
      toast: false,
      returnTo: () => accountReturnTo(location.pathname, location.search),
    }),
  );
  const status = deriveRequestStatus(loading, error, data);
  // 编辑提交（手动）：错误行内呈现（toast:false），成功链走 onSuccess——
  // 退出编辑态 + 重取 GetProfile + Toast，run 不吞错、错误进集中 onError。
  const submit = useRequest(updateProfile, {
    manual: true,
    ...requestOptions({
      toast: false,
      returnTo: () => accountReturnTo(location.pathname, location.search),
    }),
    onSuccess: () => {
      // 保存成功：退出编辑态 + 重取 GetProfile（重取优于乐观更新，服务端
      // 权威回读为准）；avatarOverride 保留不清——头像持久化与资料保存并发
      // 时，重取可能先于持久化落地拿到旧 avatarUrl，此刻清除 override 会让
      // 展示回退旧头像且不再刷新（手动刷新才恢复）；override 优先展示直到
      // 服务端值追平，是竞态消除口径。
      setEditing(false);
      refresh();
      Toast.success(t('account.profileSaved'));
    },
  });
  const editStatus = deriveRequestStatus(
    submit.loading,
    submit.error,
    submit.data,
  );
  // 头像持久化（手动）：错误先走集中分派（401 跳登录；其余静默），非 401
  // 失败再置行内专属文案（判定归 avatarPersistFailureMessage，node 可测）。
  const persistOptions = requestOptions({
    toast: false,
    returnTo: () => accountReturnTo(location.pathname, location.search),
  });
  const avatarPersist = useRequest(updateProfile, {
    manual: true,
    ...persistOptions,
    onError: (error) => {
      persistOptions.onError(error);
      if (avatarPersistFailureMessage(error) !== undefined) {
        setAvatarPersistFailed(true);
      }
    },
  });
  const [avatarOverride, setAvatarOverride] = useState<string | undefined>(
    undefined,
  );
  const [avatarPersistFailed, setAvatarPersistFailed] = useState(false);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<ProfileEditDraft | undefined>(undefined);
  const [fieldError, setFieldError] = useState<
    ProfileEditFieldError | undefined
  >(undefined);

  /** 头像上传成功（§10.8 终点 {url}）：本地刷新展示 + 持久化接线。 */
  const handleAvatarUploaded = (url: string) => {
    setAvatarOverride(url);
    // UpdateProfile {avatarUrl} 持久化（§3.2）：纳入 useRequest 管理；
    // 失败提示专属文案、展示不回滚（本地已刷新，服务端值以下次 GetProfile
    // 重取为准）；成功静默（头像已展示新值）。
    setAvatarPersistFailed(false);
    avatarPersist.run(buildAvatarPersistRequest(url));
  };

  const startEdit = () => {
    if (data === undefined) {
      return;
    }
    setDraft({
      nickname: data.nickname,
      // 0/1/2 枚举值域内 bigint → number 无精度问题（§1.12 仅 >2^53 concern）。
      gender: Number(data.profile?.gender ?? BigInt(0)),
      birthday: data.profile?.birthday ?? '',
      locale: data.profile?.locale ?? '',
      timezone: data.profile?.timezone ?? '',
    });
    setFieldError(undefined);
    setEditing(true);
  };

  const handleSaveEdit = () => {
    if (data === undefined || draft === undefined) {
      return;
    }
    const built = buildUpdateProfileRequest(data, draft);
    if (!built.ok) {
      setFieldError(built.error);
      return;
    }
    setFieldError(undefined);
    // 无改动：不发请求、不提示、不退出编辑态（服务端空操作无需重放）。
    if (!built.changed) {
      return;
    }
    // 成功链在 onSuccess；错误由集中 onError 静默（行内 apiErrorText 呈现）。
    submit.run(built.request);
  };

  return (
    <ProfilePageView
      status={status}
      profile={data}
      error={error}
      avatarOverride={avatarOverride}
      onAvatarUploaded={handleAvatarUploaded}
      avatarPersistFailed={avatarPersistFailed}
      editing={editing}
      draft={draft}
      editStatus={editStatus}
      fieldError={fieldError}
      editError={submit.error}
      onEdit={startEdit}
      onCancelEdit={() => setEditing(false)}
      onSaveEdit={handleSaveEdit}
      onDraftChange={setDraft}
    />
  );
}
