/**
 * 个人资料页（docs/前端架构.md §5 行 513；docs/接口文档.md §3.2 行 831-837）：
 * 用户名（只读）、昵称（展示 + 编辑）、头像（展示 + 上传入口 + 持久化）；GetProfile
 * 真实消费（后端已实装）。头像上传入口 = AvatarUploader（前端架构
 * §5 行 503：组件内部仅调 useUpload，不感知 proxy / direct；零值投影
 * 隐藏入口），上传成功回填 url 刷新本页头像展示（avatarOverride 优先于
 * profile.avatarUrl）。
 *
 * 资料编辑 + UpdateProfile 持久化（后端 account 域桩未实装，按接口契约
 * 消费、msw mock 覆盖，不因 mock 放宽契约）：
 * - 编辑 / 展示两态：编辑帧 nickname（Input）+ gender（Select 枚举 0/1/2）+
 *   birthday（DatePicker → "YYYY-MM-DD"）+ locale / timezone（Input）+
 *   extra（就地 JSON textarea + 提交前解析校验，沿 admin JsonEditor
 *   零依赖先例）；username / phone / email 只读展示不进表单（§3.2 行
 *   837 不可修改，掩码服务端完成前端零处理）；avatarUrl 不进表单（走上传
 *   链路 §10.8）；
 * - 头像持久化接线：AvatarUploader onUploaded 后经 updateProfile {avatarUrl}
 *   提交；失败提示 §1.6 failed
 *   兜底文案、不回滚展示（裁量：本地已刷新，服务端值以下次 GetProfile 重取
 *   为准）；
 * - 保存成功重取 GetProfile 刷新展示（裁量：重取优于乐观更新，服务端权威）。
 *
 * 结构沿 login 页族模式（ResetPage 等）：View 为纯状态帧视图
 * （renderToStaticMarkup 可测任意 status 帧），Page 为状态壳
 * （ahooks useRequest 发请求 + 集中 onError 分派）。
 *
 * 401 处理（§5 行 480）：统一走 shared/hooks/requestOptions 的集中
 * onError（跳 `{al_root}/sso/login` 带 returnTo）；其余错误
 * 静默（toast:false）就地错误帧呈现。例外：头像持久化（手写保留点，
 * §5.4-#7）与改密成功后的延时跳登录（PasswordChangeForm）仍内联。
 * 文案经 shared/i18n（account.* 域键）。
 */
import { useState, type ReactNode } from 'react';
import {
  Avatar,
  Banner,
  Button,
  DatePicker,
  Descriptions,
  Input,
  Select,
  Spin,
  Toast,
  Typography,
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
import { AvatarUploader } from '../components/AvatarUploader';
import {
  accountReturnTo,
  apiErrorText,
  buildAvatarPersistRequest,
  buildUpdateProfileRequest,
  getProfile,
  isUnauthenticatedError,
  profileGenderText,
  updateProfile,
  type ProfileEditDraft,
  type ProfileEditFieldError,
} from '../api';
import styles from './ProfilePage.module.less';

/** 昵称为空串（protojson 省略零值 → 解码即空串）时的占位（§9 第 18 条零值兜底）。 */
const EMPTY_PLACEHOLDER = '-';

/**
 * 资料编辑帧视图（纯渲染）：字段全部受控——草稿归 ProfilePage 壳持有，
 * 保存 / 校验语义在 ./api 的 buildUpdateProfileRequest（node 可测；Semi 渲染
 * 测试 blocker 见 account.test.tsx 头注）。extra 编辑裁量：就地 JSON
 * textarea + 解析校验，不提升 shared、不引第三方（沿 admin JsonEditor 先例
 * 零依赖形态）——校验失败文案按 fieldError 键定位展示。
 */
function ProfileEditView(props: {
  /** GetProfile 原值：extra 未编辑时展示基线对象文本。 */
  profile: ProfileResponse;
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
  // extraText undefined = 未编辑 → 展示基线对象文本；onChange 后即用户文本。
  const extraText =
    props.draft.extraText ??
    JSON.stringify(props.profile.profile?.extra ?? {}, null, 2);
  return (
    <form
      className={styles.editForm}
      onSubmit={(event) => {
        event.preventDefault();
        props.onSave();
      }}
    >
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
          value={props.draft.gender}
          onChange={(value) => setDraft({ gender: Number(value) })}
          disabled={submitting}
        >
          <Select.Option value={0}>{t('account.genderSecret')}</Select.Option>
          <Select.Option value={1}>{t('account.genderMale')}</Select.Option>
          <Select.Option value={2}>{t('account.genderFemale')}</Select.Option>
        </Select>
      </div>
      <div className={styles.field}>
        <label className={styles.label} htmlFor="account-edit-birthday">
          {t('account.birthdayLabel')}
        </label>
        <DatePicker
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
        <Input
          id="account-edit-locale"
          value={props.draft.locale}
          onChange={(value) => setDraft({ locale: value })}
          disabled={submitting}
        />
      </div>
      <div className={styles.field}>
        <label className={styles.label} htmlFor="account-edit-timezone">
          {t('account.timezoneLabel')}
        </label>
        <Input
          id="account-edit-timezone"
          value={props.draft.timezone}
          onChange={(value) => setDraft({ timezone: value })}
          disabled={submitting}
        />
      </div>
      <div className={styles.field}>
        <label className={styles.label} htmlFor="account-edit-extra">
          {t('account.extraLabel')}
        </label>
        <textarea
          id="account-edit-extra"
          className={styles.extraInput}
          value={extraText}
          onChange={(event) => setDraft({ extraText: event.target.value })}
          disabled={submitting}
          aria-label={t('account.extraLabel')}
          rows={6}
          spellCheck={false}
          placeholder={t('account.extraPlaceholder')}
        />
      </div>
      {props.fieldError !== undefined ? (
        <p role="alert" className={styles.error}>
          {props.fieldError === 'invalid_birthday'
            ? t('account.birthdayInvalid')
            : t('account.extraInvalidJson')}
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
 * - 成功：标题 + 头像 + AvatarUploader 上传入口（零值投影时组件自隐藏，
 *   §3.2 行 842）+ 头像持久化失败提示（§1.6 failed 兜底文案，不回滚展示）
 *   + 编辑 / 展示两态：展示态明细（username / nickname / phone /
 *   email 掩码零处理 / gender / birthday / locale / timezone）+ 编辑入口；
 *   编辑态渲染 ProfileEditView。
 */
export function ProfilePageView(props: {
  status: RequestStatus;
  profile: ProfileResponse | undefined;
  error: unknown;
  /** 上传成功后的头像地址（§10.8 流程终点 {url}），优先于 profile.avatarUrl 展示。 */
  avatarOverride?: string;
  /** AvatarUploader 上传成功回调：刷新展示 + 持久化接线（壳内消化）。 */
  onAvatarUploaded?: (url: string) => void;
  /** 头像持久化失败（UpdateProfile {avatarUrl} 提交失败；展示不回滚）。 */
  avatarPersistFailed: boolean;
  /** 编辑 / 展示两态开关。 */
  editing: boolean;
  /** 编辑草稿（editing=true 时非 undefined）。 */
  draft: ProfileEditDraft | undefined;
  /** UpdateProfile 提交状态（编辑帧按钮态）。 */
  editStatus: RequestStatus;
  /** 本地校验失败（birthday / extra，键定位展示）。 */
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
  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>
        {t('account.profileTitle')}
      </Typography.Title>
      <div className={styles.avatarRow}>
        <Avatar
          size="large"
          src={avatarUrl || undefined}
          alt={t('account.avatarAlt')}
        >
          {username.charAt(0)}
        </Avatar>
        <Typography.Text type="secondary">{username}</Typography.Text>
      </div>
      <AvatarUploader
        currentUrl={avatarUrl}
        onUploaded={props.onAvatarUploaded}
      />
      {props.avatarPersistFailed ? (
        <p role="alert" className={styles.error}>
          {t('errors.status.failed')}
        </p>
      ) : null}
      {props.editing && props.draft !== undefined ? (
        <ProfileEditView
          profile={profile}
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
          <Descriptions
            data={[
              { key: t('account.usernameLabel'), value: username },
              {
                key: t('account.nicknameLabel'),
                value: profile.nickname || EMPTY_PLACEHOLDER,
              },
              // 掩码服务端完成（§3.1 行 818-829），前端零处理直接展示。
              {
                key: t('account.phoneLabel'),
                value: profile.phone || EMPTY_PLACEHOLDER,
              },
              {
                key: t('account.emailLabel'),
                value: profile.email || EMPTY_PLACEHOLDER,
              },
              {
                key: t('account.genderLabel'),
                value: profileGenderText(profile.profile?.gender ?? BigInt(0)),
              },
              {
                key: t('account.birthdayLabel'),
                value: profile.profile?.birthday || EMPTY_PLACEHOLDER,
              },
              {
                key: t('account.localeLabel'),
                value: profile.profile?.locale || EMPTY_PLACEHOLDER,
              },
              {
                key: t('account.timezoneLabel'),
                value: profile.profile?.timezone || EMPTY_PLACEHOLDER,
              },
            ]}
          />
          <Button onClick={props.onEdit}>
            {t('account.profileEditAction')}
          </Button>
        </>
      )}
    </section>
  );
}

/** 资料页状态壳：首次进入请求 GetProfile；401 集中 onError 跳登录（§5 行 480）。 */
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
      // 保存成功：退出编辑态 + 重取 GetProfile（裁量：重取优于乐观更新，
      // 服务端权威回读为准）；avatarOverride 一并清除——重取后以服务端
      // avatarUrl 为准（若此前头像持久化失败，此处回到服务端旧值属预期，
      // 持久化失败提示已单独呈现）。成功反馈接 Semi Toast（P1-6）。
      setEditing(false);
      setAvatarOverride(undefined);
      refresh();
      Toast.success(t('account.profileSaved'));
    },
  });
  const editStatus = deriveRequestStatus(
    submit.loading,
    submit.error,
    submit.data,
  );
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
    // UpdateProfile {avatarUrl} 持久化（§3.2 行 837）：失败
    // 提示 §1.6 failed 兜底文案、展示不回滚（裁量：本地已刷新，服务端值以
    // 下次 GetProfile 重取为准）；成功静默（头像已展示新值）。
    setAvatarPersistFailed(false);
    updateProfile(buildAvatarPersistRequest(url)).catch(() => {
      setAvatarPersistFailed(true);
    });
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
      extraText: undefined,
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
