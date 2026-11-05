/**
 * 个人资料页（docs/前端架构.md §5 行 491；docs/接口文档.md §3.2 行 819 / §3.1）：
 * 用户名（只读）、昵称（展示）、头像（展示；上传归后续 AvatarUploader，
 * 本次只消费 avatarUrl）；GetProfile 真实消费（后端已实装）。
 * UpdateProfile 后端仍为桩，昵称编辑表单不落本次实现。
 *
 * 结构沿 login 页族模式（ResetPage 等）：View 为纯状态帧视图
 * （renderToStaticMarkup 可测任意 status 帧），Page 为状态壳
 * （useRequest 发请求 + 401 统一跳登录）。
 *
 * 401 处理（§5 行 480）：GetProfile 返回未登录 → window.location.replace
 * 跳 `{al_root}/sso/login`（AppLayout 层无请求，跳转逻辑经 ./api 的
 * isUnauthenticatedError + ./bootstrap 的 loginUrl 由页面层统一实现，
 * 后续页面复用同一对工具）；其余错误就地提示。
 * 文案经 shared/i18n（account.* 域键）。
 */
import { useEffect, type ReactNode } from 'react';
import { Avatar, Descriptions, Spin, Typography } from '@douyinfe/semi-ui-19';
import type { ProfileResponse } from '../../gen/proto/api/account/v1/profile_pb';
import { useRequest, type RequestStatus } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import { getProfile, isUnauthenticatedError } from '../api';
import { loadAccountBootstrap, loginUrl } from '../bootstrap';
import styles from './ProfilePage.module.less';

/** 昵称为空串（protojson 省略零值 → 解码即空串）时的占位（§9 第 18 条零值兜底）。 */
const EMPTY_PLACEHOLDER = '-';

/**
 * 资料帧视图（纯渲染，无请求）：
 * - 401 未登录：渲染加载态（页面壳的 effect 随即跳登录，不就地出错误文案）；
 * - 其余请求失败：错误提示（§1.6 词汇外的页面级兜底文案）；
 * - 加载中 / 无数据：Spin；
 * - 成功：标题 + 头像 + 用户名（只读）+ 昵称。
 */
export function ProfilePageView(props: {
  readonly status: RequestStatus;
  readonly profile: ProfileResponse | undefined;
  readonly error: unknown;
}): ReactNode {
  const { profile, error } = props;
  if (profile === undefined) {
    if (props.status === 'error' && !isUnauthenticatedError(error)) {
      return <p role="alert">{t('account.profileLoadFailed')}</p>;
    }
    return <Spin />;
  }
  const username = profile.username;
  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>{t('account.profileTitle')}</Typography.Title>
      <div className={styles.avatarRow}>
        <Avatar size="large" src={profile.avatarUrl || undefined} alt={t('account.avatarAlt')}>
          {username.charAt(0)}
        </Avatar>
        <Typography.Text type="secondary">
          {username}
        </Typography.Text>
      </div>
      <Descriptions
        data={[
          { key: t('account.usernameLabel'), value: username },
          { key: t('account.nicknameLabel'), value: profile.nickname || EMPTY_PLACEHOLDER },
        ]}
      />
    </section>
  );
}

/** 资料页状态壳：首次进入请求 GetProfile；401 统一跳登录（§5 行 480）。 */
export function ProfilePage(): ReactNode {
  const { status, data, error, run } = useRequest(getProfile);
  const alRoot = loadAccountBootstrap().alRoot;
  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §5 行 480：401 统一跳登录（replace：资料页不可回退占位）。
      window.location.replace(loginUrl(alRoot));
    }
  }, [error, alRoot]);
  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防 unhandled rejection；
    // 错误呈现 / 401 跳转均由上 effect + View 帧 处理。
    run().catch(() => {});
  }, [run]);
  return <ProfilePageView status={status} profile={data} error={error} />;
}
