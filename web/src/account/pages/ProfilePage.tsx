/**
 * 个人资料页（docs/前端架构.md §5 行 513；docs/接口文档.md §3.2 行 831-837）：
 * 用户名（只读）、昵称（展示）、头像（展示 + 上传入口）；GetProfile 真实消费
 * （后端已实装）。头像上传入口 = AvatarUploader（前端架构
 * §5 行 503：组件内部仅调 useUpload，不感知 proxy / direct；零值投影隐藏入口），
 * 上传成功回填 url 刷新本页头像展示（avatarOverride 优先于 profile.avatarUrl）；
 * 持久化到用户资料归 UpdateProfile（后端仍为桩，随其实装接线，昵称
 * 编辑表单同批）。
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
import { useEffect, useState, type ReactNode } from 'react';
import { Avatar, Descriptions, Spin, Typography } from '@douyinfe/semi-ui-19';
import type { ProfileResponse } from '../../gen/proto/api/account/v1/profile_pb';
import { useRequest, type RequestStatus } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import { AvatarUploader } from '../components/AvatarUploader';
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
 * - 成功：标题 + 头像 + 用户名（只读）+ 昵称 + AvatarUploader 上传入口
 *   （零值投影时组件自隐藏，§3.2 行 842；成功帧挂载使 GetConfig 随资料
 *   就绪才发起）。
 */
export function ProfilePageView(props: {
  readonly status: RequestStatus;
  readonly profile: ProfileResponse | undefined;
  readonly error: unknown;
  /** 上传成功后的头像地址（§10.8 流程终点 {url}），优先于 profile.avatarUrl 展示。 */
  readonly avatarOverride?: string;
  /** AvatarUploader 上传成功回调：刷新本页头像展示。 */
  readonly onAvatarUploaded?: (url: string) => void;
}): ReactNode {
  const { profile, error } = props;
  if (profile === undefined) {
    if (props.status === 'error' && !isUnauthenticatedError(error)) {
      return <p role="alert">{t('account.profileLoadFailed')}</p>;
    }
    return <Spin />;
  }
  const username = profile.username;
  const avatarUrl = props.avatarOverride ?? profile.avatarUrl;
  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>{t('account.profileTitle')}</Typography.Title>
      <div className={styles.avatarRow}>
        <Avatar size="large" src={avatarUrl || undefined} alt={t('account.avatarAlt')}>
          {username.charAt(0)}
        </Avatar>
        <Typography.Text type="secondary">
          {username}
        </Typography.Text>
      </div>
      <AvatarUploader currentUrl={avatarUrl} onUploaded={props.onAvatarUploaded} />
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
  const [avatarOverride, setAvatarOverride] = useState<string | undefined>(undefined);
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
  return (
    <ProfilePageView
      status={status}
      profile={data}
      error={error}
      avatarOverride={avatarOverride}
      onAvatarUploaded={setAvatarOverride}
    />
  );
}
