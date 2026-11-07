/**
 * 修改密码表单（docs/前端架构.md §5 行 483；docs/接口文档.md §3.3 行 854-863）：
 * hasPassword（GetConfig 下发，§3.2 行 819）驱动当前密码必填——false 为首设
 * 密码场景，currentPassword 省略；新密码实时过 PasswordStrengthMeter（§5.6
 * 同源预校验，服务端 password_weak 权威）。成功为空响应 + 全会话失效
 * （需求 §4.1.9）→ 提示「已退出登录，请重新登录」并跳登录页。
 *
 * 结构沿 ProfilePage 模式：View 为纯状态帧视图，Form 为状态壳
 * （useRequest 提交 + 成功后延时跳转）。请求构造 / 错误文案纯逻辑在 ./api
 * （node 可测；Semi 渲染测试 blocker 见 account.test.tsx 头注）。
 * 文案经 shared/i18n（account.* 域键）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Button, Input, Toast } from '@douyinfe/semi-ui-19';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { PasswordStrengthMeter } from '../../shared/components/PasswordStrengthMeter';
import {
  deriveRequestStatus,
  type RequestStatus,
} from '../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import {
  accountReturnTo,
  apiErrorText,
  buildChangePasswordRequest,
  changePassword,
  type PasswordChangeFieldError,
} from '../api';
import { loadAccountBootstrap, loginUrl } from '../bootstrap';
import styles from './PasswordChangeForm.module.less';

/** 成功帧停留时长（ms）：提示可读后跳登录页（§5 行 483「提示并跳登录页」）。 */
const REDIRECT_DELAY_MS = 1500;

/**
 * 改密帧视图（纯渲染，无请求）：
 * 表单 → 当前密码（hasPassword 时）+ 新密码 + 确认新密码（A-1，只本地比对）
 * + 强度提示 + 错误提示；成功后壳清空表单 + Toast 并延时跳登录页，done 期间
 * 全表单禁用防重复提交。
 */
export function PasswordChangeFormView(props: {
  readonly hasPassword: boolean;
  readonly status: RequestStatus;
  readonly done: boolean;
  readonly currentPassword: string;
  readonly newPassword: string;
  readonly confirmPassword: string;
  readonly fieldError: PasswordChangeFieldError | undefined;
  /** 确认密码与新密码不一致（A-1：只本地比对，不进 payload，不发请求）。 */
  readonly mismatch: boolean;
  readonly submitError: unknown;
  readonly onCurrentPasswordChange: (value: string) => void;
  readonly onNewPasswordChange: (value: string) => void;
  readonly onConfirmPasswordChange: (value: string) => void;
  readonly onSubmit: () => void;
}): ReactNode {
  // 成功后清空表单并 Toast（壳已清值），done 期间禁再提交，等跳转登录页。
  const submitting = props.status === 'loading' || props.done;
  return (
    <form
      className={styles.form}
      onSubmit={(event) => {
        event.preventDefault();
        props.onSubmit();
      }}
    >
      {props.hasPassword ? (
        <div className={styles.field}>
          <label className={styles.label} htmlFor="account-current-password">
            {t('account.currentPasswordLabel')}
          </label>
          <Input
            id="account-current-password"
            mode="password"
            value={props.currentPassword}
            onChange={props.onCurrentPasswordChange}
            disabled={submitting}
            autoComplete="current-password"
          />
        </div>
      ) : null}
      <div className={styles.field}>
        <label className={styles.label} htmlFor="account-new-password">
          {t('account.newPasswordLabel')}
        </label>
        <Input
          id="account-new-password"
          mode="password"
          value={props.newPassword}
          onChange={props.onNewPasswordChange}
          disabled={submitting}
          autoComplete="new-password"
        />
        {/* §4.3：密码强度提示仅注册 / 改密 / 重置场景渲染（复用既有组件）。 */}
        <PasswordStrengthMeter password={props.newPassword} />
      </div>
      {/* A-1：确认新密码（mode=password 自带显隐眼睛）；不一致行内报错不发请求。 */}
      <div className={styles.field}>
        <label className={styles.label} htmlFor="account-confirm-new-password">
          {t('account.confirmPasswordLabel')}
        </label>
        <Input
          id="account-confirm-new-password"
          mode="password"
          value={props.confirmPassword}
          onChange={props.onConfirmPasswordChange}
          disabled={submitting}
          autoComplete="new-password"
        />
      </div>
      {props.mismatch ? (
        <p role="alert" className={styles.error}>
          {t('account.confirmPasswordMismatch')}
        </p>
      ) : null}
      {props.fieldError?.field === 'currentPassword' ? (
        <p role="alert" className={styles.error}>
          {t('account.currentPasswordRequired')}
        </p>
      ) : null}
      {props.status === 'error' ? (
        <p role="alert" className={styles.error}>
          {apiErrorText(props.submitError, {
            invalid_credentials: t('account.currentPasswordIncorrect'),
          })}
        </p>
      ) : null}
      <Button
        theme="solid"
        htmlType="submit"
        loading={submitting}
        disabled={submitting}
      >
        {props.hasPassword ? t('account.changePasswordAction') : t('account.setPasswordAction')}
      </Button>
    </form>
  );
}

/** 改密状态壳：本地校验 → ChangePassword；成功 → 全会话失效，延时跳登录页。 */
export function PasswordChangeForm(props: {
  /** 当前用户是否已有 kind=password 凭证（GetConfig.hasPassword，§3.2 行 819）。 */
  readonly hasPassword: boolean;
}): ReactNode {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [mismatch, setMismatch] = useState(false);
  const [fieldError, setFieldError] = useState<PasswordChangeFieldError | undefined>(
    undefined,
  );
  const [done, setDone] = useState(false);
  const alRoot = loadAccountBootstrap().alRoot;
  // useLocation 在 HashRouter 下即 hash 内 location——
  // done 跳转与集中 onError 的 401 returnTo 共用同一拼装（accountReturnTo）。
  const location = useLocation();
  // 手动提交：错误行内呈现（toast:false 防双报），成功链走 onSuccess——
  // 清空表单 + Toast（P1-6 统一通道；文案含「已退出登录」语义）+ done 驱动
  // 延时跳登录页（全会话失效契约不变）。run 不吞错、错误进集中 onError。
  const { data, error, loading, run } = useRequest(changePassword, {
    manual: true,
    ...requestOptions({
      toast: false,
      returnTo: () => accountReturnTo(location.pathname, location.search),
    }),
    onSuccess: () => {
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      Toast.success(t('account.passwordChangedDone'));
      setDone(true);
    },
  });
  const status = deriveRequestStatus(loading, error, data);

  // §3.3 行 863：改密成功 → 当前会话与全部令牌失效——短暂停留展示提示后
  // 跳登录页（§5 行 483；与 401 同一 loginUrl，replace 防回退到已失效会话页）。
  // 同样带 returnTo（重登后回安全页；本组件恒渲染于 /security 路由内）。
  useEffect(() => {
    if (!done) {
      return;
    }
    const timer = window.setTimeout(() => {
      window.location.replace(loginUrl(alRoot, accountReturnTo(location.pathname, location.search)));
    }, REDIRECT_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [done, alRoot, location]);

  const handleSubmit = () => {
    const built = buildChangePasswordRequest(props.hasPassword, currentPassword, newPassword);
    if (!built.ok) {
      setFieldError(built.error);
      return;
    }
    setFieldError(undefined);
    // A-1：确认密码只本地比对（不进 payload，沿 RegisterPage 同款）；
    // 不一致行内报错不发请求，并聚焦确认框（Semi Input 无公开 focus 方法，
    // 走原生 DOM id）。
    if (newPassword !== confirmPassword) {
      setMismatch(true);
      if (typeof document !== 'undefined') {
        document.getElementById('account-confirm-new-password')?.focus();
      }
      return;
    }
    setMismatch(false);
    // 成功链在 onSuccess（清空表单 + Toast + done 延时跳登录，全会话失效契约不变）；
    // 错误进集中 onError（toast:false 静默，行内 apiErrorText 呈现）。
    run(built.request);
  };

  return (
    <PasswordChangeFormView
      hasPassword={props.hasPassword}
      status={status}
      done={done}
      currentPassword={currentPassword}
      newPassword={newPassword}
      confirmPassword={confirmPassword}
      fieldError={fieldError}
      mismatch={mismatch}
      submitError={error}
      onCurrentPasswordChange={setCurrentPassword}
      onNewPasswordChange={(value) => {
        setNewPassword(value);
        setMismatch(false);
      }}
      onConfirmPasswordChange={(value) => {
        setConfirmPassword(value);
        setMismatch(false);
      }}
      onSubmit={handleSubmit}
    />
  );
}
