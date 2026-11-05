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
 * 文案无 i18n 键：中文字面量 + 注释声明，扩键归后续 i18n 实现。
 */
import { useEffect, useState, type ReactNode } from 'react';
// 子路径 import（同 ProfilePage 口径：避免全量入口，测试链 / 产物见其注释）。
import Button from '@douyinfe/semi-ui/lib/es/button';
import Input from '@douyinfe/semi-ui/lib/es/input';
import { PasswordStrengthMeter } from '../../shared/components/PasswordStrengthMeter';
import { useRequest, type RequestStatus } from '../../shared/hooks/useRequest';
import {
  apiErrorText,
  buildChangePasswordRequest,
  changePassword,
  type PasswordChangeFieldError,
} from '../api';
import { loadAccountBootstrap, loginUrl } from '../bootstrap';
import styles from './PasswordChangeForm.module.less';

/** 成功帧停留时长（ms）：提示可读后跳登录页（§5 行 483「提示并跳登录页」）。 */
const REDIRECT_DELAY_MS = 1500;

/** hasPassword=true 且当前密码为空的本地提示（§3.3 行 860 必填）。 */
const CURRENT_PASSWORD_REQUIRED_TEXT = '请输入当前密码';

/** invalid_credentials 在改密语境的覆写（当前密码校验失败，apiErrorText 的 overrides）。 */
const INVALID_CREDENTIALS_TEXT = '当前密码不正确';

/**
 * 改密帧视图（纯渲染，无请求）：
 * 成功 → 「已退出登录，请重新登录」（壳的 effect 随即跳登录页）；
 * 表单 → 当前密码（hasPassword 时）+ 新密码 + 强度提示 + 错误提示。
 */
export function PasswordChangeFormView(props: {
  readonly hasPassword: boolean;
  readonly status: RequestStatus;
  readonly done: boolean;
  readonly currentPassword: string;
  readonly newPassword: string;
  readonly fieldError: PasswordChangeFieldError | undefined;
  readonly submitError: unknown;
  readonly onCurrentPasswordChange: (value: string) => void;
  readonly onNewPasswordChange: (value: string) => void;
  readonly onSubmit: () => void;
}): ReactNode {
  if (props.done) {
    return (
      <div role="status" className={styles.done}>
        密码修改成功，已退出登录，请重新登录
      </div>
    );
  }
  const submitting = props.status === 'loading';
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
            当前密码
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
          新密码
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
      {props.fieldError?.field === 'currentPassword' ? (
        <p role="alert" className={styles.error}>
          {CURRENT_PASSWORD_REQUIRED_TEXT}
        </p>
      ) : null}
      {props.status === 'error' ? (
        <p role="alert" className={styles.error}>
          {apiErrorText(props.submitError, {
            invalid_credentials: INVALID_CREDENTIALS_TEXT,
          })}
        </p>
      ) : null}
      <Button
        theme="solid"
        htmlType="submit"
        loading={submitting}
        disabled={submitting}
      >
        {props.hasPassword ? '修改密码' : '设置密码'}
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
  const [fieldError, setFieldError] = useState<PasswordChangeFieldError | undefined>(
    undefined,
  );
  const [done, setDone] = useState(false);
  const { status, error, run } = useRequest(changePassword);
  const alRoot = loadAccountBootstrap().alRoot;

  // §3.3 行 863：改密成功 → 当前会话与全部令牌失效——短暂停留展示提示后
  // 跳登录页（§5 行 483；与 401 同一 loginUrl，replace 防回退到已失效会话页）。
  useEffect(() => {
    if (!done) {
      return;
    }
    const timer = window.setTimeout(() => {
      window.location.replace(loginUrl(alRoot));
    }, REDIRECT_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [done, alRoot]);

  const handleSubmit = () => {
    const built = buildChangePasswordRequest(props.hasPassword, currentPassword, newPassword);
    if (!built.ok) {
      setFieldError(built.error);
      return;
    }
    setFieldError(undefined);
    // run 失败会 rethrow（错误已入 state），吞掉防 unhandled rejection；
    // 竞态丢弃（undefined）不切成功帧。
    run(built.request)
      .then((result) => {
        if (result !== undefined) {
          setDone(true);
        }
      })
      .catch(() => {});
  };

  return (
    <PasswordChangeFormView
      hasPassword={props.hasPassword}
      status={status}
      done={done}
      currentPassword={currentPassword}
      newPassword={newPassword}
      fieldError={fieldError}
      submitError={error}
      onCurrentPasswordChange={setCurrentPassword}
      onNewPasswordChange={setNewPassword}
      onSubmit={handleSubmit}
    />
  );
}
