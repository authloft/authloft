/**
 * 绑定选择（docs/前端架构.md §4.4 行 468；docs/接口文档.md §2.7.5 行 654-676）：
 * status=binding_required 时绑定中间态的两个分支与提示。
 *
 * - 两选项（§2.7.5 行 656-661）：创建新账号 / 退出并使用其他账号登录——
 *   **仅此两项**，不渲染「绑定已有账号」分支（§2.7.5 行 676：把三方身份
 *   绑到已有账号走登录后安全中心 §3.7，不经登录流程）；
 * - 信封 binding.allowSignup=false（Provider enable_signup=0 映射，§2.7.5
 *   行 665）→ 「创建新账号」置灰不可选 + 提示「该渠道未开放注册」，只保留
 *   退出项（§2.7.5 行 663 口径：流程分支不变，服务端仍会拒绝建号请求）；
 * - allowSignup=true（enable_signup=1）时两项均可选。
 *
 * 文案：绑定分支专属文案经 i18n 字典 login.* 键取用。
 */
import { t } from '../../shared/i18n';
import styles from './BindingChoice.module.less';

export interface BindingChoiceProps {
  /** 三方身份名（binding.displayName）；空串零值兜底不渲染身份行（§9 第 18 条）。 */
  readonly displayName: string;
  /** 信封 binding.allowSignup（enable_signup 映射，§2.7.5 行 665）。 */
  readonly allowSignup: boolean;
  /** 选「创建新账号」（置灰时不可达，§2.7.5 行 660）。 */
  onCreateAccount: () => void;
  /** 选「退出并使用其他账号登录」（§2.7.5 行 661：清 login_token 回 /sso/login）。 */
  onExit: () => void;
}

export function BindingChoice({
  displayName,
  allowSignup,
  onCreateAccount,
  onExit,
}: BindingChoiceProps) {
  return (
    <div className={styles.section}>
      {displayName !== '' && (
        <p className={styles.identity}>
          {t('login.bindingIdentity', { name: displayName })}
        </p>
      )}
      <button
        type="button"
        className={styles.optionBtn}
        disabled={!allowSignup}
        onClick={onCreateAccount}
      >
        {t('login.createAccountOption')}
      </button>
      {!allowSignup && (
        <p className={styles.signupClosed}>{t('login.channelSignupClosed')}</p>
      )}
      <button type="button" className={styles.optionBtn} onClick={onExit}>
        {t('login.exitBinding')}
      </button>
    </div>
  );
}
