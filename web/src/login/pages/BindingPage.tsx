/**
 * 绑定页（docs/前端架构.md §4.4 行 466；docs/接口文档.md §2.7.5）：
 * status=binding_required 时的两个选项——创建新账号 / 退出并使用其他账号登录。
 * 由 LoginContainer 的 binding_required 分支**原地渲染**（§4.1 行 406「绑定
 * 选择页」；不跳路由，/sso/binding 不在路由表）。
 *
 * 两个选项（§2.7.5 行 656-661，仅此两项，无「绑定已有账号」分支）：
 * - 创建新账号 → **原地引入注册表单**（复用注册链路纯函数：runFlowStep /
 *   flowTerminalUrl / ssoPath / isFlowErrorStatus / RESTART_STATUSES + api.register）：
 *   三方免密建号走 SsoService/Register 的 set_password 步、仅提交 username
 *   （§2.7.5 行 660 / 行 672，login_token.tp 非空、服务端忽略 password）。
 *   不跳 /sso/register 的原因：login_token 仅存内存（§1.3 行 145 禁止持久化），
 *   location.replace 整页跳转即丢失 → 免密建号无法完成；且 /sso/register 渲染
 *   普通注册页（flags.registration 开关 + 三方式 tabs + 密码表单），与免密建号
 *   语义不符。§4.4 行 466 即按原地注册表单落地。
 * - 退出并使用其他账号登录 → 不发请求：清空内存 login_token →
 *   location.replace 到 /sso/login（§2.7.5 行 661，exitBinding）。
 *
 * 信封 binding 的 nickname / avatarUrl 本实现不渲染（§4.4 行 466-468 未规定
 * 用场，视觉完善归后续样式实现）。免密建号请求的 method 取值文档未显式规定
 * （§2.3 方式白名单不覆盖三方路径），取登录域三方方式名 'thirdparty'
 * （服务端按 login_token.tp 判定免密建号，§2.7.5 行 667-672）。
 *
 * 文案：绑定页专属（身份行 / 按钮名 / 成功提示）经 i18n 字典 login.* 键取用。
 */
import { useState, type FormEvent } from 'react';
import type {
  Binding,
  LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import { resolveFlowStatus } from '../../shared/api/errors';
import { ErrorBanner } from '../../shared/components';
import { isValidUsername } from '../../shared/utils/validate';
import { t } from '../../shared/i18n';
import { register, type RegisterInput } from '../api';
import { clearLoginToken } from '../loginTokenStore';
import {
  RESTART_STATUSES,
  flowTerminalUrl,
  isFlowErrorStatus,
  runFlowStep,
  ssoPath,
} from './RegisterPage';
import { BindingChoice } from '../binding/BindingChoice';
import styles from './BindingPage.module.less';

// ---------------------------------------------------------------------------
// 纯函数（node 可测；建号载荷 / 退出动作是本实现契约落点）
// ---------------------------------------------------------------------------

/**
 * 免密建号请求的 method 取值（见文件头）：绑定中间态由三方
 * 登录进入（信封 binding.providerKey 标识来源），登录域方式名为 thirdparty；
 * 服务端按 login_token.tp 判定免密建号（§2.7.5 行 667-672）。
 */
export const BINDING_REGISTER_METHOD = 'thirdparty';

/** RegisterPayload 的 init 形状（login/api.ts 的 RegisterInput.payload）。 */
type RegisterPayloadInit = NonNullable<RegisterInput['payload']>;

/**
 * 免密建号载荷（§2.7.5 行 660 / 行 672：login_token.tp 非空 → 仅提交
 * {username}，服务端忽略请求中的 password）。
 */
export function createAccountPayload(username: string): RegisterPayloadInit {
  return { username };
}

/**
 * 退出动作（§2.7.5 行 661）：不发请求，清空内存 login_token →
 * location.replace 到 /sso/login。clearToken / navigate 注入（壳默认
 * clearLoginToken + location.replace；node 测试传记录函数断言顺序与 URL）。
 */
export function exitBinding(
  clearToken: () => void,
  navigate: (url: string) => void,
): void {
  clearToken();
  navigate(ssoPath('/sso/login'));
}

// ---------------------------------------------------------------------------
// 视图（纯状态帧渲染；renderToStaticMarkup 下不执行副作用）
// ---------------------------------------------------------------------------

/** 绑定分支两帧：choice（两选项）/ create（免密建号表单）。 */
export type BindingChoiceKind = 'choice' | 'create';

export interface BindingPageViewProps {
  /** 信封 binding（§1.3 行 129-132）；undefined 走零值兜底（§9 第 18 条）。 */
  readonly binding: Binding | undefined;
  /** choice（两选项）/ create（免密建号表单）。 */
  readonly choice: BindingChoiceKind;
  /** 建号表单用户名（受控）。 */
  readonly username: string;
  /** 请求在途（提交按钮禁用，§3.2）。 */
  readonly loading: boolean;
  /** 最近一次 Register 响应 status（初始 'idle'）。 */
  readonly status: string;
  /** 最近一次响应信封（失败态 ErrorBanner 字段来源）。 */
  readonly envelope: LoginFlowResponse | undefined;
  /** restart / 传输失败的一次性提示（i18nKey）。 */
  readonly notice?: string;
  onChooseCreate: () => void;
  onExit: () => void;
  onUsernameChange: (value: string) => void;
  /** 免密建号提交（载荷 {username}，§2.7.5 行 672）。 */
  onSubmitAccount: () => void;
}

export function BindingPageView({
  binding,
  choice,
  username,
  loading,
  status,
  envelope,
  notice,
  onChooseCreate,
  onExit,
  onUsernameChange,
  onSubmitAccount,
}: BindingPageViewProps) {
  // 信封 binding 零值兜底（§9 第 18 条）：binding_required 必附 binding
  // （§1.3 行 129），缺失按防御处理——兜底提示 + 保留退出（用户可离开）。
  if (binding === undefined) {
    return (
      <div className={styles.section}>
        <p role="alert">{t('common.refreshAndRetry')}</p>
        <button type="button" className={styles.submit} onClick={onExit}>
          {t('login.exitBinding')}
        </button>
      </div>
    );
  }

  if (status === 'success') {
    return (
      <div className={styles.section}>
        <p role="status">{t('login.accountCreated')}</p>
      </div>
    );
  }

  const resolution = isFlowErrorStatus(status)
    ? resolveFlowStatus(status)
    : undefined;
  // §1.6「可重试 = 否」的失败态禁用提交（表单保留原地，不隐藏）。
  const submitDisabled = resolution !== undefined && !resolution.retryable;
  const error = envelope?.error;

  const submitCreate = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!loading && !submitDisabled) {
      onSubmitAccount();
    }
  };

  return (
    <div className={styles.section}>
      {notice !== undefined && <ErrorBanner i18nKey={notice} />}
      <p role="status">{t('errors.status.binding_required')}</p>
      {choice === 'create' ? (
        <form onSubmit={submitCreate} className={styles.form}>
          <div className={styles.field}>
            <label className={styles.label}>{t('login.usernameLabel')}</label>
            <input
              className={styles.input}
              name="username"
              type="text"
              value={username}
              autoComplete="username"
              onChange={(e) => onUsernameChange(e.target.value)}
            />
            {username !== '' && !isValidUsername(username) && (
              <p role="status" className={styles.hint}>
                {t('login.usernameHint')}
              </p>
            )}
          </div>
          <button
            type="submit"
            disabled={loading || submitDisabled}
            className={styles.submit}
          >
            {t('login.createAccount')}
          </button>
        </form>
      ) : (
        <BindingChoice
          displayName={binding.displayName}
          allowSignup={binding.allowSignup}
          onCreateAccount={onChooseCreate}
          onExit={onExit}
        />
      )}
      {resolution !== undefined && (
        <ErrorBanner
          i18nKey={resolution.i18nKey}
          fallbackMessage={error?.message}
          retryAfter={error?.retryAfter}
          attemptsLeft={error?.attemptsLeft}
          retryable={resolution.retryable}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 页壳（本地状态 + 建号 / 退出编排）
// ---------------------------------------------------------------------------

export interface BindingPageProps {
  /** 信封 binding（LoginContainer binding_required 分支传入，§1.3 行 129）。 */
  readonly binding: Binding | undefined;
  /** restart / 传输失败的一次性提示（容器 notice 透传）。 */
  readonly notice?: string;
}

export function BindingPage({ binding, notice }: BindingPageProps) {
  const [choice, setChoice] = useState<BindingChoiceKind>('choice');
  const [username, setUsername] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('idle');
  const [envelope, setEnvelope] = useState<LoginFlowResponse | undefined>(
    undefined,
  );
  // 传输失败一次性提示（本地镜像；容器 notice 优先，RegisterPage notice 同款语义）。
  const [localNotice, setLocalNotice] = useState<string | undefined>(undefined);

  // 退出（§2.7.5 行 661）：清内存 login_token → 回登录第一步 /sso/login。
  const exit = () => {
    exitBinding(clearLoginToken, (url) => location.replace(url));
  };

  /** 回到绑定流程第一步（传输失败，§1.6「回到第一步」；choice 帧 = 本页首步）。 */
  const restartFlow = () => {
    setChoice('choice');
    setStatus('idle');
    setEnvelope(undefined);
    setUsername('');
    setLocalNotice('errors.status.failed');
  };

  // 免密建号提交（§2.7.5 行 660 / 672）：SsoService/Register 的 set_password
  // 步仅提交 username，loginToken 由 api 层自动注入（内存 token flow=login）。
  const submitAccount = async () => {
    setLoading(true);
    const result = await runFlowStep(register, {
      method: BINDING_REGISTER_METHOD,
      step: 'set_password',
      payload: createAccountPayload(username),
    });
    setLoading(false);
    if (!result.ok) {
      // 传输层失败：回到第一步 + failed 兜底提示（§1.6 行 272，不暴露内部信息；
      // failed 表驱动不可重试，不走 status 为 failed 帧——RegisterPage 同款模式）。
      restartFlow();
      return;
    }
    const env = result.envelope;
    setEnvelope(env);
    setStatus(env.status);
    if (env.status === 'success') {
      // 建号即完成登录（§10.3 行 1547）：终点跳转（loginToken 已由 api 层清空）。
      const url = flowTerminalUrl(env);
      if (url !== '') {
        location.replace(url);
      }
      return;
    }
    if (RESTART_STATUSES.has(env.status)) {
      // step / token / state 类（§1.6 行 251「回到第一步」+ 超时提示）：回
      // choice 帧（本页首步）+ 一次性状态提示（RegisterPage 行 607-610 同款，
      // 不整页 exit()——用户仍可重新选择创建账号或退出）。
      restartFlow();
      setLocalNotice(resolveFlowStatus(env.status).i18nKey);
    }
  };

  return (
    <BindingPageView
      binding={binding}
      choice={choice}
      username={username}
      loading={loading}
      status={status}
      envelope={envelope}
      notice={notice ?? localNotice}
      onChooseCreate={() => setChoice('create')}
      onExit={exit}
      onUsernameChange={setUsername}
      onSubmitAccount={submitAccount}
    />
  );
}
