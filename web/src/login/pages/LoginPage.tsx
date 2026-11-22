/**
 * 登录页外壳（docs/前端架构.md §4.4 行 463）：组装 LoginContainer + 入口
 * 导航 + 第三方图标墙——「MethodTabs + LoginContainer」的组装关系由容器视图
 * LoginFlowView 内嵌 MethodTabs 满足，此处不重复渲染防双份；图标墙在入口
 * 导航下方独立渲染（thirdparty providers 由 factors/ProviderButtons 承载）。
 *
 * - `/auth/authorize` 的已登录直达由后端 302 处理（§4.4），前端只渲染
 *   无会话空壳；登录成功后的终点跳转（syncCookieUrl / redirectTo）在
 *   LoginContainer 内处理；
 * - 「忘记密码」「注册」入口可见性取注入快照 `methods.flags`（接口文档
 *   §2.1 行 374-377：镜像 allow_password_reset / allow_registration），
 *   不另发请求；入口激活为真链接（/sso/reset、/sso/register，Go 渲染
 *   的空壳页路由），flags 为 false / 缺省时保持隐藏（§2.1 行 407）；
 * - 扫码结论经受控 state 注入容器，回到同一状态机分派（不引入全局事件）。
 *
 * 文案：标题 / 入口文案经 i18n 字典 login.* 键取用。
 *
 * 卡片底部结构：入口导航（右对齐）→「或」分割线 → 第三方图标墙（居中），
 * footer 为极简语言切换——小图标触发（当前语言原生名）+ 下拉菜单选择，
 * 只做会话内存内切换（setLocale 模块级变量 + 本地 state 触发整树重渲染，
 * t() 渲染期取新语言）；不写 localStorage / 不做持久化（与 §9 第 1 条
 * 冲突，持久化口径待定）。
 */
import { useEffect, useState } from 'react';
import { getLocale, setLocale, t, type Locale } from '../../shared/i18n';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import { LoginContainer } from '../LoginContainer';
import { LocaleSwitcher } from '../components/LocaleSwitcher';
import { ProviderButtons } from '../factors/ProviderButtons';
import { clearLoginToken } from '../loginTokenStore';
import type {
  MethodsSnapshot,
  OidcAccountContext,
} from '../../shared/types/init';
import { getInit } from '../../shared/types/init';
import { oidcView } from '../bootstrap';
import {
  consentApprove,
  consentDeny,
  landConsent,
  toConsentApproveInput,
  toConsentDenyInput,
} from '../api';
import { ApiError, resolveCode } from '../../shared/api/errors';
import { setOidcSelectedScope } from '../oidcContext';
import { initialSelection, PermissionPanel } from './PermissionPanel';
import styles from './LoginPage.module.less';
import permissionStyles from './PermissionPanel.module.less';
import { Link } from '@modern-js/runtime/router';
import { AppLayout } from '../components/AppLayout';
import { ssoPath } from './RegisterPage';

export interface LoginPageProps {
  /** 注入快照（§2.1；bootstrap 读取后传入，§4.1 行 375）。 */
  snapshot: MethodsSnapshot;
}

/**
 * 同意提交失败 → 展示文案键（exhaustive 映射，node 可测）：已知 ApiError 按
 * §1.6 code 归一取 i18n 键（含 invalid_scope），未知异常兜底 internal_error，
 * 不暴露原始 message。
 */
export function consentErrorKey(error: unknown): string {
  return error instanceof ApiError
    ? resolveCode(error).i18nKey
    : 'errors.code.internal_error';
}

/**
 * 同意页左栏账号卡片（§4.2 形态 B）：后端注入的掩码摘要（昵称 / 头像 /
 * 标识）+ 同意 / 拒绝按钮。无登录表单、不进登录状态机、不碰 loginTokenStore。
 */
function ConsentAccountCard({
  account,
  clientName,
  submitting,
  errorKey,
  onApprove,
  onDeny,
}: {
  account?: OidcAccountContext;
  clientName: string;
  submitting: boolean;
  errorKey?: string;
  onApprove: () => void;
  onDeny: () => void;
}) {
  return (
    <section
      className={permissionStyles.accountCard}
      data-testid="consent-account-card"
      aria-label={t('login.consent.accountLabel')}
    >
      <h2 className={permissionStyles.nickname}>{t('login.consent.title')}</h2>
      <p className={permissionStyles.hint}>
        {t('login.consent.hint', { app: clientName })}
      </p>
      <div className={permissionStyles.accountIdentity}>
        {account?.avatar_url ? (
          <img
            className={permissionStyles.avatar}
            src={account.avatar_url}
            alt=""
          />
        ) : (
          <span className={permissionStyles.avatarFallback} aria-hidden="true">
            {(account?.nickname ?? '?').slice(0, 1)}
          </span>
        )}
        <div>
          <p className={permissionStyles.nickname}>{account?.nickname ?? ''}</p>
          <p className={permissionStyles.identifier}>
            {account?.identifier ?? ''}
          </p>
        </div>
      </div>
      {errorKey !== undefined && (
        <p role="alert" className={permissionStyles.consentError}>
          {t(errorKey)}
        </p>
      )}
      <div className={permissionStyles.consentActions}>
        <button
          type="button"
          data-testid="consent-approve"
          className={permissionStyles.approveButton}
          disabled={submitting}
          onClick={onApprove}
        >
          {submitting
            ? t('login.consent.processing')
            : t('login.consent.approve')}
        </button>
        <button
          type="button"
          data-testid="consent-deny"
          className={permissionStyles.denyButton}
          disabled={submitting}
          onClick={onDeny}
        >
          {t('login.consent.deny')}
        </button>
      </div>
    </section>
  );
}

export function LoginPage({ snapshot }: LoginPageProps) {
  // SPA 内路由跳转不清内存 loginToken（登录 ↔ 注册 / 重置互跳会把上一个流程
  // 的残留 token 带进本页请求：login 端点只认 login token → token_invalid
  // 首步即失败），挂载即清——本页流程的 token 由响应重签；硬跳页 / 刷新本就
  // 随页面销毁（内存变量无持久化，五条之 4 / 5）。绑定 / 二次验证等原地视图
  // 在本页挂载树内，不受影响。
  useEffect(() => {
    clearLoginToken();
  }, []);
  // oidc.mode 三态分派（§4.2）：login 双栏 / consent 双栏 / plain 直登单栏。
  const view = oidcView(getInit()?.oidc);
  const ctx = view.ctx;
  // §2.1 行 407：flags 只用于隐藏登录页的「忘记密码」「注册」入口；
  // 零值兜底——undefined / 缺省不渲染。
  const flags = snapshot.flags;
  const showForgot = flags?.passwordReset === true;
  const showRegister = flags?.registration === true;
  // 内存内语言切换（持久化口径待定）；state 驱动重渲染使 t() 生效。
  const [locale, setLocaleState] = useState<Locale>(getLocale);
  // 第三方图标墙数据与扫码结论：结论经受控 prop 注入容器，避免全局事件。
  const thirdparty = snapshot.methods.find((m) => m.method === 'thirdparty');
  const providers = thirdparty?.providers ?? [];
  const [qrResult, setQrResult] = useState<LoginFlowResponse | undefined>(
    undefined,
  );
  // 右栏受控勾选集（形态 A/B 共用）：初值取注入的有效 scope 全员勾选。
  const [selected, setSelected] = useState<string[]>(() =>
    initialSelection(ctx?.scope ?? ''),
  );
  // 勾选收敛子集同步（§4.2：勾选收窄适用于全部首签路径）：扫码 / 注册 / 三方
  // 落盘三条路径经 oidcContext 收敛点读取，与主因子（oidcScope prop）共用
  // 同一子集、不放大。同步时机先于任何用户动作（轮询 / 提交 / 跳转均由交互
  // 触发）；SPA 内跨路由（授权页 → 注册页）收敛值仍存活。plain 直登 selected
  // 恒空 → 同步空串即回退注入原值。
  useEffect(() => {
    setOidcSelectedScope(selected.join(' '));
  }, [selected]);
  // 同意 / 拒绝提交态与错误键（error.message 不透出，§1.6）。
  const [submitting, setSubmitting] = useState(false);
  const [errorKey, setErrorKey] = useState<string | undefined>(undefined);
  const switchLocale = (next: Locale) => {
    setLocale(next);
    setLocaleState(next);
  };

  /** 同意提交（§3.10）：请求映射 → RPC → 终点跳转（landConsent 注入 navigate，可测）。 */
  const submitConsent = async (approve: boolean) => {
    if (ctx === undefined || submitting) {
      return;
    }
    setSubmitting(true);
    setErrorKey(undefined);
    try {
      const response = approve
        ? await consentApprove(toConsentApproveInput(ctx, selected.join(' ')))
        : await consentDeny(toConsentDenyInput(ctx));
      landConsent(response, (url) => {
        location.replace(url);
      });
    } catch (error) {
      console.error('[login] consent submit failed', error);
      setErrorKey(consentErrorKey(error));
    } finally {
      setSubmitting(false);
    }
  };

  // 「或」分割线只在图标墙在场时渲染（语义 = 分隔账号登录与第三方登录）。
  const orDivider =
    providers.length > 0 ? (
      <div className={styles.orDivider} aria-hidden="true">
        {t('login.orDivider')}
      </div>
    ) : null;

  const footer = <LocaleSwitcher locale={locale} onSwitch={switchLocale} />;

  // plain（/sso/login 直登、无 oidc）：维持现有单栏，不渲染权限面板。
  if (view.mode === 'plain') {
    return (
      <AppLayout title={t('login.title')} footer={footer}>
        <LoginContainer snapshot={snapshot} qrResult={qrResult} />
        {(showForgot || showRegister) && (
          <nav className={styles.entryNav}>
            {showForgot && (
              <Link className={styles.entryLink} to={ssoPath('/sso/reset')}>
                {t('login.forgotPassword')}
              </Link>
            )}
            {showRegister && (
              <Link className={styles.entryLink} to={ssoPath('/sso/register')}>
                {t('login.registerNow')}
              </Link>
            )}
          </nav>
        )}
        {orDivider}
        {providers.length > 0 && (
          <ProviderButtons providers={providers} onQrResult={setQrResult} />
        )}
      </AppLayout>
    );
  }

  // login / consent（形态 A / B）：双栏容器，AppLayout 不改、LoginPage 自行包裹。
  return (
    <AppLayout
      title={t(view.mode === 'consent' ? 'login.consent.title' : 'login.title')}
      footer={footer}
    >
      <div className={permissionStyles.twoColumn}>
        <div className={permissionStyles.leftColumn}>
          {view.mode === 'consent' ? (
            <ConsentAccountCard
              account={view.account}
              clientName={view.clientName}
              submitting={submitting}
              errorKey={errorKey}
              onApprove={() => void submitConsent(true)}
              onDeny={() => void submitConsent(false)}
            />
          ) : (
            <>
              <LoginContainer
                snapshot={snapshot}
                qrResult={qrResult}
                oidcScope={selected.join(' ')}
                oidcSubmitLabel="login.submitAndAgree"
              />
              {(showForgot || showRegister) && (
                <nav className={styles.entryNav}>
                  {showForgot && (
                    <Link
                      className={styles.entryLink}
                      to={ssoPath('/sso/reset')}
                    >
                      {t('login.forgotPassword')}
                    </Link>
                  )}
                  {showRegister && (
                    <Link
                      className={styles.entryLink}
                      to={ssoPath('/sso/register')}
                    >
                      {t('login.registerNow')}
                    </Link>
                  )}
                </nav>
              )}
              {orDivider}
              {providers.length > 0 && (
                <div className={styles.providerWall}>
                  <ProviderButtons
                    providers={providers}
                    onQrResult={setQrResult}
                  />
                </div>
              )}
            </>
          )}
        </div>
        <div className={permissionStyles.rightColumn}>
          {/* granted_scopes 取注入（§8 形态 B 键）：已授权项锁定不可取消（授权
              记录只扩不缩）；形态 A 无此键 / 空集 → 空串，回退现状仅 openid 恒锁。 */}
          <PermissionPanel
            clientName={view.clientName}
            scope={ctx?.scope ?? ''}
            grantedScopes={ctx?.granted_scopes ?? ''}
            selected={selected}
            onSelectedChange={setSelected}
            disabled={submitting}
          />
        </div>
      </div>
    </AppLayout>
  );
}
