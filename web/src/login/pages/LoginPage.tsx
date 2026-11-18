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
 * 评审 P1-7：卡片 footer 极简语言切换（中文 / EN）——只做
 * 会话内存内切换（setLocale 模块级变量 + 本地 state 触发整树重渲染，
 * t() 渲染期取新语言）；不写 localStorage / 不做持久化（与 §9 第 1 条
 * 冲突，持久化口径待定）。
 */
import { useState } from "react";
import { getLocale, setLocale, t, type Locale } from "../../shared/i18n";
import type { LoginFlowResponse } from "../../gen/proto/api/sso/v1/envelope_pb";
import { LoginContainer } from "../LoginContainer";
import { ProviderButtons } from "../factors/ProviderButtons";
import type {
  MethodsSnapshot,
  OidcAccountContext,
} from "../../shared/types/init";
import { getInit } from "../../shared/types/init";
import { oidcView } from "../bootstrap";
import {
  consentApprove,
  consentDeny,
  landConsent,
  toConsentApproveInput,
  toConsentDenyInput,
} from "../api";
import { ApiError, resolveCode } from "../../shared/api/errors";
import { initialSelection, PermissionPanel } from "./PermissionPanel";
import styles from "./LoginPage.module.less";
import permissionStyles from "./PermissionPanel.module.less";
import { Link } from "@modern-js/runtime/router";
import { AppLayout } from "../components/AppLayout";
import { ssoPath } from "./RegisterPage";

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
    : "errors.code.internal_error";
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
      aria-label={t("login.consent.accountLabel")}
    >
      <h2 className={permissionStyles.nickname}>{t("login.consent.title")}</h2>
      <p className={permissionStyles.hint}>
        {t("login.consent.hint", { app: clientName })}
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
            {(account?.nickname ?? "?").slice(0, 1)}
          </span>
        )}
        <div>
          <p className={permissionStyles.nickname}>{account?.nickname ?? ""}</p>
          <p className={permissionStyles.identifier}>
            {account?.identifier ?? ""}
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
            ? t("login.consent.processing")
            : t("login.consent.approve")}
        </button>
        <button
          type="button"
          data-testid="consent-deny"
          className={permissionStyles.denyButton}
          disabled={submitting}
          onClick={onDeny}
        >
          {t("login.consent.deny")}
        </button>
      </div>
    </section>
  );
}

export function LoginPage({ snapshot }: LoginPageProps) {
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
  const thirdparty = snapshot.methods.find((m) => m.method === "thirdparty");
  const providers = thirdparty?.providers ?? [];
  const [qrResult, setQrResult] = useState<LoginFlowResponse | undefined>(
    undefined,
  );
  // 右栏受控勾选集（形态 A/B 共用）：初值取注入的有效 scope 全员勾选。
  const [selected, setSelected] = useState<string[]>(() =>
    initialSelection(ctx?.scope ?? ""),
  );
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
        ? await consentApprove(toConsentApproveInput(ctx, selected.join(" ")))
        : await consentDeny(toConsentDenyInput(ctx));
      landConsent(response, (url) => {
        location.replace(url);
      });
    } catch (error) {
      setErrorKey(consentErrorKey(error));
    } finally {
      setSubmitting(false);
    }
  };

  const footer = (
    <>
      <button
        type="button"
        className={
          locale === "zh-CN" ? styles.langButtonActive : styles.langButton
        }
        aria-pressed={locale === "zh-CN"}
        onClick={() => switchLocale("zh-CN")}
      >
        {t("login.langZh")}
      </button>
      <button
        type="button"
        className={
          locale === "en-US" ? styles.langButtonActive : styles.langButton
        }
        aria-pressed={locale === "en-US"}
        onClick={() => switchLocale("en-US")}
      >
        {t("login.langEn")}
      </button>
    </>
  );

  // plain（/sso/login 直登、无 oidc）：维持现有单栏，不渲染权限面板。
  if (view.mode === "plain") {
    return (
      <AppLayout title={t("login.title")} footer={footer}>
        <LoginContainer snapshot={snapshot} qrResult={qrResult} />
        {(showForgot || showRegister) && (
          <nav className={styles.entryNav}>
            {showForgot && (
              <Link className={styles.entryLink} to={ssoPath("/sso/reset")}>
                {t("login.forgotPassword")}
              </Link>
            )}
            {showRegister && (
              <Link className={styles.entryLink} to={ssoPath("/sso/register")}>
                {t("login.register")}
              </Link>
            )}
          </nav>
        )}
        {providers.length > 0 && (
          <div className={styles.providerWall}>
            <ProviderButtons providers={providers} onQrResult={setQrResult} />
          </div>
        )}
      </AppLayout>
    );
  }

  // login / consent（形态 A / B）：双栏容器，AppLayout 不改、LoginPage 自行包裹。
  return (
    <AppLayout
      title={t(view.mode === "consent" ? "login.consent.title" : "login.title")}
      footer={footer}
    >
      <div className={permissionStyles.twoColumn}>
        <div className={permissionStyles.leftColumn}>
          {view.mode === "consent" ? (
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
                oidcScope={selected.join(" ")}
                oidcSubmitLabel="login.submitAndAgree"
              />
              {(showForgot || showRegister) && (
                <nav className={styles.entryNav}>
                  {showForgot && (
                    <Link
                      className={styles.entryLink}
                      to={ssoPath("/sso/reset")}
                    >
                      {t("login.forgotPassword")}
                    </Link>
                  )}
                  {showRegister && (
                    <Link
                      className={styles.entryLink}
                      to={ssoPath("/sso/register")}
                    >
                      {t("login.register")}
                    </Link>
                  )}
                </nav>
              )}
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
          {/* granted 数据源待契约补齐：注入暂未提供已授权 scope，此处按空集传入；
              已授权项锁定逻辑已在 PermissionPanel 实现并测试，数据接线后即可生效。 */}
          <PermissionPanel
            clientName={view.clientName}
            scope={ctx?.scope ?? ""}
            selected={selected}
            onSelectedChange={setSelected}
            disabled={submitting}
          />
        </div>
      </div>
    </AppLayout>
  );
}
