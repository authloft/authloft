/**
 * 登录页外壳（docs/前端架构.md §4.4 行 463）：组装 LoginContainer——
 * 「MethodTabs + LoginContainer」的组装关系由容器视图 LoginFlowView
 * 内嵌 MethodTabs 满足（既有交付结构），此处不重复渲染防双份。
 *
 * - `/auth/authorize` 的已登录直达由后端 302 处理（§4.4），前端只渲染
 *   无会话空壳；登录成功后的终点跳转（syncCookieUrl / redirectTo）在
 *   LoginContainer 内处理；
 * - 「忘记密码」「注册」入口可见性取注入快照 `methods.flags`（接口文档
 *   §2.1 行 374-377：镜像 allow_password_reset / allow_registration），
 *   不另发请求；入口激活为真链接（/sso/reset、/sso/register，Go 渲染
 *   的空壳页路由），flags 为 false / 缺省时保持隐藏（§2.1 行 407）。
 *
 * 文案：标题 / 入口文案经 i18n 字典 login.* 键取用。
 *
 * 评审 P1-7：卡片 footer 极简语言切换（中文 / EN）——只做
 * 会话内存内切换（setLocale 模块级变量 + 本地 state 触发整树重渲染，
 * t() 渲染期取新语言）；不写 localStorage / 不做持久化（与 §9 第 1 条
 * 冲突，持久化口径待定）。
 */
import { useState } from 'react';
import { getLocale, setLocale, t, type Locale } from '../../shared/i18n';
import { LoginContainer } from '../LoginContainer';
import type { MethodsSnapshot } from '../../shared/types/init';
import { ssoPath } from './RegisterPage';
import styles from './LoginPage.module.less';

export interface LoginPageProps {
  /** 注入快照（§2.1；bootstrap 读取后传入，§4.1 行 375）。 */
  readonly snapshot: MethodsSnapshot;
}

export function LoginPage({ snapshot }: LoginPageProps) {
  // §2.1 行 407：flags 只用于隐藏登录页的「忘记密码」「注册」入口；
  // 零值兜底——undefined / 缺省不渲染。
  const flags = snapshot.flags;
  const showForgot = flags?.passwordReset === true;
  const showRegister = flags?.registration === true;
  // 内存内语言切换（持久化口径待定）；state 驱动重渲染使 t() 生效。
  const [locale, setLocaleState] = useState<Locale>(getLocale);
  const switchLocale = (next: Locale) => {
    setLocale(next);
    setLocaleState(next);
  };
  return (
    <main className={styles.page}>
      {/* 统一卡片容器（页面底 + 居中白卡），DOM 语义不变。 */}
      <div className={styles.card}>
        <h1 className={styles.title}>{t('login.title')}</h1>
        <LoginContainer snapshot={snapshot} />
        {(showForgot || showRegister) && (
          <nav className={styles.entryNav}>
            {showForgot && (
              <a className={styles.entryLink} href={ssoPath('/sso/reset')}>
                {t('login.forgotPassword')}
              </a>
            )}
            {showRegister && (
              <a className={styles.entryLink} href={ssoPath('/sso/register')}>
                {t('login.register')}
              </a>
            )}
          </nav>
        )}
        {/* 评审 P1-7：footer 语言切换，仅内存内（不持久化）。 */}
        <footer className={styles.footer}>
          <button
            type="button"
            className={
              locale === 'zh-CN' ? styles.langButtonActive : styles.langButton
            }
            aria-pressed={locale === 'zh-CN'}
            onClick={() => switchLocale('zh-CN')}
          >
            {t('login.langZh')}
          </button>
          <button
            type="button"
            className={
              locale === 'en-US' ? styles.langButtonActive : styles.langButton
            }
            aria-pressed={locale === 'en-US'}
            onClick={() => switchLocale('en-US')}
          >
            {t('login.langEn')}
          </button>
        </footer>
      </div>
    </main>
  );
}
