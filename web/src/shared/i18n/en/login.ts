/**
 * en-US 登录域文案模块（分域底座）：以 zh 侧同名模块为类型约束，
 * 键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块内追加。
 */
import type { login as zhLogin } from '../zh/login';

export const login: typeof zhLogin = {
  // ---- 容器 / 方式列表（LoginContainer、MethodTabs）------------------------
  'login.title': 'Sign in',
  'login.register': 'Register',
  'login.forgotPassword': 'Forgot password',
  'login.noMethods': 'No sign-in methods available',
  'login.selectMethodHint': 'Please choose a sign-in method',
  'login.mfaSelectHint': 'Please choose a second-factor verification method',
  'login.pollPlaceholder': 'QR code sign-in is coming soon',
  'login.redirecting': 'Signed in, redirecting…',
  // ---- 注册页（RegisterPage）----------------------------------------------
  'login.noRegisterMethods': 'No registration methods available',
  'login.nextStep': 'Next',
  'login.resend': 'Resend',
  'login.resendCountdown': 'Resend available in {seconds}s',
  'login.usernameHint':
    'Username must be 5-20 characters of letters, digits, or underscores',
  'login.registerSuccess': 'Registration complete, redirecting…',
  'login.codeLabel': 'Verification code',
  'login.usernameLabel': 'Username',
  'login.passwordLabel': 'Password',
  'login.attemptsLeft': '{count} attempts left',
  'login.registerMethodPassword': 'Register with username and password',
  'login.registerMethodOtpSms': 'Register with phone number',
  'login.registerMethodOtpEmail': 'Register with email',
  // ---- 重置页（ResetPage）--------------------------------------------------
  'login.reset': 'Reset password',
  'login.newPasswordLabel': 'New password',
  'login.resetMethodOtpSms': 'Recover via phone number',
  'login.resetMethodOtpEmail': 'Recover via email',
  'login.resetSuccess':
    'Password reset complete. Please sign in with your new password',
  'login.goLogin': 'Go to sign in',
  // ---- 绑定（BindingPage、BindingChoice）-----------------------------------
  'login.createAccount': 'Create account',
  'login.accountCreated': 'Account created, redirecting…',
  'login.bindingIdentity': 'Sign-in method "{name}"',
  'login.createAccountOption': 'Create a new account',
  'login.exitBinding': 'Exit and sign in with a different account',
  'login.channelSignupClosed': 'Sign-up is not available for this channel',
  // ---- OAuth 回调页（OAuthCallbackPage）------------------------------------
  'login.processing': 'Processing, please wait…',
  'login.bindUnavailable': 'Account binding is coming soon',
  'login.mfaPlaceholder':
    'Second-factor verification is required. Please go back and sign in again',
  'login.backToLogin': 'Back to sign in',
  // ---- 因子表单（factors/：OTPForm、PasswordForm、WebAuthnButton、
  //      RecoveryCodeForm、ProviderButtons）------------------------------------
  'login.submit': 'Sign in',
  'login.sendCode': 'Send verification code',
  'login.codeWillBeSentTo': 'The verification code will be sent to {target}',
  'login.capsLockOn': 'Caps Lock is on',
  'login.passkeySignIn': 'Sign in with passkey',
  'login.passkeyVerify': 'Verify',
  'login.passkeyCancelled': 'Passkey verification cancelled',
  'login.passkeyFailed': 'Passkey verification failed. Please try again',
  // ---- 步骤杂项（steps/、routes、entry）--------------------------------------
  // 「请刷新重试」复用 common.refreshAndRetry（收口，login.refreshRetry 已删）。
  'login.qrNeedCaptcha': 'Please complete the verification first',
  'login.fetchQrcodeAction': 'Get QR code',
  'login.redirectInProgress': 'Redirecting…',
  'login.initMissing': 'Initialization data is missing. Please refresh and try again',
  'login.routeNotFound': 'Page not found',
  'login.renderError': 'This page hit an unexpected error. Please refresh and try again',
};
