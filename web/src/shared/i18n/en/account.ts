/**
 * en-US 安全中心域文案模块（分域底座）：以 zh 侧同名模块为类型
 * 约束，键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块
 * 内追加。
 */
import type { account as zhAccount } from '../zh/account';

export const account: typeof zhAccount = {
  // ---- Layout / routes / entry ---------------------------------------------
  'account.personalCenter': 'Account Center',
  'account.profileTitle': 'Profile',
  'account.securityTitle': 'Security',
  'account.auditTitle': 'Sign-in History',
  'account.logout': 'Sign out',
  'account.appTitle': 'Authloft User Center',
  'account.routeNotFound': 'Page not found',
  'account.renderError': 'This page hit an unexpected error. Please refresh and try again',

  // ---- SecurityPage (passkey card title reuses factors.webauthn) ----------
  'account.configLoadFailed': 'Failed to load settings. Please refresh and try again',
  'account.close': 'Close',
  'account.twoFactorTitle': 'Two-Step Verification',
  'account.mfaEnabledStatus': 'Two-step verification is on',
  'account.mfaDisabledStatus': 'Two-step verification is off',
  'account.mfaRequiredNote': ' (required by policy and cannot be turned off)',
  'account.trustDeviceNote':
    'Trusted devices: not supported yet (second verification is required at every sign-in)',
  'account.passwordCardTitle': 'Sign-in password',
  'account.contactCardTitle': 'Contact Information',
  'account.thirdpartyCardTitle': 'Third-Party Accounts',

  // ---- ProfilePage ---------------------------------------------------------
  'account.profileLoadFailed': 'Failed to load profile. Please refresh and try again',
  'account.avatarAlt': 'User avatar',
  'account.usernameLabel': 'Username',
  'account.nicknameLabel': 'Nickname',

  // ---- api.ts display helpers (unknown fallback reuses errors.code.unknown)
  'account.mfaNotBound': 'Not bound yet',
  'account.mfaLastUsedAt': ' · Last used {time}',
  'account.boundAt': 'Linked at {time}',
  'account.mfaTarget': 'Target {target}',
  'account.mfaCredentialCount': '{count} credentials linked',
  'account.mfaRemainingCount': '{count} remaining',
  'account.bindTargetTaken': 'This account is already linked to another account',
  'account.bindSuccess': 'Third-party account linked successfully',

  // ---- ThirdPartyList (refresh hint reuses common.refreshAndRetry) ---------
  'account.unionTag': 'Federated identity',
  'account.unbindConfirm': 'Unlink "{name}"? You will no longer be able to sign in with it.',
  'account.unbindAction': 'Unlink',
  'account.bindAction': 'Link',
  'account.thirdpartyLoadFailed':
    'Failed to load third-party accounts. Please refresh and try again',
  'account.thirdpartyEmpty': 'No third-party accounts linked yet',
  'account.thirdpartyAvailableTitle': 'Available third-party accounts',

  // ---- RecoveryCodePanel ---------------------------------------------------
  'account.recoveryNotice': 'Recovery codes are shown only once. Copy and save them somewhere safe',
  'account.recoveryIssuedAt': 'Issued at: {time}',
  'account.recoveryRegenerateConfirm':
    'Regenerating will invalidate all existing recovery codes. Continue?',
  'account.recoveryRegenerate': 'Regenerate',
};
