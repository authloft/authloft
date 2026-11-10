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
  // back link on the not-found fallback page.
  'account.backToHome': 'Back to account home',
  'account.renderError':
    'This page hit an unexpected error. Please refresh and try again',

  // ---- SecurityPage (passkey row title reuses factors.webauthn) ----------
  'account.configLoadFailed':
    'Failed to load settings. Please refresh and try again',
  'account.close': 'Close',
  'account.loginMethodTitle': 'Sign-in Method',
  'account.thirdpartyCardTitle': 'Third-Party Accounts',
  'account.passwordLabel': 'Password',
  'account.passwordChangeHint': 'Recommended to change regularly',
  'account.passwordNotSet': 'Not set',
  'account.goBindAction': 'Link',
  'account.rebindAction': 'Change',
  'account.setPasswordFirst': 'Set a password first',
  'account.bindPhoneTitle': 'Link Phone Number',
  'account.bindEmailTitle': 'Link Email',
  'account.mfaSectionTitle': 'Two-Factor Authentication',
  'account.mfaUnbindConfirm':
    'Unlink "{factor}"? It will no longer be required when you sign in.',
  'account.mfaUnbindSuccess': '{factor} unlinked',
  'account.webauthnBoundCount': '{count} linked',
  'account.webauthnViewBound': 'View linked',
  'account.addAction': 'Add',
  'account.webauthnAddTitle': 'Add Passkey',
  'account.webauthnRegisterSuccess': 'Passkey registered',

  // ---- ProfilePage ---------------------------------------------------------
  'account.profileLoadFailed':
    'Failed to load profile. Please refresh and try again',
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
  'account.bindTargetTaken':
    'This account is already linked to another account',
  'account.bindSuccess': 'Third-party account linked successfully',

  // ---- ThirdPartyList (refresh hint reuses common.refreshAndRetry) ---------
  'account.unionTag': 'Federated identity',
  'account.unbindConfirm':
    'Unlink "{name}"? You will no longer be able to sign in with it.',
  'account.unbindAction': 'Unlink',
  // disabled reason (canUnbindThirdpartyRow: no password and no other
  // non-union binding left).
  'account.unbindDisabledReason':
    'No password is set and no other third-party account is linked. Unlinking this would leave you with no way to sign in. Set a password or link another account first',
  // unbind success feedback (P1-6, unified Semi Toast success channel).
  'account.unbindSuccess': 'Unlinked "{name}"',
  'account.bindAction': 'Link',
  'account.thirdpartyLoadFailed':
    'Failed to load third-party accounts. Please refresh and try again',
  'account.thirdpartyEmpty': 'No third-party accounts linked yet',
  'account.thirdpartyAvailableTitle': 'Available third-party accounts',

  // ---- RecoveryCodePanel ---------------------------------------------------
  'account.recoveryNotice':
    'Recovery codes are shown only once. Copy and save them somewhere safe',
  'account.recoveryIssuedAt': 'Issued at: {time}',
  'account.recoveryRegenerateConfirm':
    'Regenerating will invalidate all existing recovery codes. Continue?',
  'account.recoveryRegenerate': 'Regenerate',
  // download as text (P2-3, pure frontend Blob download).
  'account.recoveryDownload': 'Download as text',

  // ---- MfaSetting (merged MFA + recovery-code row; factor names reuse
  //      factors.*, the recovery-code modal title reuses
  //      factors.recovery_code, the bind button reuses account.bindAction) ---
  'account.mfaEnabledSuccess': '{factor} enabled',
  'account.recoveryRegenerateSuccess':
    'Recovery codes regenerated; all old codes are void',
  'account.factorTotp': 'TOTP authenticator code',
  'account.factorBoundTag': 'Linked',
  'account.factorUnboundTag': 'Not linked',
  'account.mfaLocked':
    'Policy requires two-step verification; it cannot be fully turned off',
  'account.viewRecoveryCodes': 'View recovery codes',
  'account.recoveryLoadFailed': 'Failed to load recovery codes',

  // ---- WebauthnList ---------------------------------------------------------
  'account.webauthnLabelPlaceholder': 'Name this passkey (optional)',
  'account.webauthnRegisterAction': 'Register passkey',
  'account.webauthnCancelled': 'Passkey registration was cancelled',
  'account.webauthnRegisterFailed':
    'Failed to register the passkey. Please try again',
  'account.webauthnLoadFailed':
    'Failed to load passkeys. Please refresh and try again',
  'account.webauthnEmpty': 'No passkeys registered yet',
  'account.webauthnUnsupported':
    'Passkeys are not supported by this browser or device',
  'account.saveAction': 'Save',
  'account.cancelAction': 'Cancel',
  'account.unnamedCredential': 'Unnamed',
  'account.webauthnAddedAt': 'Added at {time}',
  'account.webauthnRenameAction': 'Rename',
  'account.webauthnDeleteConfirm':
    'Delete "{name}"? You will no longer be able to sign in with it.',
  'account.deleteAction': 'Delete',

  // ---- ContactBindForm (the captcha hint reuses errors.status.captcha_required,
  //      the email kind label reuses channels.email) ---------------------------
  'account.phoneLabel': 'Phone number',
  'account.bindInvalidPhone': 'Enter a valid phone number',
  'account.bindInvalidEmail': 'Enter a valid email address',
  'account.bindCodeInvalid': 'Enter the {count}-digit verification code',
  'account.bindDone': '{kind} linked successfully',
  'account.bindContinue': 'Link another / change',
  'account.bindCodeSentToPrefix': 'Verification code sent to',
  'account.bindCodeAria': '{kind} binding code',
  'account.bindConfirmAction': 'Confirm',
  'account.bindResendAction': 'Resend',
  // A-2: current bound value display + resend cooldown countdown.
  'account.bindCurrentValue': 'Current: {value}',
  'account.bindCurrentVerified': 'Current: {value} (verified)',
  'account.bindResendCountdown': 'Resend available in {seconds}s',
  'account.phonePlaceholder': 'Enter a phone number',
  'account.emailPlaceholder': 'Enter an email address',
  'account.sendCodeAction': 'Send code',

  // ---- ThirdPartyBindDialog -------------------------------------------------
  'account.qrNeedCaptcha': 'Please complete the verification first',
  'account.fetchQrcodeAction': 'Get QR code',
  'account.qrBindHint': 'Scanning will link it to your current account',
  'account.scanBindTitle': 'Scan to link',
  'account.bindNameTitle': 'Link {name}',

  // ---- PasswordChangeForm ----------------------------------------------------
  'account.currentPasswordRequired': 'Enter your current password',
  'account.currentPasswordIncorrect': 'The current password is incorrect',
  'account.passwordChangedDone':
    'Password changed. You have been signed out. Please sign in again',
  'account.currentPasswordLabel': 'Current password',
  'account.newPasswordLabel': 'New password',
  // A-1: confirm new password (local-only check, never sent, same as RegisterPage).
  'account.confirmPasswordLabel': 'Confirm new password',
  'account.confirmPasswordMismatch': 'The new passwords do not match',
  'account.changePasswordAction': 'Change password',
  'account.setPasswordAction': 'Set password',

  // ---- AvatarUploader (the avatar alt reuses account.avatarAlt) -------------
  'account.uploadProgress': 'Uploading {percent}%',
  'account.avatarChooseFileAria': 'Choose an avatar file',
  'account.avatarUploadAction': 'Upload avatar',

  // ---- TotpBindDialog (the retry button reuses common.retry, the
  //      code aria-label reuses account.factorTotp) -----------------------------
  'account.totpCodeInvalid': 'Enter the {count}-digit code',
  'account.totpBindTitle': 'Link TOTP authenticator',
  'account.totpBindSuccess': 'TOTP linked successfully.',
  'account.totpDoneAction': 'Saved. Finish linking',
  'account.totpSecretLabel': 'Secret key',
  'account.totpVerifyAction': 'Verify and finish linking',
  // ---- TotpBindDialog steps (Steps indicator + back / next) ---------
  'account.totpStepAdd': 'Add authenticator',
  'account.totpStepVerify': 'Verify code',
  'account.totpStepRecovery': 'Save recovery codes',
  'account.totpNextAction': 'Next',
  'account.backAction': 'Back',

  // ---- TotpBindDialog QR code (the key / otpauth text fallback keeps
  //      totpSecretLabel / totpOtpauthLabel / totpManualHint, not removed) ------
  'account.totpHint':
    'Use an authenticator app (such as Google Authenticator) to scan the QR code or enter the key manually to add it',
  'account.totpQrImageAlt': 'TOTP binding QR code',

  // ---- EventLogTable -----------------------------------------------------------
  'account.logTimeColumn': 'Time',
  'account.logMethodColumn': 'Method',
  'account.logUaColumn': 'Device (UA)',
  'account.logLoadFailed':
    'Failed to load sign-in history. Please refresh and try again',
  'account.logEmpty': 'No sign-in records yet',

  // ---- ProfilePage editing (save / cancel reuse saveAction / cancelAction,
  //      phone label reuses phoneLabel; avatar persist failure reuses
  //      errors.status.failed) --------------------------------------------------
  'account.profileEditAction': 'Edit Profile',
  // save success feedback (P1-6, unified Semi Toast success channel).
  'account.profileSaved': 'Profile saved',
  'account.emailLabel': 'Email',
  'account.genderLabel': 'Gender',
  'account.genderSecret': 'Prefer not to say',
  'account.genderMale': 'Male',
  'account.genderFemale': 'Female',
  'account.birthdayLabel': 'Birthday',
  'account.localeLabel': 'Locale',
  'account.timezoneLabel': 'Time Zone',
  'account.extraLabel': 'Extra',
  'account.extraPlaceholder': '{"key": "value"}',
  'account.extraInvalidJson': 'Extra must be a valid JSON object',
  'account.birthdayInvalid': 'Enter a valid date (YYYY-MM-DD)',
};
