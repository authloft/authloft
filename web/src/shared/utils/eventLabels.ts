/**
 * 安全事件类型文案公共映射（docs/后端架构.md §4.6）：event_log.event 值域 →
 * i18n 键。admin 事件日志与 account 安全日志共用本模块（单一真相，两域
 * 禁各持一份映射），文案在 shared/i18n 的 event.* 公用键段维护。
 *
 * - 值域 = §4.6 event 列 16 常量 + oidc_authorize_no_state（§4.2），共 17
 *   已知值；跨版本新增值原样兜底展示（§12.9）；
 * - 表存键不存文案：模块级求值会先于 entry setLocale 冻结 locale，
 *   eventTypeLabel / 消费方渲染期 t() 取当前语言。
 */
import { t, type I18nKey } from '../i18n';

export const EVENT_TYPE_LABEL_KEYS: Readonly<Record<string, I18nKey>> = {
  login_success: 'event.login_success',
  change_password: 'event.change_password',
  reset_password: 'event.reset_password',
  bind_phone: 'event.bind_phone',
  bind_email: 'event.bind_email',
  enable_mfa: 'event.enable_mfa',
  disable_mfa: 'event.disable_mfa',
  webauthn_register: 'event.webauthn_register',
  webauthn_delete: 'event.webauthn_delete',
  thirdparty_bind: 'event.thirdparty_bind',
  thirdparty_unbind: 'event.thirdparty_unbind',
  admin_disable_user: 'event.admin_disable_user',
  admin_reset_password: 'event.admin_reset_password',
  provider_create: 'event.provider_create',
  provider_update: 'event.provider_update',
  settings_update: 'event.settings_update',
  oidc_authorize_no_state: 'event.oidc_authorize_no_state',
};

/** 安全事件类型 → 展示文案（未知值原样兜底，§9 第 18 条）。 */
export function eventTypeLabel(event: string): string {
  const labelKey = Object.prototype.hasOwnProperty.call(
    EVENT_TYPE_LABEL_KEYS,
    event,
  )
    ? EVENT_TYPE_LABEL_KEYS[event]
    : undefined;
  return labelKey === undefined ? event : t(labelKey);
}
