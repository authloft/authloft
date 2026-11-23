/**
 * OIDC 授权页右栏共用组件（docs/前端架构.md §4.4；docs/接口文档.md §4.2 三态）：
 * 应用名（注入 oidc.client_name）+ scope 复选框。用户体验层规则二条——
 * ① 已授权项锁定（勾上 + 禁用 + 「已授权」标注，不可取消：授权记录只扩不缩）；
 * ② openid 全链路强制、恒锁定不可取消。本次新请求项默认勾选、可逐项取消。
 * 服务端以注册 scopes 为上限做权威校验（§3.10 invalid_scope），前端只做拦截。
 *
 * 受控组件：勾选集由调用方持有，经 onSelectedChange 上抛；形态 A 提交时收敛
 * 成 oidc.scope 子集（前端架构 §4.4），形态 B 提交时作为 selected_scope（§3.10）。
 * 锁定判定与勾选变换抽为纯函数（node 可测，无 DOM 交互依赖）。
 */
import { t } from '../../shared/i18n';
import styles from './PermissionPanel.module.less';

/** scope 封闭集六值（§4.2 行 1458）：展示顺序按此固定，不受注入串顺序影响。 */
export const SCOPE_ORDER = [
  'openid',
  'profile',
  'email',
  'phone',
  'phone_plain',
  'email_plain',
] as const;

/** 空格分隔的 scope 串 → 封闭集内的 token 列表（去重、按封闭集序、丢弃未支持值）。 */
export function scopeTokens(scope: string): string[] {
  const parts = new Set(
    scope
      .trim()
      .split(/\s+/)
      .filter((part) => part !== ''),
  );
  return SCOPE_ORDER.filter((value) => parts.has(value));
}

/**
 * 某项是否锁定：openid 恒锁（§4.2 行 1459）；已授权项锁定（裁决①，授权记录
 * 只扩不缩）。grantedScopes 为已授权并集原文（空格分隔），当前注入未提供该
 * 字段、形态 B 传空串——锁定逻辑完备，待注入补齐即可生效。
 */
export function isScopeLocked(scope: string, grantedScopes: string): boolean {
  return scope === 'openid' || scopeTokens(grantedScopes).includes(scope);
}

/** 初始勾选集：请求 scope 全员默认勾选（形态 A / B 的新请求项口径）。 */
export function initialSelection(scope: string): string[] {
  return scopeTokens(scope);
}

/**
 * 勾选集规整：剔除不在请求 scope 内的项（不可放大），并补齐恒锁项（openid +
 * 已授权）——保证上抛给提交的集合永远含锁定项、且无请求外项。
 */
export function normalizeSelection(
  selected: readonly string[],
  scope: string,
  grantedScopes: string,
): string[] {
  const allowed = scopeTokens(scope);
  const selectedSet = new Set(
    selected.filter((value) => allowed.includes(value)),
  );
  for (const value of allowed) {
    if (isScopeLocked(value, grantedScopes)) {
      selectedSet.add(value);
    }
  }
  return allowed.filter((value) => selectedSet.has(value));
}

/**
 * 切换单项：锁定项（openid / 已授权）不可取消，返回原集；其余项在未选↔已选
 * 间翻转。纯函数，便于「openid 禁取消 / 已授权锁定」的可证伪断言。
 */
export function toggleScopeItem(
  selected: readonly string[],
  scope: string,
  grantedScopes: string,
): string[] {
  if (isScopeLocked(scope, grantedScopes)) {
    return [...selected];
  }
  return selected.includes(scope)
    ? selected.filter((value) => value !== scope)
    : [...selected, scope];
}

export interface PermissionPanelProps {
  /** 应用名（注入 oidc.client_name）。 */
  clientName: string;
  /** 请求 scope 原文（注入 oidc.scope，缺省补值后的有效 scope）。 */
  scope: string;
  /** 已授权 scope 并集原文（形态 B）；当前注入未提供，传空串。 */
  grantedScopes?: string;
  /** 受控勾选集（封闭集内的 scope token）。 */
  selected: readonly string[];
  /** 勾选集变化上抛（已规整：含锁定项、无请求外项）。 */
  onSelectedChange: (next: string[]) => void;
  /** 提交在途：禁用全部复选框，防并发改选。 */
  disabled?: boolean;
}

/** 单个 scope 复选框（锁定项 checked + disabled + 「已授权」标注）。 */
function ScopeCheckbox({
  scope,
  checked,
  locked,
  disabled,
  onToggle,
}: {
  scope: string;
  checked: boolean;
  locked: boolean;
  disabled: boolean;
  onToggle: () => void;
}) {
  return (
    <label className={styles.scopeItem}>
      <input
        type="checkbox"
        className={styles.checkbox}
        checked={checked}
        disabled={disabled || locked}
        data-scope={scope}
        data-locked={locked ? 'true' : 'false'}
        onChange={onToggle}
      />
      <span className={styles.scopeLabel}>{t(`login.scope.${scope}`)}</span>
      {locked && (
        <span className={styles.lockedBadge}>
          {t('login.consent.alwaysAuthorized')}
        </span>
      )}
    </label>
  );
}

/** 右栏：应用名 + 受控 scope 勾选列表。 */
export function PermissionPanel({
  clientName,
  scope,
  grantedScopes = '',
  selected,
  onSelectedChange,
  disabled = false,
}: PermissionPanelProps) {
  const tokens = scopeTokens(scope);
  const change = (token: string) => {
    const next = toggleScopeItem(selected, token, grantedScopes);
    onSelectedChange(normalizeSelection(next, scope, grantedScopes));
  };
  return (
    <section className={styles.panel} aria-label={t('login.consent.title')}>
      <h2 className={styles.appName}>{clientName}</h2>
      {tokens.length === 0 ? (
        <p className={styles.empty}>
          {t('login.consent.hint', { app: clientName })}
        </p>
      ) : (
        <ul className={styles.scopeList}>
          {tokens.map((token) => (
            <li key={token}>
              <ScopeCheckbox
                scope={token}
                checked={selected.includes(token)}
                locked={isScopeLocked(token, grantedScopes)}
                disabled={disabled}
                onToggle={() => change(token)}
              />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
