/**
 * 回调地址只读提示（docs/前端架构.md §6 行 511；docs/接口文档.md §2.7.3
 * 行 602 `GET /sso/oauth/callback/{provider_key}` / §5.3 行 1193 回调地址
 * 语义）：`{al_root}/sso/oauth/callback/{provider_key}` 只读展示 + 复制
 * （shared CopyButton）；OIDC 类 Provider 另提示「回调需精确匹配」。
 *
 * 两种形态：
 * - **模板形态**（providerKey 缺省）：渲染字面 `{provider_key}` 占位——列表
 *   页顶部提示用（告知回调地址结构，复制产物即该模板）；
 * - **具体形态**（providerKey + type 给定）：具体 Provider 的回调地址 +
 *   OIDC 精确匹配注记——编辑页消费。
 *
 * URL 组装（providerCallbackUrl）与 OIDC 判定（isOidcProviderType）为纯
 * 函数（零 Semi 依赖，node 可测）；本组件零 Semi import，渲染可经
 * renderToStaticMarkup 静态验证（components.test.ts 同模式）。
 * OIDC 判定口径：标准协议兜底渠道 type 为 `oidc` 或 `oauth2`
 * （接口文档 §9 行 1461「type=oidc｜oauth2」+ 需求 §4.3.1 行 162）——
 * 后端注册表现状（oauth 域 wechat_mp、消息域 aliyun_sms / smtp）无任何
 * `oidc_` 前缀类型，原前缀判定恒 false。
 * 样式（§1.7）：同目录同名 module less。
 */
import type { ReactNode } from 'react';
import { CopyButton } from '../../shared/components/CopyButton';
import { t } from '../../shared/i18n';
import { OAUTH_CALLBACK_PREFIX } from '../../shared/urls';
import styles from './ProviderCallbackHint.module.less';

/** providerKey 未给定时渲染的字面占位（复制产物即此模板）。 */
const PROVIDER_KEY_PLACEHOLDER = '{provider_key}';

/**
 * 回调地址组装（node 可测）：`{alRoot}/sso/oauth/callback/{providerKey}`；
 * providerKey 缺省 → 字面 `{provider_key}` 模板（alRoot 归一后无尾斜杠，
 * 见 ./bootstrap；node 环境为空串 → 相对路径形态）。
 */
export function providerCallbackUrl(
  alRoot: string,
  providerKey?: string,
): string {
  return `${alRoot}${OAUTH_CALLBACK_PREFIX}${providerKey ?? PROVIDER_KEY_PLACEHOLDER}`;
}

/**
 * OIDC 类判定（接口文档 §9 行 1461 + 需求 §4.3.1 行 162：标准协议兜底
 * 渠道 type=oidc｜oauth2）：命中 → 另提示「回调需精确匹配」。
 */
export function isOidcProviderType(type: string | undefined): boolean {
  return type === 'oidc' || type === 'oauth2';
}

/**
 * 回调地址提示是否展示：只有 oauth 类 Provider 有 `/sso/oauth/callback/{key}`
 * 入口。schema 未落地（尚未选型）沿用模板形态提示；`sms` / `email` /
 * `union` 及虚拟类别一律不展示（接口文档 §5.3 表列按 category 裁剪）。
 */
export function showsCallbackHint(category: string | undefined): boolean {
  return category === undefined || category === 'oauth';
}

export interface ProviderCallbackHintProps {
  /** 归一后 Authloft 根域名（回调地址前缀）。 */
  alRoot: string;
  /** Provider 唯一标识；缺省渲染字面 `{provider_key}` 模板（列表页顶部形态）。 */
  providerKey?: string;
  /** Provider 类型；OIDC / OAuth2 标准协议兜底类另提示「回调需精确匹配」（编辑页消费）。 */
  type?: string;
}

/** 顶部只读提示：地址文本 + 复制按钮 + 可选 OIDC 精确匹配注记。 */
export function ProviderCallbackHint(
  props: ProviderCallbackHintProps,
): ReactNode {
  const url = providerCallbackUrl(props.alRoot, props.providerKey);
  return (
    <div className={styles.hint} role="note">
      <span className={styles.label}>{t('admin.callbackUrlLabel')}</span>
      <code className={styles.url}>{url}</code>
      <CopyButton text={url} />
      {isOidcProviderType(props.type) ? (
        <span className={styles.oidcNote}>
          {t('admin.oidcCallbackExactMatchNote')}
        </span>
      ) : null}
    </div>
  );
}
