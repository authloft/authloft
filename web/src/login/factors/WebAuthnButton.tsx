/**
 * 通行密钥因子按钮（webauthn；docs/前端架构.md §4.3 行 453）：
 * 双段按钮——challenge 步（无 challengeData）点击上抛 onSubmit 空表单值（容器
 * 以 step=challenge 提交、payload {}，§2.6 行 547），后端经 nextStep.challengeData
 * 下发 WebAuthn options；verify 段（容器注入 challengeData）点击调
 * @simplewebauthn/browser 的 startAuthentication()，断言对象经 onCredential
 * 上抛（容器组装 payload {credential}，§2.6 行 548）。
 *
 * - 固定 usernameless（§1.10 行 308：不传 allowCredentials、不收集用户名；需求
 *   §4.1.6 行 103）：options 完全取自后端下发的 challengeData（§1.3 行 117；
 *   §12.9 方案 A Struct），不解析字段、整体透传给 navigator.credentials.get()
 *   （经 startAuthentication 包装）；
 * - window.PublicKeyCredential 缺失则隐藏（§4.3 行 453；需求 §4.1.6 行 105
 *   浏览器 / 设备不支持自动不展示，无「不支持」提示）；
 * - 不使用通用字段渲染器（§4.3 行 453：浏览器原生 UI 改不了任何一行）；
 *   错误语义独立处理：用户取消（NotAllowedError）与失败分开提示，不进
 *   ErrorBanner / FieldRenderer 管线；
 * - 注册 / 创建凭据场景（PublicKeyCredentialCreationOptions）归 account 域
 *   安全中心（§4.5），本组件只承担登录断言。
 *
 * 文案：i18n 无键，中文字面量 + 注释声明，扩键归后续 i18n 实现。
 */
import { useState } from 'react';
import type { JsonObject } from '@bufbuild/protobuf';
import {
  startAuthentication,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import type { FactorProps } from './registry';
import styles from './WebAuthnButton.module.less';

/** challenge 步发起按钮文案（i18n 无键，字面量声明见文件头）。 */
const USE_TEXT = '使用通行密钥登录';
/** verify 段断言按钮文案（同上）。 */
const VERIFY_TEXT = '验证';
/** 用户取消提示（NotAllowedError = 浏览器原生 UI 关闭；同上）。 */
const CANCELLED_TEXT = '已取消通行密钥验证';
/** 失败兜底提示（§1.6 行 272 不暴露内部信息；同上）。 */
const FAILED_TEXT = '通行密钥验证失败，请重试';

/** window.PublicKeyCredential 缺失则隐藏（§4.3 行 453；node 测试环境无 window）。 */
function webauthnAvailable(): boolean {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window;
}

/** authenticate 依赖注入（缺省 @simplewebauthn/browser；测试替身注入）。 */
export interface AuthenticateDeps {
  /** 断言发起替身：optionsJSON 整体透传（不解析、不额外传 allowCredentials）。 */
  start?: (optionsJSON: JsonObject) => Promise<JsonObject>;
}

/** 断言结果：ok=false 时 cancelled 区分用户取消与失败（错误语义独立，§4.3 行 453）。 */
export type WebAuthnAuthResult =
  | { readonly ok: true; readonly credential: JsonObject }
  | { readonly ok: false; readonly cancelled: boolean };

/** 缺省发起：@simplewebauthn/browser startAuthentication（浏览器原生 UI）。 */
async function defaultStart(optionsJSON: JsonObject): Promise<JsonObject> {
  const assertion: AuthenticationResponseJSON = await startAuthentication({
    optionsJSON: optionsJSON as unknown as PublicKeyCredentialRequestOptionsJSON,
  });
  // @simplewebauthn 断言对象 → Struct JSON 形状（§12.9 行 1783 credential 透传）。
  return assertion as unknown as JsonObject;
}

/**
 * 发起断言（纯函数，node 可测）：challengeData 整体透传（§12.9 方案 A：前端
 * 不逐字段消费 options 对象）；NotAllowedError = 用户取消（浏览器原生 UI 关闭），
 * 其余为失败——异常语义收口在此，组件只消费 cancelled 布尔。
 */
export async function authenticate(
  challengeData: JsonObject,
  deps: AuthenticateDeps = {},
): Promise<WebAuthnAuthResult> {
  const start = deps.start ?? defaultStart;
  try {
    const credential = await start(challengeData);
    return { ok: true, credential };
  } catch (err) {
    return {
      ok: false,
      cancelled: err instanceof DOMException && err.name === 'NotAllowedError',
    };
  }
}

/** WebAuthn 系专属扩展 props（全部可选，不破坏 registry 的 FactorProps 契约）。 */
export interface WebAuthnButtonProps extends FactorProps {
  /** 后端下发的 WebAuthn options（§1.3 行 117 nextStep.challengeData；undefined=challenge 步发起）。 */
  challengeData?: JsonObject;
  /** 断言对象上抛（容器组装 payload {credential}，§2.6 行 548；Struct 透传）。 */
  onCredential?: (credential: JsonObject) => void;
}

/**
 * WebAuthn 因子判定（组件引用比较，isOtpForm 同款）：容器据此走「专属因子
 * 组件 + 扩展 props」的渲染路径（challengeData 注入 / 断言上抛）。
 */
export function isWebAuthnForm(factor: unknown): boolean {
  return factor === WebAuthnButton;
}

export function WebAuthnButton({
  loading,
  disabled,
  onSubmit,
  onCredential,
  challengeData,
}: WebAuthnButtonProps) {
  // 错误提示独立 state（§4.3 行 453 错误语义独立处理，不进通用渲染器管线）。
  const [error, setError] = useState<'cancelled' | 'failed' | null>(null);

  if (!webauthnAvailable()) {
    // 需求 §4.1.6 行 105：不支持时自动不展示（无「不支持」提示）。
    return null;
  }

  const start = async () => {
    if (loading || disabled) {
      return;
    }
    setError(null);
    if (challengeData === undefined) {
      // challenge 步：空表单值上抛（容器 step=challenge 提交，payload {}，§2.6 行 547）。
      onSubmit({});
      return;
    }
    const result = await authenticate(challengeData);
    if (result.ok) {
      onCredential?.(result.credential);
    } else {
      setError(result.cancelled ? 'cancelled' : 'failed');
    }
  };

  return (
    <div className={styles.wrap}>
      <button
        type="button"
        disabled={loading || disabled}
        onClick={start}
        className={styles.button}
      >
        {challengeData === undefined ? USE_TEXT : VERIFY_TEXT}
      </button>
      {error === 'cancelled' && (
        <p role="alert" className={styles.notice}>{CANCELLED_TEXT}</p>
      )}
      {error === 'failed' && (
        <p role="alert" className={styles.notice}>{FAILED_TEXT}</p>
      )}
    </div>
  );
}
