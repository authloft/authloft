/**
 * CaptchaWidget 分派器（docs/前端架构.md §3.5 行 350）：按当前
 * captcha.type 加载对应 wrapper（image →
 * adapters/Image；turnstile / recaptcha / hcaptcha → 对应厂商 wrapper，第三方
 * JS 由 wrapper 经 loadVendorScript 运行期动态加载，不打包不写死标签），
 * 统一生命周期（render / getToken / reset 经 ref 暴露给调用方）。
 *
 * 本组件不发任何配置请求（§3.5 行 363、§9 第 11 条）：{providerKey, type,
 * siteKey} 全部由调用方 prop 传入——首屏注入快照（login）/ GetConfig（account）
 * / 运行期响应顶层 captcha 三个取用时机是调用方职责，组件不感知来源、不缓存
 * 为模块级常量（§9 第 11 条）。
 *
 * 调用方换 captcha 对象（权威来源变化，含服务端降级为 image，§3.5 行 361、
 * §2.5 行 515-519）→ adapterKey 变化 → effect 重建 wrapper 按新 type 重新
 * 渲染，不刷新页面。组件不感知业务（登录 vs 绑定一律不分）。
 */
import { useEffect, useImperativeHandle, useRef, type Ref } from 'react';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import { t } from '../i18n';
import { createHCaptchaAdapter } from './adapters/HCaptcha';
import { createImageAdapter } from './adapters/Image';
import { createRecaptchaAdapter } from './adapters/Recaptcha';
import { createTurnstileAdapter } from './adapters/Turnstile';
import type { CaptchaAdapter, CaptchaAdapterFactory } from './types';
import styles from './CaptchaWidget.module.less';

// 未知 type（§2.5 行 500 四值之外的协议外取值）→ 兜底错误态，
// 文案 common.refreshAndRetry（i18n 收口）。

/**
 * wrapper 重建判据：providerKey / type / siteKey 三字段联合（§2.5 行 478-486
 * 三处同结构）。同值对象换引用不重建（权威来源重复下发同值时不无谓重拉）；
 * 任一字段变（含降级 image）→ 重建。缺失字段按零值兜底（§9 第 18 条）。
 */
export function adapterKey(captcha: CaptchaConfig): string {
  return `${captcha.providerKey ?? ''}\u0000${captcha.type ?? ''}\u0000${captcha.siteKey ?? ''}`;
}

/**
 * type → wrapper 工厂分派（§3.5 行 350；§2.5 行 500 四种 type）。image 含
 * 服务端降级态（§2.5 行 486、515：第三方不可用时服务端下发 type=image）；
 * turnstile / recaptcha / hcaptcha →
 * 厂商 wrapper；未知 type →
 * undefined → 兜底错误态。
 */
export function adapterFactoryFor(
  type: string,
): CaptchaAdapterFactory | undefined {
  switch (type) {
    case 'image':
      return createImageAdapter;
    case 'turnstile':
      return createTurnstileAdapter;
    case 'recaptcha':
      return createRecaptchaAdapter;
    case 'hcaptcha':
      return createHCaptchaAdapter;
    default:
      return undefined;
  }
}

/** 经 ref 暴露给调用方的统一生命周期句柄（提交取凭据、校验失败重置）。 */
export interface CaptchaWidgetHandle {
  /** 透传当前 wrapper 的 getToken；wrapper 无 / 用户未完成 → undefined（调用方不带 captcha 提交）。 */
  getToken(): CaptchaPayload | undefined;
  /** 透传 reset（captcha_invalid / 过期 / 场景切换，§3.5 行 364）。 */
  reset(): void;
}

export interface CaptchaWidgetProps {
  /** 当前权威 captcha 配置对象（接口文档 §2.5；来源三选一，由调用方注入）。 */
  captcha: CaptchaConfig;
  /** React 19 ref-as-prop：暴露 {getToken, reset}。 */
  ref?: Ref<CaptchaWidgetHandle>;
}

export function CaptchaWidget({ captcha, ref }: CaptchaWidgetProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const adapterRef = useRef<CaptchaAdapter | undefined>(undefined);
  const factory = adapterFactoryFor(captcha.type ?? '');
  const key = adapterKey(captcha);

  useEffect(() => {
    const container = containerRef.current;
    if (container === null) {
      return;
    }
    const adapter = factory?.(captcha);
    if (adapter === undefined) {
      return;
    }
    adapterRef.current = adapter;
    adapter.render(container);
    return () => {
      // 换 wrapper / 卸载：丢引用即可——旧 wrapper 在途取图完成也只 paint 进
      // 已脱离文档的容器，不可见、不再被引用。CaptchaAdapter 接口三方法固定
      // （§3.5 行 351），不为其扩 dispose。
      adapterRef.current = undefined;
    };
  }, [key]);

  useImperativeHandle(
    ref,
    () => ({
      getToken: () => adapterRef.current?.getToken(),
      reset: () => {
        adapterRef.current?.reset();
      },
    }),
    [],
  );

  if (factory === undefined) {
    return (
      <p role="alert" className={styles.fallbackAlert}>
        {t('common.refreshAndRetry')}
      </p>
    );
  }
  return <div ref={containerRef} className={styles.container} />;
}
