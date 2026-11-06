/**
 * Google reCAPTCHA wrapper（docs/前端架构.md §3.5 行 391；接口文档 §2.5
 * 行 489-531）。
 *
 * API 口径：reCAPTCHA v3（脚本带 `?render=SITEKEY` 加载、execute →
 * Promise<token> 的当前主流形态）——无感验证、无可视挑战 widget（badge 由
 * 厂商注入页面），挂载即 `grecaptcha.ready(() => execute(siteKey,
 * {action}))` 预取 token；reset 生命周期 = 重新 execute 换新 token（v3
 * token 短效，无过期回调概念）。action 取中性值 'captcha'——组件不感知
 * 业务（登录 vs 绑定一律不分，CaptchaWidget 头注释口径）。只封装 ready /
 * execute 最小面（主题 / 语言 / 企业特性不做）。
 *
 * 提交格式：{providerKey, token}（§2.5 行 514-522 第三方统一格式，由
 * VendorChallenge 基座的 getToken 产出）。siteKey 空串 → 基座错误态
 * （§2.5 行 501）。execute 失败 → 基座错误态（可见、可重试）。
 *
 * 类型手写最小面声明（零 npm 依赖）；getVendor 可注入，node 测试环境
 * mock grecaptcha 替身。
 */
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaAdapter } from '../types';
import {
  VendorChallengeAdapter,
  type VendorChallengeOptions,
} from './VendorChallenge';

/** reCAPTCHA 脚本地址基址（v3：追加 ?render=SITEKEY）。 */
export const RECAPTCHA_SCRIPT_URL = 'https://www.google.com/recaptcha/api.js';

/** execute 的 action 取值（中性、无业务语义；服务端不校验 action，§2.5 提交格式无此字段）。 */
export const RECAPTCHA_ACTION = 'captcha';

/** reCAPTCHA v3 全局 API（手写最小面声明）。 */
export interface GrecaptchaApi {
  /** 脚本就绪回调（onload 后注册立即触发）。 */
  ready(callback: () => void): void;
  /** v3 口径：执行挑战 → Promise<token>（无感，无可视 widget）。 */
  execute(siteKey: string, options: { action: string }): Promise<string>;
}

declare global {
  interface Window {
    grecaptcha?: GrecaptchaApi;
  }
}

export interface RecaptchaAdapterOptions extends VendorChallengeOptions {
  /** 厂商全局对象取用（缺省 () => window.grecaptcha；测试注入 mock）。 */
  getVendor?: () => GrecaptchaApi | undefined;
}

export class RecaptchaAdapter extends VendorChallengeAdapter<GrecaptchaApi> {
  private readonly getVendorFn: () => GrecaptchaApi | undefined;

  constructor(captcha: CaptchaConfig, options: RecaptchaAdapterOptions = {}) {
    super(captcha, options);
    this.getVendorFn = options.getVendor ?? (() => window.grecaptcha);
  }

  protected scriptUrl(): string {
    return `${RECAPTCHA_SCRIPT_URL}?render=${encodeURIComponent(this.siteKey)}`;
  }

  protected getVendor(): GrecaptchaApi | undefined {
    return this.getVendorFn();
  }

  protected mountChallenge(
    vendor: GrecaptchaApi,
    _container: HTMLElement,
  ): void {
    const epoch = this.challengeEpoch();
    vendor.ready(() => {
      vendor
        .execute(this.siteKey, { action: RECAPTCHA_ACTION })
        .then((token) => this.acceptToken(epoch, token))
        .catch(() => this.rejectChallenge(epoch));
    });
  }

  /** v3 无已挂载 widget（badge 由厂商自管）：无可清。 */
  protected teardownChallenge(): void {}
}

/**
 * 分派器用的工厂（§3.5 行 350：recaptcha → 本 adapter）；签名兼容
 * CaptchaAdapterFactory。第二参供测试注入替身，缺省生产实现。
 */
export const createRecaptchaAdapter = (
  captcha: CaptchaConfig,
  options?: RecaptchaAdapterOptions,
): CaptchaAdapter => new RecaptchaAdapter(captcha, options);
