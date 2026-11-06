/**
 * hCaptcha wrapper（docs/前端架构.md §3.5 行 391；接口文档 §2.5 行
 * 489-531）。
 *
 * API 口径：hCaptcha 显式渲染（官方 js.hcaptcha.com/1/api.js 当前主流）
 * ——api.js 动态加载后 `window.hcaptcha.render(container, {sitekey,
 * callback, 'expired-callback'})` 挂载挑战，token 经回调产出。与 Turnstile
 * 的差异在重置：hcaptcha.reset(widgetId) 原地重置挑战（回到未完成态、
 * 用户重新完成后再次回调 token），无需销毁重挂——reset 生命周期与过期
 * 换新都走它。只封装 render / callback / expired-callback / reset 最小面
 * （主题 / 语言 / 企业特性不做）。
 *
 * 提交格式：{providerKey, token}（§2.5 行 514-522 第三方统一格式，由
 * VendorChallenge 基座的 getToken 产出）。siteKey 空串 → 基座错误态
 * （§2.5 行 501）。
 *
 * 类型手写最小面声明（零 npm 依赖）；getVendor 可注入，node 测试环境
 * mock window.hcaptcha 替身。
 */
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaAdapter } from '../types';
import {
  VendorChallengeAdapter,
  type VendorChallengeOptions,
} from './VendorChallenge';

/** hCaptcha 脚本地址（运行期动态注入，不打包不写死标签）。 */
export const HCAPTCHA_SCRIPT_URL = 'https://js.hcaptcha.com/1/api.js';

/** render 挂载选项（最小面：sitekey + token 回调 + 过期回调）。 */
export interface HCaptchaRenderOptions {
  sitekey: string;
  callback: (token: string) => void;
  'expired-callback': () => void;
}

/** hCaptcha 全局 API（手写最小面声明）。 */
export interface HCaptchaApi {
  /** 显式渲染：挑战挂进 container，token 经 options.callback 回调；返回 widget id。 */
  render(container: HTMLElement, options: HCaptchaRenderOptions): string;
  /** 原地重置挑战（回到未完成态，重新完成后再次回调 token）。 */
  reset(widgetId?: string): void;
}

declare global {
  interface Window {
    hcaptcha?: HCaptchaApi;
  }
}

export interface HCaptchaAdapterOptions extends VendorChallengeOptions {
  /** 厂商全局对象取用（缺省 () => window.hcaptcha；测试注入 mock）。 */
  getVendor?: () => HCaptchaApi | undefined;
}

export class HCaptchaAdapter extends VendorChallengeAdapter<HCaptchaApi> {
  private readonly getVendorFn: () => HCaptchaApi | undefined;
  private widgetId: string | null = null;

  constructor(captcha: CaptchaConfig, options: HCaptchaAdapterOptions = {}) {
    super(captcha, options);
    this.getVendorFn = options.getVendor ?? (() => window.hcaptcha);
  }

  protected scriptUrl(): string {
    return HCAPTCHA_SCRIPT_URL;
  }

  protected getVendor(): HCaptchaApi | undefined {
    return this.getVendorFn();
  }

  protected mountChallenge(
    vendor: HCaptchaApi,
    container: HTMLElement,
  ): void {
    const epoch = this.challengeEpoch();
    this.widgetId = vendor.render(container, {
      sitekey: this.siteKey,
      callback: (token) => this.acceptToken(epoch, token),
      'expired-callback': () => this.onExpired(epoch),
    });
  }

  /**
   * 已挂载挑战的重置走 hcaptcha.reset 原地换新（widget 仍有效、id 不变，
   * 故不清 widgetId——连续 reset 均原地重置，与 Turnstile 的销毁式不同）。
   */
  protected teardownChallenge(): void {
    if (this.widgetId !== null) {
      this.getVendorFn()?.reset(this.widgetId);
    }
  }

  /**
   * 重启挑战覆盖（reset / 过期 / 手动重试）：已挂载 → 原地 vendor.reset
   * （不重复挂载，避免双 widget）；未挂载（加载失败 / 在途 / siteKey 空）
   * → 从头 recover（重新加载与渲染，脚本已加载时幂等直通）。
   */
  protected restart(): void {
    if (this.widgetId !== null && this.getVendorFn() !== undefined) {
      this.teardownChallenge();
      return;
    }
    void this.recover();
  }
}

/**
 * 分派器用的工厂（§3.5 行 350：hcaptcha → 本 adapter）；签名兼容
 * CaptchaAdapterFactory。第二参供测试注入替身，缺省生产实现。
 */
export const createHCaptchaAdapter = (
  captcha: CaptchaConfig,
  options?: HCaptchaAdapterOptions,
): CaptchaAdapter => new HCaptchaAdapter(captcha, options);
