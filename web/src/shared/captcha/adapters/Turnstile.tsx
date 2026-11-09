/**
 * Cloudflare Turnstile wrapper（docs/前端架构.md §3.5 行 391；接口文档
 * §2.5 行 489-531）。
 *
 * API 口径：Turnstile 显式渲染（官方 challenges.cloudflare.com/turnstile/v0
 * 当前主流）——api.js 动态加载后 `window.turnstile.render(container,
 * {sitekey, callback, 'expired-callback'})` 挂载挑战，token 经回调产出；
 * token 过期（expired-callback）与 reset 生命周期同路：`remove(widgetId)`
 * 销毁旧 widget 后重新挂载换新。只封装 render / expired-callback / remove
 * 最小面（主题 / 语言 / 企业特性不做，§3.5 行 391）。
 *
 * 提交格式：{providerKey, token}（§2.5 行 514-522 第三方统一格式，由
 * VendorChallenge 基座的 getToken 产出）。siteKey 空串 → 基座错误态
 * （§2.5 行 501：空串正常态只应出现在 type=image）。
 *
 * 类型手写最小面声明（零 npm 依赖：禁引 @types 或厂商 SDK 包）；getVendor
 * 可注入，node 测试环境 mock window.turnstile 替身。
 */
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaAdapter } from '../types';
import {
  VendorChallengeAdapter,
  type VendorChallengeOptions,
} from './VendorChallenge';

/** Turnstile 脚本地址（运行期动态注入，不打包不写死标签）。 */
export const TURNSTILE_SCRIPT_URL =
  'https://challenges.cloudflare.com/turnstile/v0/api.js';

/** render 挂载选项（最小面：sitekey + token 回调 + 过期回调）。 */
export interface TurnstileRenderOptions {
  sitekey: string;
  callback: (token: string) => void;
  'expired-callback': () => void;
}

/** Turnstile 全局 API（手写最小面声明）。 */
export interface TurnstileApi {
  /** 显式渲染：挑战挂进 container，token 经 options.callback 回调；返回 widget id。 */
  render(container: HTMLElement, options: TurnstileRenderOptions): string;
  /** 销毁 widget（reset / 过期换新：销毁后重新 render）。 */
  remove(widgetId: string): void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

export interface TurnstileAdapterOptions extends VendorChallengeOptions {
  /** 厂商全局对象取用（缺省 () => window.turnstile；测试注入 mock）。 */
  getVendor?: () => TurnstileApi | undefined;
}

export class TurnstileAdapter extends VendorChallengeAdapter<TurnstileApi> {
  private getVendorFn: () => TurnstileApi | undefined;
  private widgetId: string | null = null;

  constructor(captcha: CaptchaConfig, options: TurnstileAdapterOptions = {}) {
    super(captcha, options);
    this.getVendorFn = options.getVendor ?? (() => window.turnstile);
  }

  protected scriptUrl(): string {
    return TURNSTILE_SCRIPT_URL;
  }

  protected getVendor(): TurnstileApi | undefined {
    return this.getVendorFn();
  }

  protected mountChallenge(vendor: TurnstileApi, container: HTMLElement): void {
    const epoch = this.challengeEpoch();
    this.widgetId = vendor.render(container, {
      sitekey: this.siteKey,
      callback: (token) => this.acceptToken(epoch, token),
      'expired-callback': () => this.onExpired(epoch),
    });
  }

  protected teardownChallenge(): void {
    if (this.widgetId !== null) {
      this.getVendorFn()?.remove(this.widgetId);
      this.widgetId = null;
    }
  }
}

/**
 * 分派器用的工厂（§3.5 行 350：turnstile → 本 adapter）；签名兼容
 * CaptchaAdapterFactory。第二参供测试注入替身，缺省生产实现。
 */
export const createTurnstileAdapter = (
  captcha: CaptchaConfig,
  options?: TurnstileAdapterOptions,
): CaptchaAdapter => new TurnstileAdapter(captcha, options);
