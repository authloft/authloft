/**
 * GeeTest v4 wrapper（docs/前端架构.md §3.5 行 391；接口文档 §2.5 行 489-531）。
 *
 * API 口径（review/03 §1.2）：gt4.js 动态加载后 `initGeetest4(config, cb)`
 * 初始化，captchaObj.appendTo 挂载触发按钮；用户完成挑战 onSuccess 后
 * `getValidate()` 返回四字段对象（失败返回 false），不提交、可重新触发。
 * getValidate 必须在 onSuccess 后调用（review §1.5 坑点）。
 *
 * token 承载（§2.5 行 690）：getValidate() 的四字段（lot_number /
 * captcha_output / pass_token / gen_time）整体 JSON 序列化打包进单字符串
 * token，服务端 Verifier 解包后按 captcha_key 生成 sign_token 二次校验
 * （sign_token 永不从前端收取）。
 *
 * product 固定 popup：弹窗架构（§3.5「一律弹窗」）内 widget 须自含触发
 * 按钮挂进容器——bind 需业务按钮调 showCaptcha（无挂点），popup / float
 * 同为 appendTo 形态。后台 widget_product(66) / widget_options(67) 无
 * 浏览器下发渠道（CaptchaConfig 仅三字段），需透传时走 adapter options。
 *
 * siteKey = ext.client_id = captcha_id（后端架构 §15.5）。
 * 类型手写最小面声明（零 npm 依赖，沿 Turnstile 先例）；getVendor 可注入，
 * node 测试环境注入 mock。
 */
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaAdapter } from '../types';
import {
  VendorChallengeAdapter,
  type VendorChallengeOptions,
} from './VendorChallenge';

/** GeeTest v4 脚本地址（运行期动态注入，不打包不写死标签）。 */
export const GEETEST_SCRIPT_URL = 'https://static.geetest.com/v4/gt4.js';

/** initGeetest4 初始化参数（最小面：captchaId + 交互模式）。 */
export interface GeetestInitConfig {
  captchaId: string;
  product: string;
}

/** getValidate() 的四字段（§2.5 行 690 打包口径）。 */
export interface GeetestValidate {
  lot_number: string;
  captcha_output: string;
  pass_token: string;
  gen_time: string;
}

/** initGeetest4 产出的挑战对象（最小面：挂载 / 回调 / 取凭据 / 销毁）。 */
export interface GeetestCaptchaObj {
  appendTo(container: HTMLElement): void;
  onSuccess(callback: () => void): void;
  onError(callback: () => void): void;
  /** 未完成 / 失败返回 false（review §1.2）。 */
  getValidate(): GeetestValidate | false;
  destroy(): void;
}

/** GeeTest v4 全局 API（手写最小面声明）。 */
export interface GeetestApi {
  initGeetest4(
    config: GeetestInitConfig,
    callback: (captchaObj: GeetestCaptchaObj) => void,
  ): void;
}

declare global {
  interface Window {
    initGeetest4?: GeetestApi['initGeetest4'];
  }
}

export interface GeetestAdapterOptions extends VendorChallengeOptions {
  /** 厂商全局对象取用（缺省 () => window.initGeetest4；测试注入 mock）。 */
  getVendor?: () => GeetestApi | undefined;
  /** 交互模式（缺省 popup，见头部注释）。 */
  product?: string;
}

export class GeetestAdapter extends VendorChallengeAdapter<GeetestApi> {
  private getVendorFn: () => GeetestApi | undefined;
  private product: string;
  private captchaObj: GeetestCaptchaObj | null = null;

  constructor(captcha: CaptchaConfig, options: GeetestAdapterOptions = {}) {
    super(captcha, options);
    this.getVendorFn =
      options.getVendor ??
      (() =>
        window.initGeetest4
          ? { initGeetest4: window.initGeetest4 }
          : undefined);
    this.product = options.product ?? 'popup';
  }

  protected scriptUrl(): string {
    return GEETEST_SCRIPT_URL;
  }

  protected getVendor(): GeetestApi | undefined {
    return this.getVendorFn();
  }

  protected mountChallenge(vendor: GeetestApi, container: HTMLElement): void {
    const epoch = this.challengeEpoch();
    try {
      vendor.initGeetest4(
        { captchaId: this.siteKey, product: this.product },
        (captchaObj) => {
          // 迟到的初始化回调（reset 竞态）：销毁旧对象，不挂载。
          if (epoch !== this.challengeEpoch()) {
            captchaObj.destroy();
            return;
          }
          this.captchaObj = captchaObj;
          captchaObj.appendTo(container);
          captchaObj.onSuccess(() => {
            const validate = captchaObj.getValidate();
            // false（未完成 / 失败）不提交（§2.5 行 690），留按钮重试。
            if (validate === false) {
              return;
            }
            this.acceptToken(
              epoch,
              JSON.stringify({
                lot_number: validate.lot_number,
                captcha_output: validate.captcha_output,
                pass_token: validate.pass_token,
                gen_time: validate.gen_time,
              }),
            );
          });
          captchaObj.onError(() => this.rejectChallenge(epoch));
        },
      );
    } catch {
      // initGeetest4 同步抛错（配置缺失等）→ 可见错误态 + 手动重试。
      this.rejectChallenge(epoch);
    }
  }

  protected teardownChallenge(): void {
    if (this.captchaObj !== null) {
      this.captchaObj.destroy();
      this.captchaObj = null;
    }
  }
}

/**
 * 分派器用的工厂（§3.5 行 350：geetest_v4 → 本 adapter）；签名兼容
 * CaptchaAdapterFactory。第二参供测试注入替身，缺省生产实现。
 */
export const createGeetestAdapter = (
  captcha: CaptchaConfig,
  options?: GeetestAdapterOptions,
): CaptchaAdapter => new GeetestAdapter(captcha, options);
