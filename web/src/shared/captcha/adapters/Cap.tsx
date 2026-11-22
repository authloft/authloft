/**
 * Capjs wrapper（docs/前端架构.md §3.5 行 391；接口文档 §2.5 行 489-531）。
 *
 * API 口径（review/03 §3.2）：widget 脚本（默认 jsDelivr CDN，自托管时由
 * 配置换地址）注册 `<cap-widget>` 自定义元素；挂载 = 建元素并设
 * `data-cap-api-endpoint`（`<base>/<site key>/`，challenge / redeem 都打
 * 该前缀）；token 经 `solve` 事件产出（`e.detail.token`），写入隐藏字段
 * 的表单形态与本仓无关（弹窗提交，不走表单字段）。
 *
 * token 承载（§2.5 行 689）：单 token 原文直接放入，无打包。
 *
 * endpoint 取用：自托管 base 由配置透出（§3.5 行 450「自托管 base 由配置
 * 透出」）——CaptchaConfig 仅三字段，故 options.apiEndpoint 优先；缺省时
 * siteKey 本身是绝对 URL 即视为已组合的 `<base>/<site key>/` 端点；两者
 * 皆无 → 配置残缺，走基座可见错误态（fail-fast，不打默认 CDN 的演示
 * 服务，避免挑战打到错误服务器）。
 *
 * siteKey = ext.client_id = site key（后端架构 §15.5）。
 * 类型手写最小面声明（零 npm 依赖，沿 Turnstile 先例）；getVendor 可注入，
 * node 测试环境注入 mock。
 */
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaAdapter } from '../types';
import {
  VendorChallengeAdapter,
  type VendorChallengeOptions,
} from './VendorChallenge';

/** Cap widget 脚本地址（官方 CDN 默认值；自托管走配置，运行期动态注入）。 */
export const CAP_SCRIPT_URL = 'https://cdn.jsdelivr.net/npm/@cap.js/widget';

/** `solve` 事件 detail（review §3.2：e.detail.token）。 */
export interface CapSolveEventDetail {
  token?: string;
}

/** cap-widget 注册后的自定义元素构造器（getVendor 的取用面）。 */
export type CapVendorApi = CustomElementConstructor;

export interface CapAdapterOptions extends VendorChallengeOptions {
  /** 厂商全局对象取用（缺省 () => window.customElements.get('cap-widget')；测试注入 mock）。 */
  getVendor?: () => CapVendorApi | undefined;
  /** 自托管 API 端点 `<base>/<site key>/`（缺省走 siteKey 组合端点形态）。 */
  apiEndpoint?: string;
}

export class CapAdapter extends VendorChallengeAdapter<CapVendorApi> {
  private getVendorFn: () => CapVendorApi | undefined;
  private apiEndpoint: string | undefined;
  private widget: HTMLElement | null = null;

  constructor(captcha: CaptchaConfig, options: CapAdapterOptions = {}) {
    super(captcha, options);
    this.getVendorFn =
      options.getVendor ?? (() => window.customElements?.get('cap-widget'));
    this.apiEndpoint = options.apiEndpoint;
  }

  protected scriptUrl(): string {
    return CAP_SCRIPT_URL;
  }

  protected getVendor(): CapVendorApi | undefined {
    return this.getVendorFn();
  }

  /**
   * widget API 端点解析：显式 options 优先；siteKey 为绝对 URL 时视为
   * 配置透出的组合端点（§3.5 行 450）；皆无 → undefined（调用方走可见
   * 错误态，不打演示服务）。
   */
  private resolveEndpoint(): string | undefined {
    if (this.apiEndpoint !== undefined && this.apiEndpoint !== '') {
      return this.apiEndpoint;
    }
    if (/^https?:\/\//i.test(this.siteKey)) {
      return this.siteKey;
    }
    return undefined;
  }

  protected mountChallenge(vendor: CapVendorApi, container: HTMLElement): void {
    const epoch = this.challengeEpoch();
    // vendor = customElements 注册产物（getVendor 已挡未定义）；非函数属
    // 异常 SDK 状态，进错误态而非裸挂载。
    if (typeof vendor !== 'function') {
      this.rejectChallenge(epoch);
      return;
    }
    const endpoint = this.resolveEndpoint();
    if (endpoint === undefined) {
      this.rejectChallenge(epoch);
      return;
    }
    const widget = this.doc.createElement('cap-widget');
    widget.setAttribute('data-cap-api-endpoint', endpoint);
    widget.addEventListener('solve', (event: Event) => {
      const detail = (event as CustomEvent).detail as
        | CapSolveEventDetail
        | undefined;
      const token = detail?.token;
      // 空串不置位（基座 acceptToken 同口径），未完成 → getToken undefined。
      if (typeof token === 'string') {
        this.acceptToken(epoch, token);
      }
    });
    this.widget = widget;
    container.appendChild(widget);
  }

  protected teardownChallenge(): void {
    if (this.widget !== null) {
      this.widget.remove();
      this.widget = null;
    }
  }
}

/**
 * 分派器用的工厂（§3.5 行 350：capjs → 本 adapter）；签名兼容
 * CaptchaAdapterFactory。第二参供测试注入替身，缺省生产实现。
 */
export const createCapAdapter = (
  captcha: CaptchaConfig,
  options?: CapAdapterOptions,
): CaptchaAdapter => new CapAdapter(captcha, options);
