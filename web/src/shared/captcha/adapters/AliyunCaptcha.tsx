/**
 * 阿里云验证码 2.0 wrapper（docs/前端架构.md §3.5 行 391；接口文档
 * §2.5 行 489-531）。
 *
 * API 口径（review/03 §2.2，CAPTCHA 2.0 V3 架构）：AliyunCaptcha.js 必须
 * 动态加载（禁止本地化与重复加载，loadVendorScript 同 src 幂等）；init
 * 前置全局 `window.AliyunCaptchaConfig = { region, prefix }`；随后
 * `initAliyunCaptcha({ SceneId, mode, element, button, success, fail,
 * getInstance })`。无感验证不支持 embed、须 popup，popup 以触发按钮拉起
 * 弹层（官方 FAQ 形态）——弹窗架构（§3.5「一律弹窗」）内自建触发按钮 +
 * 弹层挂载点进容器，element / button 走官方选择器形态。
 *
 * token 承载（§2.5 行 691）：success 回调的 `captchaVerifyParam` **原样**
 * 放入 token（禁解析 / 重组 / 修改，两种代际形态并存）；SceneId 来自
 * siteKey（= ext.client_id，后端架构 §15.5），不随 token 提交。fail =
 * 验证未通过（无凭据产出，getToken 保持 undefined），厂商弹层内自带失败
 * 引导，不再叠加基座错误态。
 *
 * region 缺省 cn（后端 Schema 默认值）、prefix 缺省空串——两者随
 * CaptchaConfig 无浏览器下发渠道，后台 prefix(68) / region(57) 需透传时
 * 走 adapter options（接线卡对齐后收口）。
 *
 * 类型手写最小面声明（零 npm 依赖，沿 Turnstile 先例）；getVendor 可注入，
 * node 测试环境注入 mock。
 */
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import { t } from '../../i18n';
import type { CaptchaAdapter } from '../types';
import {
  VendorChallengeAdapter,
  type VendorChallengeOptions,
} from './VendorChallenge';
import styles from './Vendor.module.less';

/** 阿里云验证码脚本地址（运行期动态注入，不打包不写死标签）。 */
export const ALIYUN_CAPTCHA_SCRIPT_URL =
  'https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js';

/** V3 架构前置全局配置（review §2.2：init 前必须就位）。 */
export interface AliyunCaptchaGlobalConfig {
  region: string;
  prefix: string;
}

/** getInstance 产出的挑战实例（最小面：销毁可选——SDK 代际差异兜底）。 */
export interface AliyunCaptchaInstance {
  destroy?: () => void;
}

/** initAliyunCaptcha 初始化参数（popup 模式最小面）。 */
export interface AliyunCaptchaInitConfig {
  SceneId: string;
  mode: 'popup';
  /** 弹层挂载点（官方选择器形态）。 */
  element: string;
  /** 触发按钮（官方选择器形态）。 */
  button: string;
  /** 成功回调：captchaVerifyParam 原样透传（§2.5 行 691）。 */
  success: (captchaVerifyParam: string) => void;
  /** 验证未通过回调：无凭据产出，弹层内自带重试引导。 */
  fail: (result: unknown) => void;
  getInstance: (instance: AliyunCaptchaInstance) => void;
}

/** 阿里云验证码全局 API（手写最小面声明）。 */
export interface AliyunCaptchaApi {
  initAliyunCaptcha(config: AliyunCaptchaInitConfig): void;
}

declare global {
  interface Window {
    AliyunCaptchaConfig?: AliyunCaptchaGlobalConfig;
    initAliyunCaptcha?: AliyunCaptchaApi['initAliyunCaptcha'];
  }
}

export interface AliyunCaptchaAdapterOptions extends VendorChallengeOptions {
  /** 厂商全局对象取用（缺省 () => window.initAliyunCaptcha；测试注入 mock）。 */
  getVendor?: () => AliyunCaptchaApi | undefined;
  /** 地域（缺省 cn；后端 Schema 默认值，决定厂商资源与校验地域一致）。 */
  region?: string;
  /** 实例前缀（控制台实例信息卡获取；缺省空串待配置渠道接线）。 */
  prefix?: string;
}

/** 自建触发按钮 / 弹层挂载点的选择器序号（弹窗可能并存，保证 id 唯一）。 */
let elementSeq = 0;

export class AliyunCaptchaAdapter extends VendorChallengeAdapter<AliyunCaptchaApi> {
  private getVendorFn: () => AliyunCaptchaApi | undefined;
  private region: string;
  private prefix: string;
  private instance: AliyunCaptchaInstance | null = null;

  constructor(
    captcha: CaptchaConfig,
    options: AliyunCaptchaAdapterOptions = {},
  ) {
    super(captcha, options);
    this.getVendorFn =
      options.getVendor ??
      (() =>
        window.initAliyunCaptcha
          ? { initAliyunCaptcha: window.initAliyunCaptcha }
          : undefined);
    this.region = options.region ?? 'cn';
    this.prefix = options.prefix ?? '';
  }

  protected scriptUrl(): string {
    return ALIYUN_CAPTCHA_SCRIPT_URL;
  }

  protected getVendor(): AliyunCaptchaApi | undefined {
    return this.getVendorFn();
  }

  protected mountChallenge(
    vendor: AliyunCaptchaApi,
    container: HTMLElement,
  ): void {
    const epoch = this.challengeEpoch();
    // V3 前置全局（review §2.2）：region / prefix 在 initAliyunCaptcha 之前
    // 就位。经注入 doc 的 defaultView 落位（沿替身注入惯例，node 测试无
    // 全局 window；无 view 的桩文档跳过，SDK 自行报错走错误态）。
    const view = this.doc.defaultView;
    if (view !== null && view !== undefined) {
      view.AliyunCaptchaConfig = { region: this.region, prefix: this.prefix };
    }
    // 自建触发按钮 + 弹层挂载点（popup 模式官方形态：element / button 选择器）。
    // 触发按钮复用基座重试按钮样式（共用样式文件不扩类，review 口径最小面）。
    elementSeq += 1;
    const buttonId = `aliyun-captcha-button-${elementSeq}`;
    const elementId = `aliyun-captcha-element-${elementSeq}`;
    const trigger = this.doc.createElement('button');
    trigger.type = 'button';
    trigger.setAttribute('id', buttonId);
    trigger.textContent = t('common.captchaConfirm');
    trigger.className = styles.retryButton;
    const element = this.doc.createElement('div');
    element.setAttribute('id', elementId);
    // 先落 DOM 再 init（官方示例中 element / button 指向的元素须已在页面）；
    // init 抛错时基座错误态 repaint 会整组替换容器内容，无残留。
    container.replaceChildren(trigger, element);
    try {
      vendor.initAliyunCaptcha({
        SceneId: this.siteKey,
        mode: 'popup',
        element: `#${elementId}`,
        button: `#${buttonId}`,
        success: (captchaVerifyParam) => {
          // 原样透传（§2.5 行 691）：不解析、不重组、不修改。
          this.acceptToken(epoch, captchaVerifyParam);
        },
        fail: () => {
          // 验证未通过：无凭据产出（getToken 保持 undefined），弹层内重试。
        },
        getInstance: (instance) => {
          if (epoch === this.challengeEpoch()) {
            this.instance = instance;
          }
        },
      });
    } catch {
      // init 同步抛错（配置缺失等）→ 可见错误态 + 手动重试（repaint 清挂载元素）。
      this.rejectChallenge(epoch);
    }
  }

  protected teardownChallenge(): void {
    if (this.instance !== null) {
      // destroy 为可选面（SDK 代际差异）：缺省时基座 recover 的
      // replaceChildren 清容器兜底，不留孤儿弹层。
      this.instance.destroy?.();
      this.instance = null;
    }
  }
}

/**
 * 分派器用的工厂（§3.5 行 350：aliyun_captcha → 本 adapter）；签名兼容
 * CaptchaAdapterFactory。第二参供测试注入替身，缺省生产实现。
 */
export const createAliyunCaptchaAdapter = (
  captcha: CaptchaConfig,
  options?: AliyunCaptchaAdapterOptions,
): CaptchaAdapter => new AliyunCaptchaAdapter(captcha, options);
