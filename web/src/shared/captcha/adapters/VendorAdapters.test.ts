// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（既定裁决，tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { create } from '@bufbuild/protobuf';
import { CaptchaConfigSchema } from '../../../gen/proto/api/common/v1/captcha_pb';
import { t } from '../../i18n';
import {
  createHCaptchaAdapter,
  HCAPTCHA_SCRIPT_URL,
  type HCaptchaApi,
  type HCaptchaRenderOptions,
} from './HCaptcha';
import {
  createRecaptchaAdapter,
  RECAPTCHA_ACTION,
  RECAPTCHA_SCRIPT_URL,
  type GrecaptchaApi,
} from './Recaptcha';
import {
  createTurnstileAdapter,
  TURNSTILE_SCRIPT_URL,
  type TurnstileApi,
  type TurnstileRenderOptions,
} from './Turnstile';
import {
  createGeetestAdapter,
  GEETEST_SCRIPT_URL,
  type GeetestApi,
  type GeetestCaptchaObj,
  type GeetestInitConfig,
  type GeetestValidate,
} from './Geetest';
import {
  createAliyunCaptchaAdapter,
  ALIYUN_CAPTCHA_SCRIPT_URL,
  type AliyunCaptchaApi,
  type AliyunCaptchaInitConfig,
  type AliyunCaptchaInstance,
} from './AliyunCaptcha';
import { createCapAdapter, CAP_SCRIPT_URL, type CapVendorApi } from './Cap';

// ---------------------------------------------------------------------------
// node 无 DOM、无真厂商：document 注入桩（沿 Image.test.ts 替身注入惯例），
// 厂商全局对象经各 adapter 的 getVendor 注入 mock（render / execute / 回调
// 全可控），覆盖三家 wrapper 的挂载、token 产出、失败态与重置生命周期。
// ---------------------------------------------------------------------------

interface FakeElement {
  tag: string;
  children: FakeElement[];
  textContent: string;
  type: string;
  attributes: Record<string, string>;
  listeners: Record<string, Array<(event?: unknown) => void>>;
  removed: boolean;
  setAttribute(name: string, value: string): void;
  replaceChildren(...children: FakeElement[]): void;
  appendChild(child: FakeElement): FakeElement;
  addEventListener(kind: string, listener: (event?: unknown) => void): void;
  dispatch(kind: string, event?: unknown): void;
  click(): void;
  remove(): void;
}

function fakeElement(tag: string): FakeElement {
  const el: FakeElement = {
    tag,
    children: [],
    textContent: '',
    type: '',
    attributes: {},
    listeners: {},
    removed: false,
    setAttribute(name, value) {
      el.attributes[name] = value;
    },
    replaceChildren(...children) {
      el.children = children;
    },
    appendChild(child) {
      el.children.push(child);
      return child;
    },
    addEventListener(kind, listener) {
      (el.listeners[kind] ??= []).push(listener);
    },
    dispatch(kind, event) {
      for (const listener of el.listeners[kind] ?? []) {
        listener(event);
      }
    },
    click() {
      for (const listener of el.listeners['click'] ?? []) {
        listener();
      }
    },
    remove() {
      el.removed = true;
    },
  };
  return el;
}

const fakeDoc = {
  createElement(tag: string): FakeElement {
    return fakeElement(tag);
  },
};

/** 阿里云 V3 前置全局（window.AliyunCaptchaConfig）的可断言替身视图。 */
const fakeView: { AliyunCaptchaConfig?: { region: string; prefix: string } } =
  {};
const fakeAliyunDoc = {
  createElement(tag: string): FakeElement {
    return fakeElement(tag);
  },
  defaultView: fakeView,
};

/** 等待 adapter 内部异步链（脚本加载 / execute promise / then 回调）排空。 */
async function flush(): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
}

/** 基座错误态结构断言：文案（role=alert）+ 重试按钮（失败处理口径）。 */
function expectErrorState(container: FakeElement): void {
  expect(container.children.length).toBe(2);
  const message = container.children[0];
  const button = container.children[1];
  expect(message.tag).toBe('p');
  expect(message.textContent).toBe(t('common.captchaLoadFailed'));
  expect(message.attributes['role']).toBe('alert');
  expect(button.tag).toBe('button');
  expect(button.textContent).toBe(t('common.retry'));
}

/** 错误态未画（容器空 / 挂载的是厂商元素，首子元素不是错误文案）。 */
function expectErrorStateNotPainted(container: FakeElement): void {
  const first = container.children[0];
  if (first === undefined) {
    return;
  }
  expect(first.tag).not.toBe('p');
}

/** 脚本加载注入替身的公共形态：记录 src；可切换失败。 */
function makeScriptStub(init: { failScript?: boolean } = {}) {
  const scripts: string[] = [];
  let failScript = init.failScript === true;
  return {
    scripts,
    setFailScript: (fail: boolean) => {
      failScript = fail;
    },
    loadScript: async (src: string): Promise<void> => {
      scripts.push(src);
      if (failScript) {
        throw new Error('net down');
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Turnstile（显式渲染：render 回调 token / expired-callback / remove）
// ---------------------------------------------------------------------------

function mountTurnstile(
  siteKey = '0x4AAA',
  init: { failScript?: boolean } = {},
) {
  const script = makeScriptStub(init);
  const renderCalls: Array<{
    container: FakeElement;
    options: TurnstileRenderOptions;
  }> = [];
  const removed: string[] = [];
  let seq = 0;
  const vendor: TurnstileApi = {
    render(container, options) {
      seq += 1;
      renderCalls.push({
        container: container as unknown as FakeElement,
        options,
      });
      return `widget-${seq}`;
    },
    remove(widgetId) {
      removed.push(widgetId);
    },
  };
  const container = fakeElement('div');
  const adapter = createTurnstileAdapter(
    create(CaptchaConfigSchema, {
      providerKey: 'cf_turnstile',
      type: 'turnstile',
      siteKey,
    }),
    {
      document: fakeDoc as unknown as Document,
      loadScript: script.loadScript,
      getVendor: () => vendor,
    },
  );
  adapter.render(container as unknown as HTMLElement);
  return { adapter, container, ...script, renderCalls, removed };
}

describe('Turnstile adapter：挂载 → token 回调 → getToken（§2.5 行 514-522）', () => {
  test('render：动态加载 TURNSTILE_SCRIPT_URL → turnstile.render(container, {sitekey, callback, expired-callback})', async () => {
    const h = mountTurnstile();
    await flush();
    expect(h.scripts).toEqual([TURNSTILE_SCRIPT_URL]);
    expect(h.renderCalls.length).toBe(1);
    expect(h.renderCalls[0].container).toBe(h.container);
    expect(h.renderCalls[0].options.sitekey).toBe('0x4AAA');
    expect(typeof h.renderCalls[0].options.callback).toBe('function');
    expect(typeof h.renderCalls[0].options['expired-callback']).toBe(
      'function',
    );
  });

  test('token 回调 → getToken 返回第三方二元组（id / answer 零值省略）；未完成 → undefined', async () => {
    const h = mountTurnstile();
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();
    h.renderCalls[0].options.callback('tok-1');
    const payload = h.adapter.getToken();
    expect(payload?.$typeName).toBe('api.sso.v1.CaptchaPayload');
    expect(payload?.providerKey).toBe('cf_turnstile');
    expect(payload?.token).toBe('tok-1');
    expect(payload?.id).toBe('');
    expect(payload?.answer).toBe('');
  });

  test('厂商全局对象缺失（脚本 onload 但 window.turnstile 未定义）→ 错误态', async () => {
    const script = makeScriptStub();
    const container = fakeElement('div');
    const adapter = createTurnstileAdapter(
      create(CaptchaConfigSchema, {
        providerKey: 'cf_turnstile',
        type: 'turnstile',
        siteKey: '0x4AAA',
      }),
      {
        document: fakeDoc as unknown as Document,
        loadScript: script.loadScript,
        getVendor: () => undefined,
      },
    );
    adapter.render(container as unknown as HTMLElement);
    await flush();
    expectErrorState(container);
    expect(adapter.getToken()).toBeUndefined();
  });
});

describe('Turnstile adapter：加载失败 / 配置异常 → 可见错误态 + 手动重试', () => {
  test('脚本加载失败 → 错误态 + getToken undefined；点击重试 → 重新加载渲染，token 恢复产出', async () => {
    const h = mountTurnstile('0x4AAA', { failScript: true });
    await flush();
    expect(h.scripts.length).toBe(1);
    expectErrorState(h.container);
    expect(h.adapter.getToken()).toBeUndefined();
    expect(h.renderCalls.length).toBe(0);

    h.setFailScript(false);
    (h.container.children[1] as FakeElement).click(); // 重试 = 重新加载与渲染
    await flush();
    expect(h.scripts.length).toBe(2);
    expect(h.renderCalls.length).toBe(1);
    h.renderCalls[0].options.callback('tok-2');
    expect(h.adapter.getToken()?.token).toBe('tok-2');
  });

  test('siteKey 空串（§2.5 行 501 正常态只应出现在 type=image）→ 错误态，不加载脚本', async () => {
    const h = mountTurnstile('');
    await flush();
    expect(h.scripts.length).toBe(0);
    expectErrorState(h.container);
    expect(h.adapter.getToken()).toBeUndefined();
  });
});

describe('Turnstile adapter：过期换新与 reset（remove + 重新挂载）', () => {
  test('expired-callback → token 清空；remove 旧 widget 后重新挂载换新', async () => {
    const h = mountTurnstile();
    await flush();
    h.renderCalls[0].options.callback('tok-1');
    expect(h.adapter.getToken()?.token).toBe('tok-1');

    h.renderCalls[0].options['expired-callback']();
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();
    expect(h.removed).toEqual(['widget-1']);
    expect(h.renderCalls.length).toBe(2); // 销毁后重新挂载
    h.renderCalls[1].options.callback('tok-2');
    expect(h.adapter.getToken()?.token).toBe('tok-2');
  });

  test('reset：清 token + remove + 重新挂载（§3.5 行 364）', async () => {
    const h = mountTurnstile();
    await flush();
    h.renderCalls[0].options.callback('tok-1');
    h.adapter.reset();
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();
    expect(h.removed).toEqual(['widget-1']);
    expect(h.renderCalls.length).toBe(2);
  });

  test('reset 后旧挑战的迟到回调被丢弃（竞态：会话序号作废）', async () => {
    const h = mountTurnstile();
    await flush();
    h.renderCalls[0].options.callback('tok-1');
    h.adapter.reset();
    await flush();
    h.renderCalls[0].options.callback('stale-tok'); // 旧 epoch 回调
    expect(h.adapter.getToken()).toBeUndefined();
    h.renderCalls[1].options.callback('tok-2');
    expect(h.adapter.getToken()?.token).toBe('tok-2');
  });
});

// ---------------------------------------------------------------------------
// reCAPTCHA v3（?render=SITEKEY 加载；ready → execute → Promise<token>）
// ---------------------------------------------------------------------------

function mountRecaptcha(
  siteKey = '6LeAAA',
  init: { failScript?: boolean } = {},
) {
  const script = makeScriptStub(init);
  const executeCalls: Array<{ siteKey: string; action: string }> = [];
  let readyCalls = 0;
  let responder: ((token: string) => void) | null = null;
  let rejecter: ((err: Error) => void) | null = null;
  const vendor: GrecaptchaApi = {
    ready(callback) {
      readyCalls += 1;
      callback();
    },
    execute(siteKey, options) {
      executeCalls.push({ siteKey, action: options.action });
      return new Promise<string>((resolve, reject) => {
        responder = resolve;
        rejecter = reject;
      });
    },
  };
  const container = fakeElement('div');
  const adapter = createRecaptchaAdapter(
    create(CaptchaConfigSchema, {
      providerKey: 'google_recaptcha',
      type: 'recaptcha',
      siteKey,
    }),
    {
      document: fakeDoc as unknown as Document,
      loadScript: script.loadScript,
      getVendor: () => vendor,
    },
  );
  adapter.render(container as unknown as HTMLElement);
  return {
    adapter,
    container,
    ...script,
    executeCalls,
    readyCalls: () => readyCalls,
    resolveToken: (token: string) => {
      responder?.(token);
    },
    failExecute: () => {
      rejecter?.(new Error('execute failed'));
    },
  };
}

describe('Recaptcha adapter（v3 无感：挂载即预取 token）', () => {
  test('脚本 URL 带 ?render=SITEKEY；ready → execute(siteKey, {action}) → token 二元组', async () => {
    const h = mountRecaptcha();
    await flush();
    expect(h.scripts).toEqual([`${RECAPTCHA_SCRIPT_URL}?render=6LeAAA`]);
    expect(h.readyCalls()).toBe(1);
    expect(h.executeCalls).toEqual([
      { siteKey: '6LeAAA', action: RECAPTCHA_ACTION },
    ]);
    expect(h.adapter.getToken()).toBeUndefined(); // execute 未 resolve
    h.resolveToken('tok-r1');
    await flush();
    const payload = h.adapter.getToken();
    expect(payload?.providerKey).toBe('google_recaptcha');
    expect(payload?.token).toBe('tok-r1');
    expect(payload?.id).toBe('');
    expect(payload?.answer).toBe('');
  });

  test('siteKey 编码进 render 参数（特殊字符安全）', async () => {
    const h = mountRecaptcha('6Le AAA&x');
    await flush();
    expect(h.scripts).toEqual([
      `${RECAPTCHA_SCRIPT_URL}?render=${encodeURIComponent('6Le AAA&x')}`,
    ]);
  });

  test('execute reject → 错误态；点击重试 → 重新 execute，token 恢复产出', async () => {
    const h = mountRecaptcha();
    await flush();
    h.failExecute();
    await flush();
    expectErrorState(h.container);
    expect(h.adapter.getToken()).toBeUndefined();

    (h.container.children[1] as FakeElement).click();
    await flush();
    expect(h.executeCalls.length).toBe(2);
    h.resolveToken('tok-r2');
    await flush();
    expect(h.adapter.getToken()?.token).toBe('tok-r2');
  });

  test('reset → 重新 execute 换新 token（v3 token 短效，无过期回调）', async () => {
    const h = mountRecaptcha();
    await flush();
    h.resolveToken('tok-r1');
    await flush();
    h.adapter.reset();
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();
    expect(h.executeCalls.length).toBe(2);
    h.resolveToken('tok-r2');
    await flush();
    expect(h.adapter.getToken()?.token).toBe('tok-r2');
  });

  test('脚本加载失败 → 错误态，不 execute', async () => {
    const h = mountRecaptcha('6LeAAA', { failScript: true });
    await flush();
    expectErrorState(h.container);
    expect(h.executeCalls.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// hCaptcha（显式渲染：render 回调 token / expired-callback / 原地 reset）
// ---------------------------------------------------------------------------

function mountHCaptcha(
  siteKey = '1000-aaaa',
  init: { failScript?: boolean } = {},
) {
  const script = makeScriptStub(init);
  const renderCalls: Array<{
    container: FakeElement;
    options: HCaptchaRenderOptions;
  }> = [];
  const resetCalls: string[] = [];
  let seq = 0;
  const vendor: HCaptchaApi = {
    render(container, options) {
      seq += 1;
      renderCalls.push({
        container: container as unknown as FakeElement,
        options,
      });
      return `widget-${seq}`;
    },
    reset(widgetId) {
      resetCalls.push(widgetId ?? '');
    },
  };
  const container = fakeElement('div');
  const adapter = createHCaptchaAdapter(
    create(CaptchaConfigSchema, {
      providerKey: 'hcaptcha',
      type: 'hcaptcha',
      siteKey,
    }),
    {
      document: fakeDoc as unknown as Document,
      loadScript: script.loadScript,
      getVendor: () => vendor,
    },
  );
  adapter.render(container as unknown as HTMLElement);
  return { adapter, container, ...script, renderCalls, resetCalls };
}

describe('HCaptcha adapter：挂载 → token 回调 → getToken', () => {
  test('render：动态加载 HCAPTCHA_SCRIPT_URL → hcaptcha.render(container, {sitekey, callback, expired-callback})', async () => {
    const h = mountHCaptcha();
    await flush();
    expect(h.scripts).toEqual([HCAPTCHA_SCRIPT_URL]);
    expect(h.renderCalls.length).toBe(1);
    expect(h.renderCalls[0].container).toBe(h.container);
    expect(h.renderCalls[0].options.sitekey).toBe('1000-aaaa');
    expect(typeof h.renderCalls[0].options.callback).toBe('function');
    expect(typeof h.renderCalls[0].options['expired-callback']).toBe(
      'function',
    );
  });

  test('token 回调 → getToken 返回第三方二元组；未完成 → undefined', async () => {
    const h = mountHCaptcha();
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();
    h.renderCalls[0].options.callback('tok-h1');
    const payload = h.adapter.getToken();
    expect(payload?.$typeName).toBe('api.sso.v1.CaptchaPayload');
    expect(payload?.providerKey).toBe('hcaptcha');
    expect(payload?.token).toBe('tok-h1');
    expect(payload?.id).toBe('');
    expect(payload?.answer).toBe('');
  });
});

describe('HCaptcha adapter：过期 / reset（原地 vendor.reset，不重复挂载）', () => {
  test('expired-callback → token 清空 + vendor.reset(widgetId)；重新完成后新 token', async () => {
    const h = mountHCaptcha();
    await flush();
    h.renderCalls[0].options.callback('tok-h1');
    expect(h.adapter.getToken()?.token).toBe('tok-h1');

    h.renderCalls[0].options['expired-callback']();
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();
    expect(h.resetCalls).toEqual(['widget-1']);
    expect(h.renderCalls.length).toBe(1); // 原地重置，不重新挂载

    h.renderCalls[0].options.callback('tok-h2'); // reset 后重新完成 → 再回调
    expect(h.adapter.getToken()?.token).toBe('tok-h2');
  });

  test('reset：清 token + 原地 vendor.reset（连续 reset 不重复挂载）', async () => {
    const h = mountHCaptcha();
    await flush();
    h.renderCalls[0].options.callback('tok-h1');
    h.adapter.reset();
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();
    expect(h.resetCalls).toEqual(['widget-1']);
    h.adapter.reset();
    await flush();
    expect(h.resetCalls).toEqual(['widget-1', 'widget-1']);
    expect(h.renderCalls.length).toBe(1);
  });

  test('脚本加载失败 → 错误态 + 重试恢复挂载', async () => {
    const h = mountHCaptcha('1000-aaaa', { failScript: true });
    await flush();
    expectErrorState(h.container);
    expect(h.renderCalls.length).toBe(0);

    h.setFailScript(false);
    (h.container.children[1] as FakeElement).click();
    await flush();
    expect(h.scripts.length).toBe(2);
    expect(h.renderCalls.length).toBe(1);
    h.renderCalls[0].options.callback('tok-h2');
    expect(h.adapter.getToken()?.token).toBe('tok-h2');
  });

  test('siteKey 空串 → 错误态，不加载脚本', async () => {
    const h = mountHCaptcha('');
    await flush();
    expect(h.scripts.length).toBe(0);
    expectErrorState(h.container);
    expect(h.adapter.getToken()).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// GeeTest v4（gt4.js；initGeetest4 → appendTo → onSuccess 后 getValidate，
// 四字段整体 JSON 打包进 token，§2.5 行 690）
// ---------------------------------------------------------------------------

const VALIDATE_FIXTURE: GeetestValidate = {
  lot_number: 'lot-1',
  captcha_output: 'out-1',
  pass_token: 'pass-1',
  gen_time: '1735000000',
};

function mountGeetest(
  siteKey = 'gt-4fA2',
  init: { failScript?: boolean; product?: string } = {},
) {
  const script = makeScriptStub(init);
  const initCalls: Array<{ config: GeetestInitConfig }> = [];
  const appendedTo: FakeElement[] = [];
  const destroyed: number[] = [];
  const successCbs: Array<() => void> = [];
  const errorCbs: Array<() => void> = [];
  let validateResult: GeetestValidate | false = false;
  const captchaObj: GeetestCaptchaObj = {
    appendTo(container) {
      appendedTo.push(container as unknown as FakeElement);
    },
    onSuccess(cb) {
      successCbs.push(cb);
    },
    onError(cb) {
      errorCbs.push(cb);
    },
    getValidate() {
      return validateResult;
    },
    destroy() {
      destroyed.push(1);
    },
  };
  const vendor: GeetestApi = {
    initGeetest4(config, callback) {
      initCalls.push({ config });
      callback(captchaObj);
    },
  };
  const container = fakeElement('div');
  const adapter = createGeetestAdapter(
    create(CaptchaConfigSchema, {
      providerKey: 'geetest_v4',
      type: 'geetest_v4',
      siteKey,
    }),
    {
      document: fakeDoc as unknown as Document,
      loadScript: script.loadScript,
      getVendor: () => vendor,
      product: init.product,
    },
  );
  adapter.render(container as unknown as HTMLElement);
  return {
    adapter,
    container,
    ...script,
    initCalls,
    appendedTo,
    destroyed,
    successAt: (index: number) => successCbs[index]?.(),
    errorAt: (index: number) => errorCbs[index]?.(),
    setValidate: (value: GeetestValidate | false) => {
      validateResult = value;
    },
  };
}

describe('Geetest adapter：挂载 → onSuccess → getValidate 四字段打包（§2.5 行 690）', () => {
  test('render：动态加载 GEETEST_SCRIPT_URL → initGeetest4({captchaId, product: popup}) → appendTo 容器 + 回调注册', async () => {
    const h = mountGeetest();
    await flush();
    expect(h.scripts).toEqual([GEETEST_SCRIPT_URL]);
    expect(h.initCalls.length).toBe(1);
    expect(h.initCalls[0].config).toEqual({
      captchaId: 'gt-4fA2',
      product: 'popup',
    });
    expect(h.appendedTo).toEqual([h.container]);
  });

  test('product 可经 options 覆盖；缺省 popup', async () => {
    const h = mountGeetest('gt-4fA2', { product: 'float' });
    await flush();
    expect(h.initCalls[0].config.product).toBe('float');
  });

  test('onSuccess 后 getValidate → 四字段整体 JSON 序列化进 token；未完成 → undefined', async () => {
    const h = mountGeetest();
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();

    h.setValidate(VALIDATE_FIXTURE);
    h.successAt(0);
    const payload = h.adapter.getToken();
    expect(payload?.$typeName).toBe('api.sso.v1.CaptchaPayload');
    expect(payload?.providerKey).toBe('geetest_v4');
    expect(JSON.parse(payload?.token ?? '{}')).toEqual(VALIDATE_FIXTURE);
    expect(payload?.id).toBe('');
    expect(payload?.answer).toBe('');
  });

  test('getValidate 返回 false（未完成 / 失败）→ 不提交，getToken undefined', async () => {
    const h = mountGeetest();
    await flush();
    h.setValidate(false);
    h.successAt(0);
    expect(h.adapter.getToken()).toBeUndefined();
    expectErrorStateNotPainted(h.container);
  });

  test('onError → 错误态 + token undefined', async () => {
    const h = mountGeetest();
    await flush();
    h.setValidate(VALIDATE_FIXTURE);
    h.successAt(0);
    expect(h.adapter.getToken()?.token).toBeTruthy();
    h.errorAt(0);
    expectErrorState(h.container);
    expect(h.adapter.getToken()).toBeUndefined();
  });
});

describe('Geetest adapter：加载失败 / 配置异常 → 可见错误态 + 手动重试', () => {
  test('脚本加载失败 → 错误态；重试 → 重新 initGeetest4，token 恢复产出', async () => {
    const h = mountGeetest('gt-4fA2', { failScript: true });
    await flush();
    expect(h.scripts.length).toBe(1);
    expect(h.initCalls.length).toBe(0);
    expectErrorState(h.container);

    h.setFailScript(false);
    (h.container.children[1] as FakeElement).click();
    await flush();
    expect(h.scripts.length).toBe(2);
    expect(h.initCalls.length).toBe(1);
    h.setValidate(VALIDATE_FIXTURE);
    h.successAt(0);
    expect(h.adapter.getToken()?.providerKey).toBe('geetest_v4');
  });

  test('initGeetest4 同步抛错 → 错误态', async () => {
    const script = makeScriptStub();
    const container = fakeElement('div');
    const vendor: GeetestApi = {
      initGeetest4() {
        throw new Error('init exploded');
      },
    };
    const adapter = createGeetestAdapter(
      create(CaptchaConfigSchema, {
        providerKey: 'geetest_v4',
        type: 'geetest_v4',
        siteKey: 'gt-4fA2',
      }),
      {
        document: fakeDoc as unknown as Document,
        loadScript: script.loadScript,
        getVendor: () => vendor,
      },
    );
    adapter.render(container as unknown as HTMLElement);
    await flush();
    expectErrorState(container);
    expect(adapter.getToken()).toBeUndefined();
  });

  test('siteKey 空串 → 错误态，不加载脚本', async () => {
    const h = mountGeetest('');
    await flush();
    expect(h.scripts.length).toBe(0);
    expectErrorState(h.container);
    expect(h.adapter.getToken()).toBeUndefined();
  });
});

describe('Geetest adapter：重置与竞态（destroy + 重新 init，旧回调作废）', () => {
  test('reset → destroy 旧 captchaObj + 重新 init；旧会话 onSuccess 迟到回调被丢弃', async () => {
    const h = mountGeetest();
    await flush();
    h.setValidate(VALIDATE_FIXTURE);
    h.successAt(0);
    expect(h.adapter.getToken()?.token).toBeTruthy();

    h.adapter.reset();
    await flush();
    expect(h.destroyed.length).toBe(1);
    expect(h.initCalls.length).toBe(2);
    expect(h.adapter.getToken()).toBeUndefined();

    h.successAt(0); // 旧 epoch 迟到回调
    expect(h.adapter.getToken()).toBeUndefined();
    h.successAt(1); // 新会话回调
    expect(JSON.parse(h.adapter.getToken()?.token ?? '{}')).toEqual(
      VALIDATE_FIXTURE,
    );
  });
});

// ---------------------------------------------------------------------------
// 阿里云验证码 2.0（AliyunCaptcha.js；AliyunCaptchaConfig 前置 → popup 模式
// initAliyunCaptcha → success 回调 captchaVerifyParam 原样透传，§2.5 行 691）
// ---------------------------------------------------------------------------

function mountAliyun(
  siteKey = 'scene-1',
  init: { failScript?: boolean; region?: string; prefix?: string } = {},
) {
  // V3 前置全局每次挂载前归零，断言「init 前就位」。
  fakeView.AliyunCaptchaConfig = undefined;
  const script = makeScriptStub(init);
  const initCalls: Array<{ config: AliyunCaptchaInitConfig }> = [];
  const destroyed: number[] = [];
  const successFns: Array<(param: string) => void> = [];
  const failFns: Array<(result: unknown) => void> = [];
  const vendor: AliyunCaptchaApi = {
    initAliyunCaptcha(config) {
      initCalls.push({ config });
      successFns.push(config.success);
      failFns.push(config.fail);
      const instance: AliyunCaptchaInstance = {
        destroy: () => {
          destroyed.push(1);
        },
      };
      config.getInstance(instance);
    },
  };
  const container = fakeElement('div');
  const adapter = createAliyunCaptchaAdapter(
    create(CaptchaConfigSchema, {
      providerKey: 'aliyun_captcha',
      type: 'aliyun_captcha',
      siteKey,
    }),
    {
      document: fakeAliyunDoc as unknown as Document,
      loadScript: script.loadScript,
      getVendor: () => vendor,
      region: init.region,
      prefix: init.prefix,
    },
  );
  adapter.render(container as unknown as HTMLElement);
  return {
    adapter,
    container,
    ...script,
    initCalls,
    destroyed,
    successAt: (index: number, param: string) => successFns[index]?.(param),
    failAt: (index: number) => failFns[index]?.({}),
  };
}

describe('AliyunCaptcha adapter：AliyunCaptchaConfig 前置 → popup 挂载（review §2.2）', () => {
  test('render：动态加载 ALIYUN_CAPTCHA_SCRIPT_URL → 前置全局 cn/空 prefix → initAliyunCaptcha({SceneId, mode popup, element/button 选择器})', async () => {
    const h = mountAliyun();
    await flush();
    expect(h.scripts).toEqual([ALIYUN_CAPTCHA_SCRIPT_URL]);
    expect(fakeView.AliyunCaptchaConfig).toEqual({ region: 'cn', prefix: '' });
    expect(h.initCalls.length).toBe(1);
    const config = h.initCalls[0].config;
    expect(config.SceneId).toBe('scene-1');
    expect(config.mode).toBe('popup');
    // 自建触发按钮 + 弹层挂载点：选择器与容器内元素的 id 一一对应。
    const trigger = h.container.children[0] as FakeElement;
    const element = h.container.children[1] as FakeElement;
    expect(config.button).toBe(`#${trigger.attributes['id']}`);
    expect(config.element).toBe(`#${element.attributes['id']}`);
    expect(trigger.tag).toBe('button');
    expect(trigger.textContent).toBe(t('common.captchaConfirm'));
    expect(element.tag).toBe('div');
  });

  test('region / prefix 可经 options 覆盖，全局前置同步', async () => {
    const h = mountAliyun('scene-1', { region: 'sgp', prefix: 'pre9' });
    await flush();
    expect(fakeView.AliyunCaptchaConfig).toEqual({
      region: 'sgp',
      prefix: 'pre9',
    });
  });

  test('success 回调 captchaVerifyParam 原样进 token（不解析 / 重组 / 修改）；未完成 → undefined', async () => {
    const h = mountAliyun();
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();

    const rawParam =
      '{"sceneId":"s","certifyId":"c","deviceToken":  null,"data":"d|x"}';
    h.successAt(0, rawParam);
    const payload = h.adapter.getToken();
    expect(payload?.$typeName).toBe('api.sso.v1.CaptchaPayload');
    expect(payload?.providerKey).toBe('aliyun_captcha');
    expect(payload?.token).toBe(rawParam);
    expect(payload?.id).toBe('');
    expect(payload?.answer).toBe('');
  });

  test('fail 回调（验证未通过）→ 无凭据产出，不画错误态', async () => {
    const h = mountAliyun();
    await flush();
    h.failAt(0);
    expect(h.adapter.getToken()).toBeUndefined();
    expectErrorStateNotPainted(h.container);
  });
});

describe('AliyunCaptcha adapter：加载失败 / 配置异常 → 可见错误态 + 手动重试', () => {
  test('脚本加载失败 → 错误态；重试 → 重新 init，token 恢复产出', async () => {
    const h = mountAliyun('scene-1', { failScript: true });
    await flush();
    expect(h.scripts.length).toBe(1);
    expect(h.initCalls.length).toBe(0);
    expectErrorState(h.container);

    h.setFailScript(false);
    (h.container.children[1] as FakeElement).click();
    await flush();
    expect(h.scripts.length).toBe(2);
    expect(h.initCalls.length).toBe(1);
    h.successAt(0, 'param-2');
    expect(h.adapter.getToken()?.token).toBe('param-2');
  });

  test('initAliyunCaptcha 同步抛错 → 错误态', async () => {
    const script = makeScriptStub();
    const container = fakeElement('div');
    const vendor: AliyunCaptchaApi = {
      initAliyunCaptcha() {
        throw new Error('init exploded');
      },
    };
    const adapter = createAliyunCaptchaAdapter(
      create(CaptchaConfigSchema, {
        providerKey: 'aliyun_captcha',
        type: 'aliyun_captcha',
        siteKey: 'scene-1',
      }),
      {
        document: fakeAliyunDoc as unknown as Document,
        loadScript: script.loadScript,
        getVendor: () => vendor,
      },
    );
    adapter.render(container as unknown as HTMLElement);
    await flush();
    expectErrorState(container);
    expect(adapter.getToken()).toBeUndefined();
  });

  test('siteKey 空串 → 错误态，不加载脚本', async () => {
    const h = mountAliyun('');
    await flush();
    expect(h.scripts.length).toBe(0);
    expectErrorState(h.container);
    expect(h.adapter.getToken()).toBeUndefined();
  });
});

describe('AliyunCaptcha adapter：重置与竞态（destroy 实例 + 重新 init，旧回调作废）', () => {
  test('reset → destroy 旧实例 + 重新 init；旧会话 success 迟到回调被丢弃', async () => {
    const h = mountAliyun();
    await flush();
    h.successAt(0, 'param-1');
    expect(h.adapter.getToken()?.token).toBe('param-1');

    h.adapter.reset();
    await flush();
    expect(h.destroyed.length).toBe(1);
    expect(h.initCalls.length).toBe(2);
    expect(h.adapter.getToken()).toBeUndefined();

    h.successAt(0, 'stale-param'); // 旧 epoch 迟到回调
    expect(h.adapter.getToken()).toBeUndefined();
    h.successAt(1, 'param-2');
    expect(h.adapter.getToken()?.token).toBe('param-2');
  });
});

// ---------------------------------------------------------------------------
// Capjs（@cap.js/widget；customElements 注册 <cap-widget> → data-cap-api-endpoint
// → solve 事件 e.detail.token 原文，§2.5 行 689）
// ---------------------------------------------------------------------------

function mountCap(
  siteKey = 'cap-site-1',
  init: { failScript?: boolean; apiEndpoint?: string } = {},
) {
  const script = makeScriptStub(init);
  const vendor = function capWidgetCtor() {} as unknown as CapVendorApi;
  const container = fakeElement('div');
  const adapter = createCapAdapter(
    create(CaptchaConfigSchema, {
      providerKey: 'capjs',
      type: 'capjs',
      siteKey,
    }),
    {
      document: fakeDoc as unknown as Document,
      loadScript: script.loadScript,
      getVendor: () => vendor,
      apiEndpoint: init.apiEndpoint,
    },
  );
  adapter.render(container as unknown as HTMLElement);
  return {
    adapter,
    container,
    ...script,
    widget: () => container.children[0] as FakeElement,
    solve: (token: string) => {
      (container.children[0] as FakeElement).dispatch('solve', {
        detail: { token },
      });
    },
  };
}

describe('Cap adapter：挂载 → data-cap-api-endpoint → solve 事件 token 原文（§2.5 行 689）', () => {
  test('render：动态加载 CAP_SCRIPT_URL → siteKey 为绝对 URL 视为配置透出的组合端点 → 建 cap-widget 挂进容器', async () => {
    const h = mountCap('https://cap.example.com/cap-site-1/');
    await flush();
    expect(h.scripts).toEqual([CAP_SCRIPT_URL]);
    const widget = h.widget();
    expect(widget.tag).toBe('cap-widget');
    expect(widget.attributes['data-cap-api-endpoint']).toBe(
      'https://cap.example.com/cap-site-1/',
    );
    expect(h.container.children[0]).toBe(widget);
  });

  test('options.apiEndpoint 优先于 siteKey 组合端点形态', async () => {
    const h = mountCap('cap-site-1', { apiEndpoint: 'https://self.host/k/' });
    await flush();
    expect(h.widget().attributes['data-cap-api-endpoint']).toBe(
      'https://self.host/k/',
    );
  });

  test('siteKey 非 URL 且无 options → 配置残缺错误态（不打演示服务），脚本已加载但不挂 widget', async () => {
    const h = mountCap('cap-site-1');
    await flush();
    expect(h.scripts.length).toBe(1);
    expectErrorState(h.container);
    expect(h.adapter.getToken()).toBeUndefined();
  });

  test('solve 事件 e.detail.token 原文进 token；未完成 / 空 token → undefined', async () => {
    const h = mountCap('https://cap.example.com/k/');
    await flush();
    expect(h.adapter.getToken()).toBeUndefined();

    h.solve('cap-tok-1');
    const payload = h.adapter.getToken();
    expect(payload?.$typeName).toBe('api.sso.v1.CaptchaPayload');
    expect(payload?.providerKey).toBe('capjs');
    expect(payload?.token).toBe('cap-tok-1');
    expect(payload?.id).toBe('');
    expect(payload?.answer).toBe('');

    h.solve('');
    expect(h.adapter.getToken()?.token).toBe('cap-tok-1'); // 空 token 不覆写
  });
});

describe('Cap adapter：加载失败 / 元素未注册 → 可见错误态 + 手动重试', () => {
  test('脚本加载失败 → 错误态；重试 → 重新挂载，token 恢复产出', async () => {
    const h = mountCap('https://cap.example.com/k/', { failScript: true });
    await flush();
    expect(h.scripts.length).toBe(1);
    expectErrorState(h.container);

    h.setFailScript(false);
    (h.container.children[1] as FakeElement).click();
    await flush();
    expect(h.scripts.length).toBe(2);
    expect(h.widget().tag).toBe('cap-widget');
    h.solve('cap-tok-2');
    expect(h.adapter.getToken()?.token).toBe('cap-tok-2');
  });

  test('脚本加载但 customElements 未注册（getVendor undefined）→ 错误态', async () => {
    const script = makeScriptStub();
    const container = fakeElement('div');
    const adapter = createCapAdapter(
      create(CaptchaConfigSchema, {
        providerKey: 'capjs',
        type: 'capjs',
        siteKey: 'https://cap.example.com/k/',
      }),
      {
        document: fakeDoc as unknown as Document,
        loadScript: script.loadScript,
        getVendor: () => undefined,
      },
    );
    adapter.render(container as unknown as HTMLElement);
    await flush();
    expectErrorState(container);
    expect(adapter.getToken()).toBeUndefined();
  });

  test('siteKey 空串 → 错误态，不加载脚本', async () => {
    const h = mountCap('');
    await flush();
    expect(h.scripts.length).toBe(0);
    expectErrorState(h.container);
    expect(h.adapter.getToken()).toBeUndefined();
  });
});

describe('Cap adapter：重置与竞态（移除旧 widget + 重新挂载，旧回调作废）', () => {
  test('reset → 旧 widget remove + 新 widget 挂载；旧会话 solve 迟到事件被丢弃', async () => {
    const h = mountCap('https://cap.example.com/k/');
    await flush();
    const oldWidget = h.widget();
    h.solve('cap-tok-1');
    expect(h.adapter.getToken()?.token).toBe('cap-tok-1');

    h.adapter.reset();
    await flush();
    expect(oldWidget.removed).toBe(true);
    expect(h.widget()).not.toBe(oldWidget);
    expect(h.adapter.getToken()).toBeUndefined();

    // 旧 widget 元素上的 solve 事件（旧 epoch）不作数。
    oldWidget.dispatch('solve', { detail: { token: 'stale' } });
    expect(h.adapter.getToken()).toBeUndefined();
    h.solve('cap-tok-2');
    expect(h.adapter.getToken()?.token).toBe('cap-tok-2');
  });
});
