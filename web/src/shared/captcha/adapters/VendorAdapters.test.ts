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
  listeners: Record<string, Array<() => void>>;
  setAttribute(name: string, value: string): void;
  replaceChildren(...children: FakeElement[]): void;
  addEventListener(kind: string, listener: () => void): void;
  click(): void;
}

function fakeElement(tag: string): FakeElement {
  const el: FakeElement = {
    tag,
    children: [],
    textContent: '',
    type: '',
    attributes: {},
    listeners: {},
    setAttribute(name, value) {
      el.attributes[name] = value;
    },
    replaceChildren(...children) {
      el.children = children;
    },
    addEventListener(kind, listener) {
      (el.listeners[kind] ??= []).push(listener);
    },
    click() {
      for (const listener of el.listeners['click'] ?? []) {
        listener();
      }
    },
  };
  return el;
}

const fakeDoc = {
  createElement(tag: string): FakeElement {
    return fakeElement(tag);
  },
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
