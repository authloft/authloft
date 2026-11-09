// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { create } from '@bufbuild/protobuf';
import { CaptchaConfigSchema } from '../../../gen/proto/api/common/v1/captcha_pb';
import {
  CreateCaptchaImageResponseSchema,
  type CreateCaptchaImageResponse,
} from '../../../gen/proto/api/sso/v1/login_pb';
import { t } from '../../i18n';
import {
  IMAGE_FETCH_MAX_FAILURES,
  createImageAdapter,
  type ImageAdapterOptions,
} from './Image';

// ---------------------------------------------------------------------------
// node 无 DOM：注入替身（adapter 的 document / fetchImage 均可注入，见
// Image.tsx 头注释）；桩只实现 adapter 用到的 DOM 子集。
// ---------------------------------------------------------------------------

interface FakeElement {
  tag: string;
  children: FakeElement[];
  textContent: string;
  value: string;
  src: string;
  alt: string;
  type: string;
  autocomplete: string;
  attributes: Record<string, string>;
  listeners: Record<string, Array<() => void>>;
  setAttribute(name: string, value: string): void;
  appendChild(child: FakeElement): FakeElement;
  replaceChildren(...children: FakeElement[]): void;
  addEventListener(kind: string, listener: () => void): void;
  click(): void;
}

function fakeElement(tag: string): FakeElement {
  const el: FakeElement = {
    tag,
    children: [],
    textContent: '',
    value: '',
    src: '',
    alt: '',
    type: '',
    autocomplete: '',
    attributes: {},
    listeners: {},
    setAttribute(name, value) {
      el.attributes[name] = value;
    },
    appendChild(child) {
      el.children.push(child);
      return child;
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

/** 生成物消息构造：CreateCaptchaImage 成功响应（§2.5 行 495 的字段）。 */
function imageOk(
  id: string,
  imageBase64 = 'iVBORw0KGgo',
): CreateCaptchaImageResponse {
  return create(CreateCaptchaImageResponseSchema, {
    id,
    imageBase64,
    expiresIn: BigInt(300),
  });
}

interface AdapterHandle {
  adapter: ReturnType<typeof createImageAdapter>;
  container: FakeElement;
  input(): FakeElement;
  img(): FakeElement;
}

/** 建造 + 挂载：builtin_image（§2.5 行 484 降级口径）下渲染进桩容器。 */
function mountAdapter(
  fetchImage: ImageAdapterOptions['fetchImage'],
): AdapterHandle {
  const container = fakeElement('div');
  const adapter = createImageAdapter(
    create(CaptchaConfigSchema, {
      providerKey: 'builtin_image',
      type: 'image',
    }),
    { fetchImage, document: fakeDoc as unknown as Document },
  );
  adapter.render(container as unknown as HTMLElement);
  return {
    adapter,
    container,
    input: () => container.children[1] as FakeElement,
    img: () => container.children[0] as FakeElement,
  };
}

/** 等待 adapter 内部异步链（取图 / 自动换新递归）排空。 */
async function flush(): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
}

describe('Image adapter 生命周期：取图 → 作答 → getToken', () => {
  test('render 取图成功：img data-URI 直渲 + 作答输入框（§2.5 行 497-498，不二次请求图片）', async () => {
    let calls = 0;
    const { container, img, input } = mountAdapter(async () => {
      calls += 1;
      return imageOk('cap-1', 'QUJD');
    });
    await flush();
    expect(calls).toBe(1);
    expect(container.children.length).toBe(2);
    expect(img().tag).toBe('img');
    expect(img().src).toBe('data:image/png;base64,QUJD');
    expect(img().alt).toBe('captcha');
    expect(input().tag).toBe('input');
    expect(input().type).toBe('text');
    expect(input().autocomplete).toBe('off');
  });

  test('作答后 getToken 返回提交三元组（providerKey + id + answer；token 零值 → 序列化省略）', async () => {
    const { adapter, input } = mountAdapter(async () => imageOk('cap-1'));
    await flush();
    input().value = '123';
    const payload = adapter.getToken();
    expect(payload).toBeDefined();
    expect(payload?.$typeName).toBe('api.sso.v1.CaptchaPayload');
    expect(payload?.providerKey).toBe('builtin_image');
    expect(payload?.id).toBe('cap-1');
    expect(payload?.answer).toBe('123');
    expect(payload?.token).toBe('');
  });

  test('未作答 / 未渲染 → getToken undefined（调用方不带 captcha 提交）', async () => {
    const { adapter, input } = mountAdapter(async () => imageOk('cap-9'));
    await flush();
    input().value = '';
    expect(adapter.getToken()).toBeUndefined();

    const notRendered = createImageAdapter(
      create(CaptchaConfigSchema, { providerKey: 'p', type: 'image' }),
      {
        fetchImage: async () => imageOk('x'),
        document: fakeDoc as unknown as Document,
      },
    );
    expect(notRendered.getToken()).toBeUndefined();
  });
});

describe('Image adapter reset 重拉（§3.5 行 364）', () => {
  test('reset：清空作答、重拉新图（新 id 顶替旧的）', async () => {
    let calls = 0;
    let version = 0;
    const ids = ['cap-1', 'cap-2'];
    const { adapter, container, input } = mountAdapter(async () => {
      calls += 1;
      return imageOk(ids[Math.min(version, ids.length - 1)]);
    });
    await flush();
    const firstInput = input();
    firstInput.value = '123';
    expect(adapter.getToken()?.id).toBe('cap-1');

    version = 1;
    adapter.reset();
    await flush();

    expect(calls).toBe(2); // 取图第二次被调
    expect(container.children[1]).not.toBe(firstInput); // DOM 重建，旧作答不残留
    expect(input().value).toBe('');
    input().value = '456';
    const payload = adapter.getToken();
    expect(payload?.id).toBe('cap-2');
    expect(payload?.answer).toBe('456');
  });
});

describe('Image adapter 失败自动换新（不死循环）', () => {
  test('失败后自动重拉，成功即恢复（换新图）', async () => {
    let n = 0;
    const { img } = mountAdapter(async () => {
      n += 1;
      if (n < 3) {
        throw new Error('boom');
      }
      return imageOk('cap-ok');
    });
    await flush();
    expect(n).toBe(3);
    expect(img().tag).toBe('img');
  });

  test('连续失败达上限：停止自动重拉，转手动重试态；点击重试重新进入循环', async () => {
    let calls = 0;
    const { container } = mountAdapter(async () => {
      calls += 1;
      throw new Error('boom');
    });
    await flush();
    expect(calls).toBe(IMAGE_FETCH_MAX_FAILURES);
    expect(container.children.length).toBe(2);
    const message = container.children[0];
    const button = container.children[1];
    expect(message.tag).toBe('p');
    expect(message.textContent).toBe(t('errors.status.unknown'));
    expect(message.attributes['role']).toBe('alert');
    expect(button.tag).toBe('button');
    expect(button.textContent).toBe(t('common.retry'));

    // 手动重试 → failures 清零，重新进入自动换新（再拉满一轮上限后仍停）
    button.click();
    await flush();
    expect(calls).toBe(IMAGE_FETCH_MAX_FAILURES * 2);
    expect((container.children[1] as FakeElement).textContent).toBe(
      t('common.retry'),
    );
  });

  test('reset 期间的过期取图结果被丢弃（竞态：新会话不被旧结果覆盖）', async () => {
    const pending: Array<(r: CreateCaptchaImageResponse) => void> = [];
    const container = fakeElement('div');
    const adapter = createImageAdapter(
      create(CaptchaConfigSchema, { providerKey: 'p', type: 'image' }),
      {
        fetchImage: () =>
          new Promise((resolve) => {
            pending.push(resolve);
          }),
        document: fakeDoc as unknown as Document,
      },
    );
    adapter.render(container as unknown as HTMLElement); // 取图 A 发出
    adapter.reset(); // 取图 B 发出，A 的结果应作废
    pending[1](imageOk('cap-B'));
    await flush();
    pending[0](imageOk('cap-A')); // A 后完成：必须丢弃
    await flush();
    const input = container.children[1] as FakeElement;
    input.value = '789';
    const payload = adapter.getToken();
    expect(payload?.id).toBe('cap-B');
    expect(payload?.answer).toBe('789');
  });
});
