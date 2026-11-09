// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（既定裁决，tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { VENDOR_SCRIPT_TIMEOUT_MS, loadVendorScript } from './loadVendorScript';

// ---------------------------------------------------------------------------
// node 无 DOM：注入 document 桩（沿 Image.test.ts 替身注入惯例），桩只实现
// 加载器用到的 DOM 子集（createElement('script') + head.appendChild）。
// 加载器的去重缓存是模块级的——各用例用互不相同的 src 避免串扰。
// ---------------------------------------------------------------------------

interface FakeScript {
  tag: string;
  src: string;
  async: boolean;
  onload: (() => void) | null;
  onerror: (() => void) | null;
  removed: boolean;
  remove(): void;
}

function makeDoc() {
  const appended: FakeScript[] = [];
  const doc = {
    createElement(tag: string): FakeScript {
      const script: FakeScript = {
        tag,
        src: '',
        async: false,
        onload: null,
        onerror: null,
        removed: false,
        remove(): void {
          script.removed = true;
        },
      };
      return script;
    },
    head: {
      appendChild(child: FakeScript): FakeScript {
        appended.push(child);
        return child;
      },
    },
  };
  return { doc, appended };
}

/** 等待加载器内部清缓存的微任务（reject 后的 catch 链）排空。 */
async function flush(): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
}

describe('loadVendorScript 动态加载（不打包、不写死 script 标签）', () => {
  test('运行期 createElement(script) + head.appendChild + async；onload → resolve', async () => {
    const { doc, appended } = makeDoc();
    const p = loadVendorScript('https://t.example/1.js', {
      document: doc as unknown as Document,
    });
    expect(appended.length).toBe(1);
    expect(appended[0].tag).toBe('script');
    expect(appended[0].src).toBe('https://t.example/1.js');
    expect(appended[0].async).toBe(true);
    appended[0].onload?.();
    await p;
  });

  test('幂等：同 src 并发共享一次注入；成功后重复调用不重新注入', async () => {
    const { doc, appended } = makeDoc();
    const options = { document: doc as unknown as Document };
    const p1 = loadVendorScript('https://t.example/2.js', options);
    const p2 = loadVendorScript('https://t.example/2.js', options);
    expect(appended.length).toBe(1); // 并发去重
    appended[0].onload?.();
    await p1;
    await p2;
    await loadVendorScript('https://t.example/2.js', options); // 已成功 → 直通
    expect(appended.length).toBe(1);
  });

  test('onerror → reject（load failed）+ 标签移除；失败清缓存，重试重新注入', async () => {
    const { doc, appended } = makeDoc();
    const options = { document: doc as unknown as Document };
    const p1 = loadVendorScript('https://t.example/3.js', options);
    appended[0].onerror?.();
    await expect(p1).rejects.toThrow('vendor script load failed');
    expect(appended[0].removed).toBe(true);
    await flush();

    const p2 = loadVendorScript('https://t.example/3.js', options);
    expect(appended.length).toBe(2); // 失败后重试 → 重新注入
    appended[1].onload?.();
    await p2;
  });

  test('超时 → reject（timeout）+ 标签移除；重试重新注入', async () => {
    const { doc, appended } = makeDoc();
    const p1 = loadVendorScript('https://t.example/4.js', {
      document: doc as unknown as Document,
      timeoutMs: 10,
    });
    await new Promise((resolve) => {
      setTimeout(resolve, 25);
    });
    await expect(p1).rejects.toThrow('vendor script load timeout');
    expect(appended[0].removed).toBe(true);
    await flush();

    const p2 = loadVendorScript('https://t.example/4.js', {
      document: doc as unknown as Document,
      timeoutMs: 10,
    });
    expect(appended.length).toBe(2);
    appended[1].onload?.();
    await p2;
  });

  test('常量口径：默认超时 10s', () => {
    expect(VENDOR_SCRIPT_TIMEOUT_MS).toBe(10_000);
  });
});
