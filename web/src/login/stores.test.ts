// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化落地后移除）。
// @ts-ignore
import { afterEach, beforeEach, describe, expect, rs, test } from 'rstack/test';
import {
  clearLoginToken,
  getLoginToken,
  setLoginToken,
  subscribeLoginToken,
} from './loginTokenStore';
import {
  clearOidcContext,
  loadOidcContext,
  saveOidcContext,
} from './oidcContext';

/** 内存版 Storage 桩（记录 setItem 的键，供「只存 oidc」断言）。 */
function fakeStorage(): Storage & { writtenKeys: string[] } {
  const map = new Map<string, string>();
  const writtenKeys: string[] = [];
  return {
    writtenKeys,
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (key: string) => map.get(key) ?? null,
    key: (index: number) => [...map.keys()][index] ?? null,
    removeItem: (key: string) => {
      map.delete(key);
    },
    setItem: (key: string, value: string) => {
      map.set(key, value);
      writtenKeys.push(key);
    },
  };
}

let storage: ReturnType<typeof fakeStorage>;

beforeEach(() => {
  storage = fakeStorage();
  // rs.stubGlobal 模式（沿 shared/hooks hooks.test.ts 先例；仅测试进程内生效）。
  rs.stubGlobal('window', { localStorage: storage });
  clearLoginToken(); // 模块级变量跨用例复位
});

afterEach(() => {
  rs.unstubAllGlobals();
});

describe('loginTokenStore（§4.1 行 397-403 五条不可打折）', () => {
  test('初始为空串（空串表示无：首次请求 / 已完成 / 已失效）', () => {
    expect(getLoginToken()).toBe('');
  });

  test('set → get；订阅者收到最新值', () => {
    const received: string[] = [];
    subscribeLoginToken((token) => received.push(token));
    setLoginToken('tok-1');
    expect(getLoginToken()).toBe('tok-1');
    expect(received).toEqual(['tok-1']);
  });

  test('每次 set 无条件覆盖（五条之 2：后端每次重签，旧值立即作废）', () => {
    setLoginToken('tok-1');
    setLoginToken('tok-2');
    expect(getLoginToken()).toBe('tok-2');
    setLoginToken('tok-3');
    expect(getLoginToken()).toBe('tok-3');
  });

  test('clear → 空串并通知（五条之 3：status=success 时清空）', () => {
    setLoginToken('tok-1');
    const received: string[] = [];
    subscribeLoginToken((token) => received.push(token));
    clearLoginToken();
    expect(getLoginToken()).toBe('');
    expect(received).toEqual(['']);
  });

  test('退订后不再收到通知；多订阅者各自收到', () => {
    const a: string[] = [];
    const b: string[] = [];
    const unsubscribe = subscribeLoginToken((token) => a.push(token));
    subscribeLoginToken((token) => b.push(token));
    setLoginToken('tok-1');
    unsubscribe();
    setLoginToken('tok-2');
    expect(a).toEqual(['tok-1']);
    expect(b).toEqual(['tok-1', 'tok-2']);
  });

  test('不触碰任何 Web 存储（五条之 4：禁止 localStorage / sessionStorage / Cookie）', () => {
    setLoginToken('tok-1');
    clearLoginToken();
    expect(storage.writtenKeys).toEqual([]); // 本用例的 store 操作零落盘
  });
});

describe('oidcContext（§2.7.2 行 599-600：键 al_oidc_ctx，读出后立即 clear）', () => {
  test('save → load 读出即清：二次 load 为 undefined', () => {
    saveOidcContext({
      client_id: 'cid',
      redirect_uri: 'https://app/cb',
      scope: 'openid profile',
      state: 'st',
    });
    expect(storage.getItem('al_oidc_ctx')).not.toBeNull(); // 已落盘

    const loaded = loadOidcContext();
    expect(loaded).toEqual({
      client_id: 'cid',
      redirect_uri: 'https://app/cb',
      scope: 'openid profile',
      state: 'st',
      nonce: undefined,
      code_challenge: undefined,
      code_challenge_method: undefined,
    });
    expect(storage.getItem('al_oidc_ctx')).toBeNull(); // 读完即清（§2.7.2 行 600）
    expect(loadOidcContext()).toBeUndefined();
  });

  test('save 只写 al_oidc_ctx 一个键（登录端允许落盘的数据只有 oidc）', () => {
    saveOidcContext({ client_id: 'cid', redirect_uri: 'https://app/cb' });
    expect(storage.writtenKeys).toEqual(['al_oidc_ctx']);
  });

  test('无值 → undefined；clear 显式清除', () => {
    expect(loadOidcContext()).toBeUndefined();
    saveOidcContext({ client_id: 'cid', redirect_uri: 'https://app/cb' });
    clearOidcContext();
    expect(storage.getItem('al_oidc_ctx')).toBeNull();
    expect(loadOidcContext()).toBeUndefined();
  });

  test('非法 JSON → undefined 且键已清（不透出脏数据）', () => {
    storage.setItem('al_oidc_ctx', '{not json');
    expect(loadOidcContext()).toBeUndefined();
    expect(storage.getItem('al_oidc_ctx')).toBeNull();
  });

  test('缺必需字段（client_id / redirect_uri，§4.2 行 1081）→ undefined', () => {
    storage.setItem('al_oidc_ctx', JSON.stringify({ client_id: 'cid' }));
    expect(loadOidcContext()).toBeUndefined();
  });

  test('可选字段只还原 string 值（脏类型丢弃）', () => {
    storage.setItem(
      'al_oidc_ctx',
      JSON.stringify({
        client_id: 'cid',
        redirect_uri: 'https://app/cb',
        scope: 42, // 脏类型
        nonce: 'n-1',
      }),
    );
    expect(loadOidcContext()).toEqual({
      client_id: 'cid',
      redirect_uri: 'https://app/cb',
      scope: undefined,
      state: undefined,
      nonce: 'n-1',
      code_challenge: undefined,
      code_challenge_method: undefined,
    });
  });

  test('非浏览器环境（window 未定义）：save 无操作、load undefined', () => {
    rs.unstubAllGlobals();
    expect(loadOidcContext()).toBeUndefined();
    expect(() =>
      saveOidcContext({ client_id: 'cid', redirect_uri: 'https://app/cb' }),
    ).not.toThrow();
    expect(() => clearOidcContext()).not.toThrow();
  });
});
