// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 login-container.test.tsx / register-reset.test.tsx
// 边界惯例），建号 wire 契约经导出纯函数（createAccountPayload /
// BINDING_REGISTER_METHOD / exitBinding）+ msw 拦截 api 层覆盖。
import { renderToStaticMarkup } from 'react-dom/server';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { create } from '@bufbuild/protobuf';
import { clearLoginToken, getLoginToken, setLoginToken } from '../loginTokenStore';
import {
  BindingSchema,
  LoginFlowResponseSchema,
  type Binding,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';

const { createElement } = React;

/**
 * al_root 在 transport（http.ts）模块求值时读取，故 BindingPage / BindingChoice
 * / api 模块经 beforeAll 动态 import（沿 login-container.test.tsx 模式）；
 * BASE 与既有测试文件取同值防跨文件竞争。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
};

const REGISTER_URL = `${BASE}/api.sso.v1.SsoService/Register`;

const server = setupServer();

let pagesMod: typeof import('../pages/BindingPage');
let choiceMod: typeof import('./BindingChoice');
let apiMod: typeof import('../api');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  pagesMod = await import('../pages/BindingPage');
  choiceMod = await import('./BindingChoice');
  apiMod = await import('../api');
});

beforeEach(() => {
  // rstest 对 .tsx 走 classic JSX runtime：渲染前 stub 全局 React（仅测试进程）。
  rs.stubGlobal('React', React);
});

afterEach(() => {
  server.resetHandlers();
  rs.unstubAllGlobals();
  clearLoginToken(); // loginTokenStore 模块级变量跨用例复位
});

afterAll(() => {
  server.close();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

// ---------------------------------------------------------------------------
// 测试数据（§1.3 行 129-132 信封 binding 形状）
// ---------------------------------------------------------------------------

function binding(init: Record<string, unknown>): Binding {
  return create(BindingSchema, init);
}

function envelope(init: Record<string, unknown>): LoginFlowResponse {
  return create(LoginFlowResponseSchema, init);
}

function renderChoice(allowSignup: boolean, displayName = 'QQ'): string {
  return renderToStaticMarkup(
    createElement(
      choiceMod.BindingChoice,
      {
        displayName,
        allowSignup,
        onCreateAccount: () => {},
        onExit: () => {},
      } as never,
    ),
  );
}

function viewProps(init: Record<string, unknown>): Record<string, unknown> {
  return {
    binding: binding({ providerKey: 'qq', displayName: 'QQ', allowSignup: true }),
    choice: 'choice',
    username: '',
    loading: false,
    status: 'idle',
    envelope: undefined,
    onChooseCreate: () => {},
    onExit: () => {},
    onUsernameChange: () => {},
    onSubmitAccount: () => {},
    ...init,
  };
}

function renderView(init: Record<string, unknown>): string {
  return renderToStaticMarkup(
    createElement(pagesMod.BindingPageView, viewProps(init) as never),
  );
}

// ---------------------------------------------------------------------------
// BindingChoice（§4.4 行 468 / §2.7.5）
// ---------------------------------------------------------------------------

describe('BindingChoice（§2.7.5 行 656-663：两选项 / 置灰口径 / 无绑定已有账号）', () => {
  test('allowSignup=true：两项均可选 + 身份行，无置灰提示、无「绑定已有账号」', () => {
    const markup = renderChoice(true);
    expect(markup).toContain('登录方式「QQ」'); // 身份行（binding.displayName）
    expect(markup).toContain('创建新账号');
    expect(markup).toContain('退出并使用其他账号登录');
    expect(markup).not.toContain('该渠道未开放注册');
    expect(markup).not.toContain('绑定已有账号'); // §2.7.5 行 676
    // 两按钮均可选：无 disabled。
    expect(markup).not.toContain('disabled');
  });

  test('allowSignup=false：创建新账号置灰 + 「该渠道未开放注册」，只保留退出项', () => {
    const markup = renderChoice(false);
    expect(markup).toContain('disabled'); // 创建新账号置灰（§2.7.5 行 663）
    expect(markup).toContain('该渠道未开放注册');
    expect(markup).toContain('退出并使用其他账号登录');
  });

  test('displayName 空串：零值兜底不渲染身份行（§9 第 18 条）', () => {
    const markup = renderChoice(true, '');
    expect(markup).not.toContain('登录方式');
  });
});

// ---------------------------------------------------------------------------
// BindingPageView 状态帧（§4.4 行 466；LoginFlowView 同款静态模式）
// ---------------------------------------------------------------------------

describe('BindingPageView 状态帧', () => {
  test('choice 帧：引导语 + 两选项（原地渲染，不跳路由）', () => {
    const markup = renderView({});
    expect(markup).toContain('该第三方身份尚未绑定账号'); // t('errors.status.binding_required')
    expect(markup).toContain('创建新账号');
    expect(markup).toContain('退出并使用其他账号登录');
  });

  test('create 帧：免密建号表单仅 username（§2.7.5 行 672：服务端忽略 password）', () => {
    const markup = renderView({ choice: 'create', username: 'alice_01' });
    expect(markup).toContain('name="username"');
    expect(markup).toContain('创建账号'); // 提交按钮
    expect(markup).not.toContain('name="password"'); // 免密建号无密码输入
    expect(markup).not.toContain('该渠道未开放注册'); // 表单帧不渲染选项
  });

  test('create 帧：用户名不合规体验性预校验提示（§2.3 行 449；服务端权威）', () => {
    const markup = renderView({ choice: 'create', username: 'ab' });
    expect(markup).toContain('用户名须为 5-20 位字母、数字或下划线');
  });

  test('success 帧：建号完成跳转中文案（§10.3 行 1547）', () => {
    const markup = renderView({
      status: 'success',
      envelope: envelope({ status: 'success', redirectTo: 'https://app.test/home' }),
    });
    expect(markup).toContain('账号创建成功，正在跳转');
  });

  test('username_taken：ErrorBanner + 表单保留可重试（§1.6 行 256 字段级提示）', () => {
    const markup = renderView({
      choice: 'create',
      username: 'alice_01',
      status: 'username_taken',
      envelope: envelope({
        status: 'username_taken',
        error: { message: '用户名已被占用' },
      }),
    });
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('用户名已被占用'); // t('errors.status.username_taken')
    expect(markup).toContain('name="username"'); // 表单保留原地
    expect(markup).not.toContain('disabled'); // 可重试 → 提交不禁用
  });

  test('signup_disabled：提示注册已关闭 + 提交禁用（§1.6 行 257 服务端拒绝兜底）', () => {
    const markup = renderView({
      choice: 'create',
      username: 'alice_01',
      status: 'signup_disabled',
      envelope: envelope({ status: 'signup_disabled' }),
    });
    expect(markup).toContain('注册未开放'); // t('errors.status.signup_disabled')
    expect(markup).toContain('disabled'); // 不可重试 → 提交禁用
  });

  test('failed（服务端兜底信封）：兜底文案 + 表单保留 + 提交禁用（§1.6 行 272；表驱动不可重试）', () => {
    const markup = renderView({
      choice: 'create',
      status: 'failed',
      envelope: envelope({ status: 'failed' }),
    });
    expect(markup).toContain('操作失败，请重试'); // t('errors.status.failed')
    expect(markup).toContain('name="username"'); // 表单保留原地（不隐藏）
    expect(markup).toContain('disabled'); // FLOW_STATUS_TABLE.failed 不可重试 → 提交禁用
  });

  test('信封 binding 缺失：零值兜底提示 + 仅保留退出（§9 第 18 条）', () => {
    const markup = renderView({ binding: undefined });
    expect(markup).toContain('请刷新重试');
    expect(markup).toContain('退出并使用其他账号登录');
    expect(markup).not.toContain('创建新账号'); // 兜底帧不渲染两选项
  });

  test('notice 透传：容器一次性提示渲染（restart / 传输失败来源）', () => {
    const markup = renderView({ notice: 'errors.status.token_expired' });
    expect(markup).toContain('登录已超时');
  });

  test('建号收到 restart 类（token_expired）后：回 choice 帧 + 超时提示，不断页（§1.6 行 251）', () => {
    // submitAccount 收到 RESTART_STATUSES 状态 → restartFlow()（choice 帧 /
    // status=idle / 信封清空）+ setLocalNotice(i18nKey)，不整页 exit()。node
    // 环境无法触发事件（文件头边界），静态断言 restart 后的状态组合。
    const markup = renderView({
      choice: 'choice',
      username: '',
      status: 'idle',
      envelope: undefined,
      notice: 'errors.status.token_expired',
    });
    expect(markup).toContain('登录已超时'); // §1.6 行 251 超时提示（ErrorBanner）
    expect(markup).toContain('创建新账号'); // 回 choice 帧：两选项仍在（不断页）
    expect(markup).toContain('退出并使用其他账号登录');
    expect(markup).not.toContain('name="username"'); // create 表单已收起
  });
});

// ---------------------------------------------------------------------------
// 纯函数（建号载荷 / 退出动作 / wire 契约）
// ---------------------------------------------------------------------------

describe('createAccountPayload / BINDING_REGISTER_METHOD（§2.7.5 行 660-672）', () => {
  test('载荷仅 {username}，不含 password（服务端按 login_token.tp 忽略）', () => {
    const payload = pagesMod.createAccountPayload('alice_01');
    expect(payload).toEqual({ username: 'alice_01' });
    expect('password' in payload).toBe(false);
  });

  test('method 取登录域三方方式名 thirdparty（见 BindingPage 文件头）', () => {
    expect(pagesMod.BINDING_REGISTER_METHOD).toBe('thirdparty');
  });
});

describe('exitBinding（§2.7.5 行 661：清 login_token → /sso/login，不发请求）', () => {
  test('先清 token 再跳登录页，URL 取 al_root 根（ssoPath，getInit 走 window 注入）', () => {
    // getInit 读 window.__AUTHLOFT_INIT__（register-reset.test.tsx ssoPath 同款 stub）。
    rs.stubGlobal('window', { __AUTHLOFT_INIT__: { al_root: `${BASE}/` } });
    const order: string[] = [];
    pagesMod.exitBinding(
      () => order.push('clear'),
      (url) => order.push(`navigate:${url}`),
    );
    expect(order).toEqual(['clear', `navigate:${BASE}/sso/login`]);
  });
});

describe('免密建号 wire 契约（msw 拦截 SsoService/Register）', () => {
  test('set_password 步仅提交 username + 内存 loginToken 注入；success 清空 token', async () => {
    setLoginToken('lt-bind');
    let raw = '';
    server.use(
      http.post(REGISTER_URL, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          status: 'success',
          redirectTo: 'https://app.test/home',
        });
      }),
    );
    const env = await apiMod.register({
      method: pagesMod.BINDING_REGISTER_METHOD,
      step: 'set_password',
      payload: pagesMod.createAccountPayload('alice_01'),
    });
    expect(env.status).toBe('success');
    expect(JSON.parse(raw)).toEqual({
      method: 'thirdparty',
      step: 'set_password',
      payload: { username: 'alice_01' },
      loginToken: 'lt-bind',
    });
    expect(getLoginToken()).toBe(''); // success 清空（§1.3 行 145）
  });
});
