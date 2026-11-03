// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterEach, describe, expect, rs, test } from 'rstack/test';
import {
  fetchSetupStatus,
  requestInstall,
  requestUploadConfig,
  setupMessage,
  SetupError,
  type InstallPayload,
} from './api';

function stubFetch(
  handler: (url: string, init: RequestInit) => Response | Promise<Response>,
): Array<{ url: string; init: RequestInit }> {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  rs.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const resolved = init ?? {};
    calls.push({ url: String(input), init: resolved });
    return Promise.resolve(handler(String(input), resolved));
  });
  return calls;
}

function jsonResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected the promise to reject');
}

const fullPayload: InstallPayload = {
  dbDsn: 'user:pass@tcp(127.0.0.1:3306)/authloft',
  redisAddr: '127.0.0.1:6379',
  redisPassword: '',
  redisDb: 0,
  root: 'https://uc.example.com',
  rpId: 'uc.example.com',
  adminUsername: 'admin',
  adminPassword: 's3cret!',
};

afterEach(() => {
  rs.unstubAllGlobals();
});

describe('setup/api fetchSetupStatus（§13.1）', () => {
  test('200 + {"status":"success","mode":"setup"} → setup 模式', async () => {
    const calls = stubFetch(() =>
      jsonResponse('{"status":"success","mode":"setup"}'),
    );

    expect(await fetchSetupStatus()).toEqual({ kind: 'setup' });
    expect(calls[0].url).toBe('/api/setup/status');
  });

  test('404 → gone（§13.4：setup 路由消失 = 重启完成锚点）', async () => {
    stubFetch(() =>
      jsonResponse(
        '{"status":"error","error":{"code":"not_found","message":"no route","request_id":"r1"}}',
        404,
      ),
    );
    expect(await fetchSetupStatus()).toEqual({ kind: 'gone' });
  });

  test('连接被拒（fetch reject）→ unreachable，不 reject', async () => {
    rs.stubGlobal('fetch', () => Promise.reject(new TypeError('fetch failed')));
    expect(await fetchSetupStatus()).toEqual({ kind: 'unreachable' });
  });

  test('非 404 的非 2xx（如 500）→ unreachable，继续轮询口径', async () => {
    stubFetch(() => jsonResponse('{"status":"error"}', 500));
    expect(await fetchSetupStatus()).toEqual({ kind: 'unreachable' });
  });
});

describe('setup/api 安装请求（§13.2 / §13.3）', () => {
  test('requestInstall：载荷按契约 snake_case；成功（restarting）→ 正常返回', async () => {
    const calls = stubFetch(() =>
      jsonResponse('{"status":"success","restarting":true}'),
    );

    await requestInstall(fullPayload);

    expect(calls[0].url).toBe('/api/setup/install');
    expect(calls[0].init.method).toBe('POST');
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers['Content-Type']).toBe('application/json');
    const body = JSON.parse(calls[0].init.body as string) as Record<
      string,
      unknown
    >;
    expect(body).toEqual({
      db_dsn: 'user:pass@tcp(127.0.0.1:3306)/authloft',
      redis_addr: '127.0.0.1:6379',
      redis_password: '',
      redis_db: 0,
      root: 'https://uc.example.com',
      rp_id: 'uc.example.com',
      admin_username: 'admin',
      admin_password: 's3cret!',
    });
  });

  test('requestInstall：HTTP 200 内 status:"error" → 归一 SetupError（业务码 / 请求号透传）', async () => {
    stubFetch(() =>
      jsonResponse(
        '{"status":"error","error":{"code":"password_weak","message":"weak","request_id":"req-9"}}',
      ),
    );

    const error = await rejectionOf(requestInstall(fullPayload));

    expect(error).toBeInstanceOf(SetupError);
    const setupError = error as SetupError;
    expect(setupError.httpStatus).toBe(200);
    expect(setupError.code).toBe('password_weak');
    expect(setupError.requestId).toBe('req-9');
  });

  test('requestUploadConfig：非 2xx 错误信封 → code 取自 error.code（§1.0）', async () => {
    stubFetch(() =>
      jsonResponse(
        '{"status":"error","error":{"code":"config_invalid","message":"x","request_id":"r"}}',
        400,
      ),
    );

    const error = await rejectionOf(requestUploadConfig('config: x'));

    expect(error).toBeInstanceOf(SetupError);
    expect((error as SetupError).httpStatus).toBe(400);
    expect((error as SetupError).code).toBe('config_invalid');
  });

  test('requestUploadConfig：非 2xx 解不出信封 → §1.5 六元兜底（415 → unsupported_media_type）', async () => {
    stubFetch(() =>
      new Response('not json', {
        status: 415,
        headers: { 'content-type': 'text/plain' },
      }),
    );

    const error = await rejectionOf(requestUploadConfig('config: x'));

    expect(error).toBeInstanceOf(SetupError);
    expect((error as SetupError).code).toBe('unsupported_media_type');
  });

  test('requestUploadConfig：网络错误 → SetupError（httpStatus=0）', async () => {
    rs.stubGlobal('fetch', () => Promise.reject(new TypeError('fetch failed')));

    const error = await rejectionOf(requestUploadConfig('config: x'));

    expect(error).toBeInstanceOf(SetupError);
    expect((error as SetupError).httpStatus).toBe(0);
    expect((error as SetupError).code).toBe('internal_error');
  });
});

describe('setup/api setupMessage（对齐 errors.ts CODE_TABLE/未知兜底口径）', () => {
  test('§13 业务码查表、未知码走兜底（不透出后端 message 原文）', () => {
    expect(setupMessage('config_invalid')).toBe(
      '配置文件校验失败：内容不完整、非法或缺少 sign_key，请修正后重新上传',
    );
    expect(setupMessage('admin_missing')).toBe(
      '版本已最新但缺少管理员账号，请改走全新安装',
    );
    expect(setupMessage('totally_unknown_code')).toBe('操作失败，请检查输入后重试');
  });
});
