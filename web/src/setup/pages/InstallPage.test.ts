// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
// root 预填 / 校验逻辑在 ../wizard（零 Semi 依赖）；InstallPage.tsx 的提交
// 构造纯函数随 Semi 真实加载链可测（加载口径见 shared/semi-probe.test.tsx）。
import {
  checkRoot,
  isIpHost,
  prefillRoot,
  type InstallFormState,
} from '../wizard';
import { buildInstallPayload } from './InstallPage';

/** root 预填与前置校验（docs/前端架构.md §6b / 接口文档 §13.3）。 */
describe('setup/InstallPage root 预填与前置校验', () => {
  describe('isIpHost（§13.3 拒 IP）', () => {
    test('IPv4 点分四段 → true', () => {
      expect(isIpHost('127.0.0.1')).toBe(true);
      expect(isIpHost('192.168.1.5')).toBe(true);
    });

    test('IPv6（含冒号；hostname 无端口与方括号）→ true', () => {
      expect(isIpHost('::1')).toBe(true);
      expect(isIpHost('2001:db8::1')).toBe(true);
    });

    test('域名 / localhost → false', () => {
      expect(isIpHost('uc.example.com')).toBe(false);
      expect(isIpHost('localhost')).toBe(false);
    });
  });

  describe('prefillRoot（§6b：host 为域名或 localhost 才预填，IP 一律留空）', () => {
    test('host 为域名 / localhost → 回填 origin', () => {
      expect(prefillRoot('https://uc.example.com')).toBe(
        'https://uc.example.com',
      );
      expect(prefillRoot('http://localhost:3000')).toBe(
        'http://localhost:3000',
      );
    });

    test('host 为 IP（v4 / v6）→ 留空', () => {
      expect(prefillRoot('http://192.168.1.5:8080')).toBe('');
      expect(prefillRoot('http://[::1]:8080')).toBe('');
    });

    test('非法 origin → 留空（不做预填猜测）', () => {
      expect(prefillRoot('not-a-url')).toBe('');
    });
  });

  describe('checkRoot（§6b：必填 + 拒 IP + 域名格式）', () => {
    test('空值 → 必填', () => {
      expect(checkRoot('')).toBe('rootRequired');
      expect(checkRoot('   ')).toBe('rootRequired');
    });

    test('host 为 IP（v4 / v6）→ 拒 IP', () => {
      expect(checkRoot('http://127.0.0.1')).toBe('rootIpRejected');
      expect(checkRoot('https://192.168.1.5:8443')).toBe('rootIpRejected');
      expect(checkRoot('http://[::1]')).toBe('rootIpRejected');
    });

    test('非 http(s) 完整 URL / host 非域名 → 格式错误', () => {
      expect(checkRoot('uc.example.com')).toBe('rootInvalid');
      expect(checkRoot('ftp://uc.example.com')).toBe('rootInvalid');
      expect(checkRoot('https://')).toBe('rootInvalid');
    });

    test('完整 URL 且 host 为域名 / localhost → 通过', () => {
      expect(checkRoot('https://uc.example.com')).toBe(null);
      expect(checkRoot('http://localhost:3000/setup')).toBe(null);
    });
  });
});

/**
 * buildInstallPayload（docs/前端架构.md §6b / 接口文档 §13.3）：
 * handleSubmit 的取值路径——Semi 清空字段后 '' 转 undefined，
 * 无 validator 直达提交的字段曾在此抛未捕获 TypeError。
 */
describe('setup/InstallPage buildInstallPayload（Semi 清空字段 → undefined 的取值兜底）', () => {
  const base: InstallFormState = {
    dbDriver: 'mysql',
    dbHost: '127.0.0.1',
    dbPort: '3306',
    dbUser: 'root',
    dbPassword: 'secret',
    dbName: 'authloft',
    dbParams: '',
    redisHost: '127.0.0.1',
    redisPort: '6379',
    redisPassword: '',
    redisDb: '0',
    root: 'https://uc.example.com',
    rpId: 'uc.example.com',
    rpDisplayName: 'Authloft',
    adminUsername: 'root',
    adminPassword: 'p@ss',
  };

  test('字段清空后（handleSubmit 提交路径）不抛 TypeError 且取值兜底正确', () => {
    // 模拟 Semi onSubmit 运行期形态：类型层仍标 string，实值为 undefined。
    const cleared = {
      ...base,
      root: undefined,
      rpId: undefined,
      rpDisplayName: undefined,
      adminUsername: undefined,
    } as unknown as InstallFormState;
    let payload: ReturnType<typeof buildInstallPayload> | undefined;
    expect(() => {
      payload = buildInstallPayload(cleared);
    }).not.toThrow();
    expect(payload?.root).toBe('');
    expect(payload?.rpId).toBe('');
    expect(payload?.rpDisplayName).toBe('');
    expect(payload?.adminUsername).toBe('');
    // 其余直读字段不受兜底影响（有 validator 的字段清空会被拦截，不可达提交）。
    expect(payload?.adminPassword).toBe('p@ss');
    expect(payload?.redisDb).toBe(0);
    // 方言字段清空回落 mysql（与后端 db_driver 零值回落口径一致）。
    expect(payload?.dbDriver).toBe('mysql');
  });

  test('字符串值仍走原 trim 口径（pickString 兜底不改变既有语义）', () => {
    const payload = buildInstallPayload({
      ...base,
      root: ' https://uc.example.com ',
      rpId: ' uc.example.com ',
    });
    expect(payload.root).toBe('https://uc.example.com');
    expect(payload.rpId).toBe('uc.example.com');
  });

  test('mysql 驱动 → dbDsn 为 go-sql-driver 形态且 dbDriver 透传', () => {
    const payload = buildInstallPayload(base);
    expect(payload.dbDriver).toBe('mysql');
    expect(payload.dbDsn).toBe('root:secret@tcp(127.0.0.1:3306)/authloft');
  });

  test('postgres 驱动 → dbDsn 为 URL 形态（与后端 validatePGDSN 对齐）', () => {
    const payload = buildInstallPayload({
      ...base,
      dbDriver: 'postgres',
      dbPort: '5432',
      dbParams: 'sslmode=disable',
    });
    expect(payload.dbDriver).toBe('postgres');
    expect(payload.dbDsn).toBe(
      'postgres://root:secret@127.0.0.1:5432/authloft?sslmode=disable',
    );
  });
});
