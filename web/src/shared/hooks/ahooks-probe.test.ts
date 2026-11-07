// ahooks 探针：rstest node 环境下真实加载 ahooks（import 解析 + 类型
// smoke + SSR 渲染 manual useRequest 不触发请求）。结论：ahooks 为纯 TS
// 编译产物（lib/ CJS + es/ ESM），无 CSS / 静态资产，不满足 Semi
// 崩溃的根因（externalize 后 .css 触发 Unknown file extension）——
// rstest 无需为它配置 bundleDependencies。
// 绊线：本文件仿 semi-probe.test.tsx 长期保留；若它红了（如 ahooks 未来
// 版本引入 CSS 或 node 不兼容产物），按 Semi 先例在 rstack.config.mts 的
// define.test.bundleDependencies 追加 /ahooks[\\/]/ 并在报告说明。
// tsconfig moduleResolution=node 解析不了 rstack/test 子路径。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { useRequest } from 'ahooks';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

describe('ahooks 真实加载探针', () => {
  test('import 解析 + 类型 smoke：useRequest 为函数', () => {
    expect(typeof useRequest).toBe('function');
  });

  test('SSR 渲染 manual useRequest：不触发请求，返回形状齐备', () => {
    let fetched = 0;
    function Probe() {
      const { data, error, loading } = useRequest(
        async () => {
          fetched += 1;
          return 'ok';
        },
        { manual: true },
      );
      return createElement('span', null, `${String(loading)}:${String(data)}:${String(error)}`);
    }
    const html = renderToStaticMarkup(createElement(Probe));
    expect(html).toContain('false:undefined:undefined');
    expect(fetched).toBe(0);
  });
});
