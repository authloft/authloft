// Configuration guide: https://rstack.rs/config
import { define } from 'rstack';
import { globalIgnores } from '@rslint/core';

// 仓库既有代码统一单引号，生成产物不参与格式化。缺此配置会把存量文件与
// 生成产物全部判为未格式化（formatter 默认双引号）。
define.fmt({
  singleQuote: true,
  ignorePatterns: ['src/gen/**'],
  // 存量两文件整篇用双引号，沿用原口径避免机械改写大段无关代码。
  overrides: [
    {
      files: ['src/shared/api/errors.ts', 'src/shared/api/errors.test.ts'],
      options: { singleQuote: false },
    },
  ],
});

define.lint(({ js, ts }) => [
  globalIgnores(['**/gen/proto/**']),
  js.configs.recommended,
  ts.configs.recommended,
  {
    files: ['**/*.test.{ts,tsx}'],
    rules: {
      // tsconfig moduleResolution=node 解析不了 rstack/test 子路径，
      // 测试文件用 @ts-ignore 放宽该 import；tsconfig 现代化后移除本豁免。
      '@typescript-eslint/ban-ts-comment': 'off',
    },
  },
]);

// node 环境下 rstest 默认把 node_modules 依赖 externalize 给 Node 原生
// ESM 加载，@douyinfe/semi-ui（含 semi-foundation）内部的 .css 因此触发
// Unknown file extension ".css"。把 @douyinfe/* 打进测试 bundle，CSS 改走
// rspack 管线在构建期被吞掉。define.test 仅作用于 rs test，
// 生产构建走 modern.config.ts（Rsbuild），互不影响。
define.test({
  output: {
    // prismjs 由 Semi codeHighlight 间接引入，同样须进 bundle 才能被
    // 下方 ProvidePlugin 接管（externalized 模块插件够不着）。
    bundleDependencies: [/^@douyinfe[\\/]/, /^prismjs[\\/]/, 'prismjs'],
  },
  tools: {
    rspack: (config, { rspack }) => {
      // 连带修复：Semi codeHighlight 引入的 prismjs/components/* 是裸引
      // 全局 Prism 的 IIFE，打进 bundle 后该自由变量失去浏览器全局来源，
      // 用 ProvidePlugin 把它指向 prismjs 模块本体（仅作用于测试 bundle）。
      config.plugins ??= [];
      config.plugins.push(new rspack.ProvidePlugin({ Prism: 'prismjs' }));
    },
  },
});
