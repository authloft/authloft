// Configuration guide: https://rstack.rs/config
import { define } from 'rstack';

define.lint(({ js, ts }) => [
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

define.staged({
  '*.{js,jsx,ts,tsx,cjs,mjs,cts,mts}': ['rs lint', 'rs fmt'],
  '*.{md,mdx,json,json5,yml,yaml,css,less,scss,html}': 'rs fmt',
});

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
      config.plugins.push(
        new rspack.ProvidePlugin({ Prism: 'prismjs' }),
      );
    },
  },
});

define.fmt({
  singleQuote: true,
});
