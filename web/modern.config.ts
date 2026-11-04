import { appTools, defineConfig } from '@modern-js/app-tools';

// https://modernjs.dev/en/configure/app/usage
export default defineConfig({
  plugins: [appTools()],
  source: {
    entries: {
      // 安装 entry（docs/前端架构.md §2 / §6b）：Go 空壳引用 /assets/setup/entry.js。
      // disableMount：entry.tsx 自行 createRoot 挂载，不用 Modern.js 生成入口代码。
      setup: {
        entry: './src/setup/entry.tsx',
        disableMount: true,
      },
      // 登录 entry（docs/前端架构.md §2 行 119 / §4.1）：Go 空壳引用
      // /assets/login/entry.js（接口文档 §8 行 1428 固定 URL 契约）。
      // 同 setup 模式：disableMount，entry.tsx 自行 createRoot 挂载。
      login: {
        entry: './src/login/entry.tsx',
        disableMount: true,
      },
    },
  },
  output: {
    // 构建期资源前缀（§2 注释）；运行期由 __webpack_public_path__
    //（static_base 注入值）覆盖（§1.5）。
    assetPrefix: '/assets/',
    distPath: {
      // 初始 JS 直接落在 dist/{entry}/entry.js（§2：Go 空壳引用 /assets/{entry}/entry.js）。
      js: '',
    },
    filename: {
      js: (pathData) => {
        const chunk = pathData.chunk as { name?: string } | undefined;
        const name = chunk?.name;
        // entry 的初始 chunk → {entry}/entry.js（固定 URL 契约，Go 空壳引用
        // /assets/{entry}/entry.js）。例外回退 contenthash 命名（§1.5：产物
        // 文件名自带 contenthash）：① 异步 chunk（filename 回调里 runtime 为
        // undefined）；② Modern.js / rsbuild 拆出的 vendor chunk（lib-*、
        // builder-runtime——runtimeChunk 单拆后 hasRuntime 判别对 entry 恒
        // false，回调内无法与 entry chunk 区分，故按名字豁免）。
        const isInitial = pathData.runtime !== undefined;
        const isVendorChunk =
          name?.startsWith('lib-') || name === 'builder-runtime';
        if (name && isInitial && !isVendorChunk) {
          return `${name}/entry.js`;
        }
        return 'chunks/[id].[contenthash:8].js';
      },
    },
  },
});
