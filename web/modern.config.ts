import { appTools, defineConfig } from '@modern-js/app-tools';

// https://modernjs.dev/en/configure/app/usage

// 运行期占位符（接口文档 §8 唯一定义）：值运行期才知、由后端注入；
// 构建期由下方 security / tools / html 三 config 注入产物占位符本体。
const CSP_NONCE = '{{AUTHLOFT_CSP_NONCE}}';
const STATIC_BASE = '{{AUTHLOFT_STATIC_BASE}}';
const INIT_JSON = '{{AUTHLOFT_INIT_JSON}}';

const IS_DEV = process.env.NODE_ENV === 'development';
const DEV_INIT_JSON = {"al_root":"http://localhost:8080","static_base":"/assets","methods":{"flags":{"passwordReset":true,"registration":true},"captcha":{"providerKey":"builtin_image","type":"image"},"methods":[{"method":"password","usage":["primary"],"steps":["form"],"fields":[{"name":"username","label":"用户名/邮箱/手机号","type":"text","required":true},{"name":"password","label":"密码","type":"password","required":true},{"name":"captcha","label":"人机校验","type":"captcha"}]},{"method":"otp_sms","usage":["primary","secondary"],"steps":["challenge","form"],"challengeFields":[{"name":"phone","label":"手机号","type":"phone","required":true}],"codeLength":"6","resendAfter":"60","expiresIn":"300"},{"method":"otp_email","usage":["primary","secondary"],"steps":["challenge","form"],"challengeFields":[{"name":"email","label":"邮箱","type":"email","required":true}],"codeLength":"6","resendAfter":"60","expiresIn":"300"},{"method":"webauthn","usage":["primary","secondary"],"steps":["challenge","form"],"capability":"window.PublicKeyCredential"}]}}

export default defineConfig({
  plugins: [appTools()],
  source: {
    entries: {
      // 安装 entry（docs/前端架构.md §2 / §6b）：壳层模板 = 构建产物
      // dist/html/setup/index.html 原样复制（§1.5，占位符由下方三 config 注入）。
      // disableMount：entry.tsx 自行 createRoot 挂载，不用 Modern.js 生成入口代码。
      setup: {
        entry: './src/setup/entry.tsx',
        disableMount: true,
      },
      // 登录 entry（docs/前端架构.md §2 行 119 / §4.1）：壳层模板 = 构建产物
      // dist/html/login/index.html 原样复制（§1.5，接口文档 §8）。
      // 同 setup 模式：disableMount，entry.tsx 自行 createRoot 挂载。
      login: {
        entry: './src/login/entry.tsx',
        disableMount: true,
      },
      // 用户端安全中心 entry（docs/前端架构.md §2 / §5 行 478）：壳层模板 =
      // 构建产物 dist/html/account/index.html 原样复制（§1.5，接口文档 §8）。
      // 同 setup / login 模式：disableMount，entry.tsx 自行 createRoot 挂载。
      account: {
        entry: './src/account/entry.tsx',
        disableMount: true,
      },
      // 管理端 entry（docs/前端架构.md §2 / §6 行 499）：壳层模板 =
      // 构建产物 dist/html/admin/index.html 原样复制（§1.5，接口文档 §8）。
      // 同 setup / login / account 模式：disableMount，entry.tsx 自行 createRoot 挂载。
      admin: {
        entry: './src/admin/entry.tsx',
        disableMount: true,
      },
    },
  },
  // ── 壳层模板三个运行期占位符的构建期注入（docs/前端架构.md §1.5 定稿）──
  // 壳层模板 = dist/html/{entry}/index.html 原样复制（scripts/sync-templates.mjs 仅复制
  // + 对账校验，零改写）；三占位符全部在此构建期注入产物，框架产物是模板唯一真相源。
  security: {
    // ① nonce 统一挂（§1.5 ①）：Rsbuild 内建，在标签生成阶段给 script（外链 + 内联，
    //    含框架自动注入的 runtime / route manifest 脚本）、<style>、
    //    link[rel=preload][as=script] 统一挂 nonce，并注入 import.meta.rspackNonce
    //    （运行期动态插入的 chunk script 同享 nonce）。
    //    已知缺口：不覆盖 link[rel=stylesheet] → 由下方 html.tags Handler 补挂。
    nonce: CSP_NONCE,
  },
  tools: {
    htmlPlugin: {
      // ② 静态资源前缀（§1.5 ②）：html 插件层 publicPath，仅改写 HTML 内 script / link
      //    标签的 src / href 前缀（/assets/xxx → {{AUTHLOFT_STATIC_BASE}}/xxx）。
      //    运行期 publicPath（产物 runtime 的 "/assets/"）、CSS url()、异步 chunk
      //    不受影响——entry.tsx 的 __webpack_public_path__ 运行期覆盖逻辑不动。
      publicPath: IS_DEV ? '/' : `${STATIC_BASE}/`,
    },
  },
  html: {
    // ③ init script 前插 + link[rel=stylesheet] nonce 补挂（§1.5 ③）。
    //    Handler 收到全量 head / body 标签并写回；children 原样输出不转义，
    //    {{…}} 不匹配模板语法，minify 后占位符存活（已实证）。
    tags: [
      (tags) => {
        // a) 补挂 security.nonce 的已知缺口：link[rel=stylesheet] 也须统一携带
        //    nonce 占位符，漏挂任意一个标签即整页被 CSP 拦（§9 第 22 条）。
        for (const tag of tags) {
          if (
            tag.tag === 'link' &&
            tag.attrs?.rel === 'stylesheet' &&
            tag.attrs.nonce === undefined
          ) {
            tag.attrs.nonce = CSP_NONCE;
          }
        }
        // b) 前插 init script：head: true + append: false 使其稳定排序后位于
        //    <head> 最前（在所有其他标签前），保证 INIT 在任何脚本前执行。
        return [
          {
            tag: 'script',
            attrs: { nonce: CSP_NONCE },
            children: `window.__AUTHLOFT_INIT__ = ${IS_DEV ? JSON.stringify(DEV_INIT_JSON) : INIT_JSON};`,
            head: true,
            append: false,
          },
          ...tags,
        ];
      },
    ],
  },
  output: {
    // 构建期资源前缀（§2 注释）；运行期由 __webpack_public_path__
    //（static_base 注入值）覆盖（§1.5）。
    assetPrefix: '/assets/',
    distPath: {
      js: 'js',
      css: 'css',
    },
  },
});
