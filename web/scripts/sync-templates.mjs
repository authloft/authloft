/**
 * 壳层模板同步脚本（口径定稿：docs/前端架构.md §1.5 / docs/接口文档.md §8）：
 * 对四个 entry（与 web/modern.config.ts source.entries 一一对应）把
 * dist/html/{entry}/index.html **原样复制**（Buffer 进 Buffer 出，内容零改写）
 * 到 server/internal/pages/templates/{entry}.html（后端 internal/pages embed 消费）；
 * 随后做**对账纯校验**，只校验不改写，任何一条不满足即整次失败。
 *
 * 对账条目（§1.5 对账自检 / §9 第 22 条）：
 * ① <script（内联 + 外链，含 init script）数 + <style 数 + link[rel=stylesheet] 数
 *    三类合计 = {{AUTHLOFT_CSP_NONCE}} 出现次数（init script 的 nonce 也计入，等式恰好成立；
 *    漏挂任意一个标签即整页被 CSP 拦）；
 * ② 三占位符（CSP_NONCE / STATIC_BASE / INIT_JSON）各 ≥1 次在场；
 * ③ src="/assets 与 href="/assets 零命中（无写死前缀残留，前缀只允许占位符）。
 *
 * 仅用 node 内置模块（fs / path / url），零新增依赖；任何失败以非零 exit code 结束，
 * 供 CI 与 package.json build 命令的 && 链感知。路径经 import.meta.url 相对定位，不依赖 cwd。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** entry 列表（与 web/modern.config.ts source.entries 一一对应，本文件内唯一定义处）。 */
const ENTRIES = ['login', 'account', 'admin', 'setup'];
/** 运行期占位符（接口文档 §8 唯一定义；由构建期 config 注入，后端运行期替换值）。 */
const CSP_NONCE = '{{AUTHLOFT_CSP_NONCE}}';
const STATIC_BASE = '{{AUTHLOFT_STATIC_BASE}}';
const INIT_JSON = '{{AUTHLOFT_INIT_JSON}}';

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const distHtmlDir = path.join(webDir, 'dist', 'html');
/** 写入边界（§1.5）：对 server/ 的写权限仅限这四个落位产物文件，覆盖式写入。 */
const outputDir = path.join(webDir, '..', 'server', 'internal', 'pages', 'templates');

/** 统计正则命中数。 */
function countMatches(text, regex) {
  return text.match(regex)?.length ?? 0;
}

/** 统计子串出现次数。 */
function countOccurrences(text, needle) {
  return text.split(needle).length - 1;
}

/** 单 entry 对账：返回统计数字与问题清单。 */
function reconcile(html) {
  const scriptCount = countMatches(html, /<script\b/g);
  const styleCount = countMatches(html, /<style\b/g);
  const stylesheetCount = countMatches(html, /<link\b[^>]*\brel\s*=\s*"stylesheet"[^>]*>/g);
  const nonceCount = countOccurrences(html, CSP_NONCE);
  const staticBaseCount = countOccurrences(html, STATIC_BASE);
  const initJsonCount = countOccurrences(html, INIT_JSON);
  const hardcodedPrefixCount = countMatches(html, /\s(?:src|href)\s*=\s*"\/assets/g);

  const problems = [];
  // ① 三类标签合计 = nonce 出现次数（等式恰好成立，多算 = preload 漏网、少算 = 有标签裸奔）。
  if (scriptCount + styleCount + stylesheetCount !== nonceCount) {
    problems.push(
      `nonce 对账不过：script(${scriptCount}) + style(${styleCount}) + link[stylesheet](${stylesheetCount}) = ${scriptCount + styleCount + stylesheetCount} ≠ nonce 出现次数(${nonceCount})`,
    );
  }
  // ② 三占位符各 ≥1 次在场。
  if (nonceCount < 1) problems.push(`缺 ${CSP_NONCE}`);
  if (staticBaseCount < 1) problems.push(`缺 ${STATIC_BASE}`);
  if (initJsonCount < 1) problems.push(`缺 ${INIT_JSON}`);
  // ③ 写死前缀零残留。
  if (hardcodedPrefixCount > 0) {
    problems.push(`写死 src/href="/assets 前缀残留 ${hardcodedPrefixCount} 处`);
  }

  return {
    stats: { scriptCount, styleCount, stylesheetCount, nonceCount, staticBaseCount, initJsonCount },
    problems,
  };
}

fs.mkdirSync(outputDir, { recursive: true });

const tableRows = [];
let failed = false;

for (const entry of ENTRIES) {
  const distHtmlPath = path.join(distHtmlDir, entry, 'index.html');
  if (!fs.existsSync(distHtmlPath)) {
    console.error(`[sync-templates] ${entry}：dist/html/${entry}/index.html 缺失，请先执行 modern build`);
    failed = true;
    continue;
  }
  // 仅复制：Buffer 原样读写，内容零改写（不做结构改写 / 不删节点 / 不做任何文本替换）。
  const htmlBuf = fs.readFileSync(distHtmlPath);
  fs.writeFileSync(path.join(outputDir, `${entry}.html`), htmlBuf);
  const { stats, problems } = reconcile(htmlBuf.toString('utf8'));
  tableRows.push(
    `${entry}: script=${stats.scriptCount} style=${stats.styleCount} link[stylesheet]=${stats.stylesheetCount} nonce=${stats.nonceCount} static_base=${stats.staticBaseCount} init_json=${stats.initJsonCount}`,
  );
  for (const problem of problems) {
    console.error(`[sync-templates] ${entry}：对账不过——${problem}`);
    failed = true;
  }
}

console.log('[sync-templates] 对账数字表（script 内联+外链 / style / link[stylesheet] / nonce / STATIC_BASE / INIT_JSON）：');
for (const row of tableRows) console.log(`  ${row}`);

if (failed) {
  console.error('[sync-templates] 同步失败：对账未全部通过（复制已完成，修复构建配置后重跑）');
  process.exit(1);
}

console.log(`[sync-templates] 完成：${ENTRIES.length} 份壳层模板对账通过，已同步到 server/internal/pages/templates/`);
