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
 *
 * —— 前端产物复制段（docs/后端架构.md §3.13 施工口径，按 2026-11-06 dist 实盘校准）：
 * 模板段之后把 web/dist/** 原样复制到 server/assets/dist/**（保持相对目录结构，供后端
 * assets 包 //go:embed all:dist 经 /assets/** 伺服）；剔除：顶层 html/（模板源，模板段已消费）、
 * 全部 *.map、dist 根级 *.json（按扩展名/层级判定，布局无关，子目录 json 不剔）。复制前清空
 * 目标目录但保全 .gitkeep（bootstrap_assets_probe_test.go 依赖 GET /assets/.gitkeep → 200），
 * 复制后确保其在场（缺失则重建空文件）；源缺失/为空 → 直接非零 exit、不做任何清理/复制；
 * 清空重拷语义保证幂等（连续多次执行结果完全一致）。
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

// ---------- 前端产物复制段（docs/后端架构.md §3.13 口径）----------
/** 产物源（web/dist 根）与目标（后端 assets 包 embed 根）。 */
const distRootDir = path.join(webDir, 'dist');
const assetsDistDir = path.join(webDir, '..', 'server', 'assets', 'dist');
/** 入库占位文件：清理目标目录时必须保全（bootstrap_assets_probe_test.go 依赖其 200）。 */
const KEEP_FILE = '.gitkeep';

/** 递归收集目录下全部文件的相对路径（'/' 分隔，布局无关）。 */
function collectFiles(dir, prefix = '') {
  const files = [];
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${item.name}` : item.name;
    if (item.isDirectory()) files.push(...collectFiles(path.join(dir, item.name), rel));
    else if (item.isFile()) files.push(rel);
  }
  return files;
}

/** 剔除判定：顶层 html/ 模板源、全部 *.map、dist 根级 *.json（子目录 json 不剔——布局无关）。 */
function isExcluded(rel) {
  const segments = rel.split('/');
  return (
    segments[0] === 'html' ||
    rel.endsWith('.map') ||
    (segments.length === 1 && rel.endsWith('.json'))
  );
}

try {
  // 源校验先行：缺失/为空直接非零退出，不做任何清理/复制（不产出半份产物）。
  if (!fs.existsSync(distRootDir)) {
    console.error('[sync-templates] web/dist 不存在，请先执行 modern build（如 pnpm build）；本次未做资产清理/复制');
    process.exit(1);
  }
  const allFiles = collectFiles(distRootDir);
  if (allFiles.length === 0) {
    console.error('[sync-templates] web/dist 为空目录，请先执行 modern build（如 pnpm build）；本次未做资产清理/复制');
    process.exit(1);
  }

  const copyFiles = allFiles.filter((rel) => !isExcluded(rel));
  const skippedCount = allFiles.length - copyFiles.length;

  // 清理目标目录：除 .gitkeep 外全删（避免旧 hash 文件残留堆积），清空重拷保证幂等。
  fs.mkdirSync(assetsDistDir, { recursive: true });
  for (const item of fs.readdirSync(assetsDistDir, { withFileTypes: true })) {
    if (item.name === KEEP_FILE) continue;
    fs.rmSync(path.join(assetsDistDir, item.name), { recursive: true, force: true });
  }

  for (const rel of copyFiles) {
    const dest = path.join(assetsDistDir, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(distRootDir, rel), dest);
  }

  // .gitkeep 保全：复制完成后确保在场（被意外删除则重建空文件）。
  const keepPath = path.join(assetsDistDir, KEEP_FILE);
  if (!fs.existsSync(keepPath)) fs.writeFileSync(keepPath, '');

  console.log(
    `[sync-templates] 资产同步完成：${copyFiles.length} 个文件已复制到 server/assets/dist（剔除 ${skippedCount} 个：html 模板源 / *.map / 根级 *.json），.gitkeep 在场`,
  );
} catch (err) {
  console.error(`[sync-templates] 资产复制失败：${err?.message ?? err}`);
  process.exit(1);
}
