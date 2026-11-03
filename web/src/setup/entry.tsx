/**
 * setup entry 挂载（docs/前端架构.md §6b）：读注入变量 → 设运行期资源基址 →
 * createRoot 挂载安装页。不依赖 Modern.js 运行时能力（无路由 / i18n / SSR）。
 */
import { createRoot } from 'react-dom/client';
import { loadSetupInit } from './bootstrap';
import SetupPage from './pages/SetupPage';

declare global {
  var __webpack_public_path__: string;
}

const init = loadSetupInit();
// §1.5：在任何动态 import() 之前把 __webpack_public_path__ 设为 static_base
//（已归一为以 / 结尾）；本 entry 无动态 chunk，该值为后续扩展预留。
__webpack_public_path__ = init.staticBase;

const container = document.getElementById('root');
if (container) {
  createRoot(container).render(<SetupPage alRoot={init.alRoot} />);
}
