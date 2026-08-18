// Minimal TypeScript entry point for vite build
// The actual UI is in suspicious-intercept.html (loaded as a Tauri window)
document.addEventListener('DOMContentLoaded', () => {
    const app = document.getElementById('app');
    if (app) {
        app.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:#616161;font-size:14px;font-family:Segoe UI,sans-serif"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#10b981;margin-right:6px;animation:pulse 2s ease-in-out infinite"></span>可疑文件拦截保护运行中</div>';
    }
});
