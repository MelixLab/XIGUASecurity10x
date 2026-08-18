// XIGUA 浏览器防护 - 弹出窗口
document.addEventListener('DOMContentLoaded', () => {
  // 获取拦截统计
  chrome.runtime.sendMessage({ type: 'getStats' }, (stats) => {
    if (stats) {
      document.getElementById('blockedCount').textContent = stats.total || 0;
    }
  });

  // 显示规则数量（硬编码，与 background.js 一致）
  document.getElementById('ruleCount').textContent = '35';
});
