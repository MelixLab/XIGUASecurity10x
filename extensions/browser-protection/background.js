// XIGUA 浏览器防护 - 后台服务
let stats = { total: 0, sites: [] };

// 监听拦截事件
chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
  const url = info.request.url;
  stats.total++;
  stats.sites.push({ url, time: Date.now() });
  if (stats.sites.length > 100) stats.sites = stats.sites.slice(-100);
  chrome.storage.local.set({ stats });
  console.log(`[XIGUA] 已拦截: ${url}`);
});

// 初始化
chrome.runtime.onInstalled.addListener(() => {
  console.log(`[XIGUA] 浏览器防护 v${chrome.runtime.getManifest().version} 已安装`);
  chrome.storage.local.get({ stats: { total: 0, sites: [] } }, (data) => { stats = data.stats; });
});

chrome.storage.local.get({ stats: { total: 0, sites: [] } }, (data) => { stats = data.stats; });

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getStats') sendResponse(stats);
  return true;
});
