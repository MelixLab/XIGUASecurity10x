// ==========================================================================
// XIGUASecurity 10x — 新 UI 功能桥接层
// 基于 新UI 项目的 index.html + style.css + main.js（100% 还原），
// 此处补充新 UI 未包含的功能：真实数据、通知中心（公告系统）、工具箱、
// 云平台、高级设置、安全日志、隔离区、防护状态同步等。
// ==========================================================================

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";

declare global {
  interface Window {
    __TAURI__: any;
  }
}

const $ = (sel: string): HTMLElement | null => document.querySelector(sel);
const $$ = (sel: string): NodeListOf<HTMLElement> => document.querySelectorAll(sel);

// Toast 通知
function showToast(msg: string, duration = 3000) {
  const existing = $('#toast-container');
  let container = existing;
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:99999;display:flex;flex-direction:column;gap:8px;pointer-events:none';
    document.body.appendChild(container);
  }
  const el = document.createElement('div');
  el.textContent = msg;
  el.style.cssText = 'background:#323232;color:#fff;padding:10px 24px;border-radius:8px;font-size:14px;font-family:"Segoe UI","Microsoft YaHei UI",system-ui,sans-serif;box-shadow:0 4px 16px rgba(0,0,0,0.2);pointer-events:auto;animation:toast-in 0.3s ease';
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity 0.3s';
    setTimeout(() => el.remove(), 300);
  }, duration);
}

// 自定义选择弹窗：返回 Promise<number>，表示用户点击的按钮索引（与 buttons 对应）。
// 用纯 DOM 实现，不依赖系统 alert/confirm（避免 Tauri 权限拦截）。
function showChoiceDialog(message: string, buttons: { text: string; primary?: boolean }[]): Promise<number> {
  return new Promise((resolve) => {
    const mask = document.createElement('div');
    mask.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:100000;display:flex;align-items:center;justify-content:center;animation:fade-in 0.2s ease;';
    const box = document.createElement('div');
    box.style.cssText = 'background:#fff;border-radius:12px;padding:24px 28px;max-width:400px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,0.25);font-family:"Segoe UI","Microsoft YaHei UI",system-ui,sans-serif;-webkit-font-smoothing:antialiased;';
    const title = document.createElement('div');
    title.style.cssText = 'font-size:16px;font-weight:600;color:#1a1a1a;margin-bottom:12px;font-family:"Segoe UI","Microsoft YaHei UI",system-ui,sans-serif;';
    title.textContent = '选择防护方案';
    const msg = document.createElement('div');
    msg.style.cssText = 'font-size:14px;line-height:1.6;color:#444;margin-bottom:20px;font-family:"Segoe UI","Microsoft YaHei UI",system-ui,sans-serif;';
    msg.textContent = message;
    box.appendChild(title);
    box.appendChild(msg);
    const btnRow = document.createElement('div');
    btnRow.style.cssText = 'display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap;';
    buttons.forEach((b, idx) => {
      const btn = document.createElement('button');
      btn.textContent = b.text;
      btn.style.cssText = `padding:9px 18px;border-radius:8px;font-size:14px;cursor:pointer;font-family:"Segoe UI","Microsoft YaHei UI",system-ui,sans-serif;border:1px solid ${b.primary ? '#0067C0' : '#d0d0d0'};background:${b.primary ? '#0067C0' : '#fff'};color:${b.primary ? '#fff' : '#333'};`;
      btn.addEventListener('click', () => {
        mask.remove();
        resolve(idx);
      });
      btnRow.appendChild(btn);
    });
    box.appendChild(btnRow);
    mask.appendChild(box);
    mask.addEventListener('click', (e) => {
      if (e.target === mask) { mask.remove(); resolve(-1); }
    });
    document.body.appendChild(mask);
  });
}

// ========== 多语言（中 / 英 / 繁） ==========
type LangKey = 'zh-CN' | 'en' | 'zh-TW';
const I18N: Record<LangKey, Record<string, string>> = {
  'zh-CN': {
    'nav.home': '概览', 'nav.scan': '病毒扫描', 'nav.protection': '实时防护', 'nav.quarantine': '隔离区', 'nav.logs': '安全日志', 'nav.settings': '设置',
    'home.title': '设备已受到保护', 'home.sub': '所有防护功能均已在此设备上启用', 'home.statusOn': '实时防护已开启 · 病毒库已是最新', 'home.statusOff': '实时防护未完全开启，建议检查防护设置',
    'home.titlePartial': '设备已受到保护', 'home.subPartial': '核心防护已开启，部分可选功能未完全开启', 'home.subPartialList': '核心防护已开启，以下功能未开启：', 'home.statusPartial': '核心防护已开启 · 部分可选功能未开启',
    'home.actionNeeded': '需要执行操作', 'home.actionNeededSub': '您可能需要开启部分防护',
    'home.protectionOff': '防护已关闭', 'home.protectionOffSub': '驱动防护已禁用，您的系统存在风险',
    'home.suggestionTitle': '需要执行操作', 'home.suggestionFooter': '点击前往防护页面启用所有防护',
    'home.prot.driver': '驱动防护', 'home.prot.web': '网页防护', 'home.prot.network': '网络安全',
    'home.prot.kernel': '驱动/端点防护', 'home.prot.endpoint': '端点防护', 'home.prot.basic': '实时防护', 'home.prot.identity': '身份防护',
    'home.prot.file': '文件防护', 'home.prot.scriptScan': '脚本扫描', 'home.prot.cloudHash': '云端哈希',
    'home.prot.cloudQuery': '云查询',
    'home.quickScan': '快速扫描', 'home.threatsBlocked': '已拦截威胁', 'home.filesScanned': '已扫描文件', 'home.daysProtected': '已保护天数',
    'home.threatStopped': '威胁防护已停止', 'home.threatStoppedSub': '实时防护已关闭，您的系统存在风险', 'home.actionStart': '立即启动防护', 'home.actionEnablePartial': '启用部分防护',
    'scan.title': '病毒扫描', 'scan.sub': '选择扫描类型以检查您的系统', 'scan.quick': '快速扫描', 'scan.quickDesc': '扫描关键系统区域，约需 1-2 分钟',
    'scan.full': '全盘扫描', 'scan.fullDesc': '深度扫描所有文件，约需 15-30 分钟', 'scan.custom': '自定义扫描', 'scan.customDesc': '选择特定文件夹进行扫描',
    'scan.scanning': '正在扫描...', 'scan.preparing': '准备扫描...', 'scan.stop': '停止', 'scan.threats': '威胁', 'scan.scanned': '已扫描',
    'scan.totalFiles': '总文件', 'scan.speed': '速度', 'scan.elapsed': '用时', 'scan.noThreatsYet': '尚未发现威胁', 'scan.handle': '处理',
    'scan.done': '完成', 'scan.noThreatsFound': '未发现威胁', 'scan.deviceSecure': '您的设备很安全', 'scan.engineFooter': '威胁检测引擎 · HeySafe ML x 云端哈希',
    'prot.title': '防护', 'prot.sub': '管理实时安全功能', 'prot.driver': '驱动防护', 'prot.driverDesc': '通过 XIGUASecurityAgent 提供内核级防护',
    'prot.basic': '基础防护', 'prot.basicDesc': '实时监控文件和进程', 'prot.web': '脚本防护', 'prot.webDesc': '阻止恶意脚本和网页下载',
    'prot.network': '网络安全', 'prot.networkDesc': '监控网络流量中的可疑活动', 'prot.identity': '文件防护', 'prot.identityDesc': '保护文件免受篡改和勒索',
    'prot.endpointConfig': '设置', 'prot.back': '返回防护', 'prot.endpointTitle': '端点防护规则', 'prot.endpointSub': '管理 HIPS 防护规则、文件信任与运行时设置',
    'prot.connectionStatus': '防护连接状态', 'prot.driverStatus': '驱动防护（AVModel/Agent）', 'prot.serviceStatus': '端点防护服务（Melix.Service）', 'prot.totalProtection': '总防护状态',
    'prot.addRule': '添加规则', 'prot.refresh': '刷新', 'prot.deleteRule': '删除', 'prot.ruleType': '类型', 'prot.ruleAction': '动作', 'prot.ruleNote': '备注',
    'prot.noRules': '暂无规则，点击“添加规则”创建第一条 HIPS 防护规则', 'prot.loadingRules': '正在加载防护规则...', 'prot.rulesLoadFailed': '加载规则失败：请确认端点防护服务已启动（Melix.Service）',
    'prot.ruleName': '规则名称/行为', 'prot.ruleActor': '主体路径', 'prot.ruleTarget': '目标路径', 'prot.ruleCmd': '命令行特征', 'prot.ruleChoose': '选择', 'prot.ruleCancel': '取消', 'prot.ruleSave': '保存',
    'prot.rulesServiceNotRunning': '端点防护服务未运行，无法管理规则',
    'prot.manageRules': '规则管理', 'prot.manageRulesDesc': '查看/新增/删除 HIPS 防护规则',
    'prot.manageSettings': '端点防护设置', 'prot.manageSettingsDesc': '防护维度与 AI 研判配置',
    'prot.manageTrust': '文件信任中心', 'prot.manageTrustDesc': '管理放行文件与信任列表',
    'prot.manageChain': '行为链', 'prot.manageChainDesc': '进程链 / 攻击链分析',
    'prot.manageComposite': '组合规则', 'prot.manageCompositeDesc': 'IOA / EDR 组合规则管理',
    'prot.manageLog': '拦截记录', 'prot.manageLogDesc': '查看历史拦截与审计',
    'prot.interceptLog': '端点防护拦截日志', 'prot.clearLog': '清空',
    'quar.title': '隔离区', 'quar.sub': '管理被隔离的威胁和可疑文件', 'quar.emptyTitle': '未发现威胁', 'quar.emptyDesc': '被隔离的项目将显示在这里',
    'logs.title': '事件日志', 'logs.sub': '查看安全事件和扫描历史', 'logs.clear': '清空全部', 'logs.export': '导出', 'logs.loading': '加载中...',
    'settings.title': '设置', 'settings.sub': '配置 XIGUASecurity 偏好',
    'settings.general': '通用', 'settings.protection': '防护', 'settings.scan': '扫描', 'settings.whitelistGroup': '白名单', 'settings.rules': '病毒库', 'settings.preferences': '偏好',
    'settings.whitelistManage': '管理',
    'settings.themeMode': '主题模式', 'settings.themeModeDesc': '浅色 / 深色 / 经典外观', 'settings.windowStyle': '窗口样式', 'settings.windowStyleDesc': '无 / 亚克力 / 云母 / 云母变体',
    'settings.startWithWin': '开机自启', 'settings.startWithWinDesc': '系统启动时自动运行',
    'settings.fileProtection': '文件防护', 'settings.fileProtectionDesc': '保护文件免受篡改和勒索',
    'settings.scriptScan': '脚本扫描', 'settings.scriptScanDesc': '实时检测恶意脚本',
    'settings.cloudHash': '云端哈希扫描', 'settings.cloudHashDesc': '查询云端哈希库识别未知文件',
    'settings.cloudQuery': '云查询辅助', 'settings.cloudQueryDesc': '启用云端辅助威胁分析',
    'settings.whitelist': '进程白名单', 'settings.whitelistDesc': '白名单中的进程不会被拦截', 'settings.whitelistPlaceholder': '输入进程名，如: notepad.exe',
    'settings.whitelistAdd': '添加', 'settings.whitelistEmpty': '暂无白名单进程',
    'settings.rulesVersion': '病毒库版本', 'settings.rulesUpdate': '检查更新', 'settings.rulesUpdated': '病毒库已是最新版本',
    'settings.theme': '主题色', 'settings.themeDesc': '选择主题颜色', 'settings.language': '语言', 'settings.languageDesc': '界面显示语言',
    'settings.customBg': '自定义背景', 'settings.customBgDesc': '为应用设置自定义背景图片', 'settings.customBgBtn': '选择图片',
    'settings.about': '关于', 'settings.version': '版本', 'settings.aboutDesc': '一款自研的杀毒软件，提供病毒扫描、实时防护与云端查杀能力',
    'settings.currentVersion': '当前软件版本', 'settings.checkUpdate': '软件检查更新', 'settings.checkUpdateDesc': '检查是否有可用更新', 'settings.checkUpdateBtn': '检查更新',
    'settings.sponsor': '赞助', 'settings.feedback': '反馈问题',
    'settings.endpointProtection': '增强端点防护', 'settings.endpointProtectionDesc': '基于驱动级端点监控拦截高级威胁，带来更强的防护效果',
    'settings.ransomware': '勒索软件防护', 'settings.ransomwareDesc': '实时检测并回滚勒索软件攻击',
    'settings.archiveScan': '扫描压缩包', 'settings.archiveScanDesc': '在扫描中包含压缩归档文件',
    'settings.resetOptions': '重置选项', 'settings.resetOptionsDesc': '将应用重置回首次启动设置向导',
    'settings.resetOOBE': '重置为首启向导',
    'settings.sponsorDesc': '赞助支持开发者',
    'settings.feedbackDesc': '反馈问题与建议',
    'sponsorDialogTitle': '需要赞助开发者吗？',
    'sponsorDialogText': '赞助可以帮助我们更好地开发软件，持续的赞助将用于服务器维护、功能开发与安全研究。感谢您的支持！',
    'sponsorConfirm': '去赞助',
    'sponsorCancel': '暂不',
    'menu.chat': '云平台', 'menu.toolbox': '工具箱', 'menu.advanced': '高级设置', 'menu.engine': '引擎概览', 'menu.demo': '演示模式',
    'notif.title': '通知中心', 'notif.sub': '安全事件与系统通知', 'notif.empty': '暂无通知', 'notif.emptyDesc': '安全事件和系统通知将显示在这里',
    'notif.allRead': '全部已读', 'notif.clear': '清空',
    'toolbox.title': '工具箱', 'toolbox.sub': '实用的系统安全工具', 'toolbox.back': '返回工具箱',
    'toolbox.popup': '弹窗拦截器', 'toolbox.popupDesc': '拦截恶意弹窗广告', 'toolbox.cleaner': '垃圾清理', 'toolbox.cleanerDesc': '清理系统临时文件和缓存',
    'toolbox.process': '进程管理器', 'toolbox.processDesc': '查看和管理运行中的进程', 'toolbox.edr': 'EDR 报告', 'toolbox.edrDesc': '查看行为拦截与威胁处理历史',
    'toolbox.repair': '系统修复', 'toolbox.repairDesc': '扫描并修复系统安全配置',
    'advanced.title': '高级设置', 'advanced.sub': '扩展设置项（新 UI 未包含的功能）',
  },
  en: {
    'nav.home': 'Home', 'nav.scan': 'Scan', 'nav.protection': 'Protection', 'nav.quarantine': 'Quarantine', 'nav.logs': 'Logs', 'nav.settings': 'Settings',
    'home.title': 'Protected', 'home.sub': 'All protection features are active on this device', 'home.statusOn': 'Real-time protection on · Definitions up to date', 'home.statusOff': 'Real-time protection is not fully enabled',
    'home.titlePartial': 'Protected', 'home.subPartial': 'Core protection is active · Some optional features are off', 'home.subPartialList': 'Core protection active, these are off: ', 'home.statusPartial': 'Core protection active · Some optional features off',
    'home.actionNeeded': 'Action Required', 'home.actionNeededSub': 'You may need to enable some protection',
    'home.protectionOff': 'Protection Off', 'home.protectionOffSub': 'Driver protection is disabled, your system is at risk',
    'home.suggestionTitle': 'Action Required', 'home.suggestionFooter': 'Go to Protection page to enable all',
    'home.prot.driver': 'Driver Protection', 'home.prot.web': 'Web Protection', 'home.prot.network': 'Network Security',
    'home.prot.kernel': 'Driver/Endpoint Protection', 'home.prot.endpoint': 'Endpoint Protection', 'home.prot.basic': 'Real-time Protection', 'home.prot.identity': 'Identity Protection',
    'home.prot.file': 'File Protection', 'home.prot.scriptScan': 'Script Scan', 'home.prot.cloudHash': 'Cloud Hash',
    'home.prot.cloudQuery': 'Cloud Query',
    'home.quickScan': 'Quick Scan', 'home.threatsBlocked': 'Threats Blocked', 'home.filesScanned': 'Files Scanned', 'home.daysProtected': 'Days Protected',
    'home.threatStopped': 'Threat Protection Stopped', 'home.threatStoppedSub': 'Real-time protection is off, your system is at risk', 'home.actionStart': 'Start Protection', 'home.actionEnablePartial': 'Enable Partial Protection',
    'scan.title': 'Virus Scan', 'scan.sub': 'Select a scan type to check your system', 'scan.quick': 'Quick Scan', 'scan.quickDesc': 'Scan critical system areas, takes 1-2 minutes',
    'scan.full': 'Full Scan', 'scan.fullDesc': 'Deep scan all files, takes 15-30 minutes', 'scan.custom': 'Custom Scan', 'scan.customDesc': 'Select specific folders to scan',
    'scan.scanning': 'Scanning...', 'scan.preparing': 'Preparing to scan...', 'scan.stop': 'Stop', 'scan.threats': 'Threats', 'scan.scanned': 'Scanned',
    'scan.totalFiles': 'Total Files', 'scan.speed': 'Speed', 'scan.elapsed': 'Elapsed', 'scan.noThreatsYet': 'No threats detected yet', 'scan.handle': 'Handle',
    'scan.done': 'Done', 'scan.noThreatsFound': 'No threats found', 'scan.deviceSecure': 'Your device is secure', 'scan.engineFooter': 'Threat detection engine · HeySafe ML x Cloud Hash',
    'prot.title': 'Protection', 'prot.sub': 'Manage real-time security features', 'prot.driver': 'Driver Protection', 'prot.driverDesc': 'Kernel-level protection via XIGUASecurityAgent',
    'prot.basic': 'Real-time Protection', 'prot.basicDesc': 'Monitors files and processes in real-time', 'prot.web': 'Script Protection', 'prot.webDesc': 'Blocks malicious scripts and downloads',
    'prot.network': 'Network Security', 'prot.networkDesc': 'Monitors network traffic for suspicious activity', 'prot.identity': 'File Protection', 'prot.identityDesc': 'Protects files from tampering and ransomware',
    'prot.endpointConfig': 'Settings', 'prot.back': 'Back to Protection', 'prot.endpointTitle': 'Endpoint Protection Rules', 'prot.endpointSub': 'Manage HIPS rules, trust list and runtime settings',
    'prot.connectionStatus': 'Protection Connection Status', 'prot.driverStatus': 'Driver Protection (AVModel/Agent)', 'prot.serviceStatus': 'Endpoint Service (Melix.Service)', 'prot.totalProtection': 'Total Protection',
    'prot.addRule': 'Add Rule', 'prot.refresh': 'Refresh', 'prot.deleteRule': 'Delete', 'prot.ruleType': 'Type', 'prot.ruleAction': 'Action', 'prot.ruleNote': 'Note',
    'prot.noRules': 'No rules yet. Click "Add Rule" to create the first HIPS rule.', 'prot.loadingRules': 'Loading rules...', 'prot.rulesLoadFailed': 'Failed to load rules: make sure the endpoint protection service (Melix.Service) is running.',
    'prot.ruleName': 'Rule / Behavior', 'prot.ruleActor': 'Actor path', 'prot.ruleTarget': 'Target path', 'prot.ruleCmd': 'Command line pattern', 'prot.ruleChoose': 'Choose', 'prot.ruleCancel': 'Cancel', 'prot.ruleSave': 'Save',
    'prot.rulesServiceNotRunning': 'Endpoint protection service is not running.',
    'prot.manageRules': 'Rule Management', 'prot.manageRulesDesc': 'View / add / delete HIPS rules',
    'prot.manageSettings': 'Endpoint Settings', 'prot.manageSettingsDesc': 'Protection dimensions & AI review',
    'prot.manageTrust': 'Trust Center', 'prot.manageTrustDesc': 'Manage allowed files and trust list',
    'prot.manageChain': 'Behavior Chain', 'prot.manageChainDesc': 'Process chain / attack chain analysis',
    'prot.manageComposite': 'Composite Rules', 'prot.manageCompositeDesc': 'IOA / EDR composite rule management',
    'prot.manageLog': 'Intercept Log', 'prot.manageLogDesc': 'View history intercepts and audit',
    'prot.interceptLog': 'Endpoint Protection Intercept Log', 'prot.clearLog': 'Clear',
    'quar.title': 'Quarantine', 'quar.sub': 'Manage isolated threats and suspicious files', 'quar.emptyTitle': 'No Threats Detected', 'quar.emptyDesc': 'Your quarantined items will appear here',
    'logs.title': 'Event Logs', 'logs.sub': 'View security events and scan history', 'logs.clear': 'Clear All', 'logs.export': 'Export', 'logs.loading': 'Loading...',
    'settings.title': 'Settings', 'settings.sub': 'Configure XIGUASecurity preferences',
    'settings.general': 'General', 'settings.protection': 'Protection', 'settings.scan': 'Scan', 'settings.whitelistGroup': 'Whitelist', 'settings.rules': 'Rules', 'settings.preferences': 'Preferences',
    'settings.whitelistManage': 'Manage',
    'settings.themeMode': 'Theme Mode', 'settings.themeModeDesc': 'Colorful / Dark / Classic', 'settings.windowStyle': 'Window Style', 'settings.windowStyleDesc': 'None / Acrylic / Mica / Mica Alt',
    'settings.startWithWin': 'Start with Windows', 'settings.startWithWinDesc': 'Automatically launch on system startup',
    'settings.fileProtection': 'File Protection', 'settings.fileProtectionDesc': 'Protect files from tampering and ransomware',
    'settings.scriptScan': 'Script Scanning', 'settings.scriptScanDesc': 'Detect malicious scripts in real-time',
    'settings.cloudHash': 'Cloud Hash Scanning', 'settings.cloudHashDesc': 'Query cloud hash database for unknown files',
    'settings.cloudQuery': 'Cloud Query Assistant', 'settings.cloudQueryDesc': 'Enable auxiliary cloud-based threat analysis',
    'settings.whitelist': 'Process Whitelist', 'settings.whitelistDesc': 'Whitelisted processes will not be blocked', 'settings.whitelistPlaceholder': 'Enter process name, e.g. notepad.exe',
    'settings.whitelistAdd': 'Add', 'settings.whitelistEmpty': 'No whitelisted processes',
    'settings.rulesVersion': 'Virus Database Version', 'settings.rulesUpdate': 'Check Update', 'settings.rulesUpdated': 'Virus database is up to date',
    'settings.theme': 'Theme Color', 'settings.themeDesc': 'Choose the accent theme color', 'settings.language': 'Language', 'settings.languageDesc': 'Interface display language',
    'settings.customBg': 'Custom Background', 'settings.customBgDesc': 'Set a custom background image for the app', 'settings.customBgBtn': 'Choose Image',
    'settings.about': 'About', 'settings.version': 'Version', 'settings.aboutDesc': 'A self-developed antivirus providing scan, real-time protection and cloud detection',
    'settings.currentVersion': 'Current Version', 'settings.checkUpdate': 'Check for Updates', 'settings.checkUpdateDesc': 'Check for the latest version of the software', 'settings.checkUpdateBtn': 'Check Update',
    'settings.sponsor': 'Sponsor', 'settings.feedback': 'Feedback',
    'settings.endpointProtection': 'Enhanced Endpoint Protection', 'settings.endpointProtectionDesc': 'Advanced kernel-level endpoint monitoring against sophisticated threats',
    'settings.ransomware': 'Ransomware Protection', 'settings.ransomwareDesc': 'Detect and roll back ransomware attacks in real-time',
    'settings.archiveScan': 'Scan Archives', 'settings.archiveScanDesc': 'Include compressed archives in scans',
    'settings.resetOptions': 'Reset Options', 'settings.resetOptionsDesc': 'Reset the application back to first-run setup wizard',
    'settings.resetOOBE': 'Reset to First-Run Setup',
    'settings.sponsorDesc': 'Support the developer',
    'settings.feedbackDesc': 'Report issues and suggestions',
    'sponsorDialogTitle': 'Would you like to sponsor the developer?',
    'sponsorDialogText': 'Sponsorship helps us develop the software better. Ongoing support goes toward server maintenance, feature development, and security research. Thank you for your support!',
    'sponsorConfirm': 'Sponsor',
    'sponsorCancel': 'Not Now',
    'menu.chat': 'Cloud Platform', 'menu.toolbox': 'Toolbox', 'menu.advanced': 'Advanced Settings', 'menu.engine': 'Engine Overview', 'menu.demo': 'Demo Mode',
    'notif.title': 'Notification Center', 'notif.sub': 'Security events and system notifications', 'notif.empty': 'No notifications', 'notif.emptyDesc': 'Security events will appear here',
    'notif.allRead': 'Mark all read', 'notif.clear': 'Clear',
    'toolbox.title': 'Toolbox', 'toolbox.sub': 'Useful system security tools', 'toolbox.back': 'Back to Toolbox',
    'toolbox.popup': 'Popup Blocker', 'toolbox.popupDesc': 'Block malicious popup ads', 'toolbox.cleaner': 'Junk Cleaner', 'toolbox.cleanerDesc': 'Clean temp files and cache',
    'toolbox.process': 'Process Manager', 'toolbox.processDesc': 'View and manage running processes', 'toolbox.edr': 'EDR Reports', 'toolbox.edrDesc': 'View interception and threat history',
    'toolbox.repair': 'System Repair', 'toolbox.repairDesc': 'Scan and fix system security issues',
    'advanced.title': 'Advanced Settings', 'advanced.sub': 'Extended settings (not in the new UI)',
  },
  'zh-TW': {
    'nav.home': '概覽', 'nav.scan': '病毒掃描', 'nav.protection': '實時防護', 'nav.quarantine': '隔離區', 'nav.logs': '安全日誌', 'nav.settings': '設置',
    'home.title': '設備已受到保護', 'home.sub': '所有防護功能均已在此設備上啟用', 'home.statusOn': '實時防護已開啟 · 病毒庫已是最新', 'home.statusOff': '實時防護未完全開啟，建議檢查防護設定',
    'home.titlePartial': '設備已受到保護', 'home.subPartial': '核心防護已開啟，部分可選功能未完全開啟', 'home.subPartialList': '核心防護已開啟，以下功能未開啟：', 'home.statusPartial': '核心防護已開啟 · 部分可選功能未開啟',
    'home.actionNeeded': '需要執行操作', 'home.actionNeededSub': '您可能需要開啟部分防護',
    'home.protectionOff': '防護已關閉', 'home.protectionOffSub': '驅動防護已禁用，您的系統存在風險',
    'home.suggestionTitle': '需要執行操作', 'home.suggestionFooter': '點擊前往防護頁面啟用所有防護',
    'home.prot.driver': '驅動防護', 'home.prot.web': '網頁防護', 'home.prot.network': '網路安全',
    'home.prot.kernel': '驅動/端點防護', 'home.prot.endpoint': '端點防護', 'home.prot.basic': '即時防護', 'home.prot.identity': '身份防護',
    'home.prot.file': '檔案防護', 'home.prot.scriptScan': '腳本掃描', 'home.prot.cloudHash': '雲端哈希',
    'home.prot.cloudQuery': '雲查詢',
    'home.quickScan': '快速掃描', 'home.threatsBlocked': '已攔截威脅', 'home.filesScanned': '已掃描檔案', 'home.daysProtected': '已保護天數',
    'home.threatStopped': '威脅防護已停止', 'home.threatStoppedSub': '即時防護已關閉，您的系統存在風險', 'home.actionStart': '立即啟動防護', 'home.actionEnablePartial': '啟用部分防護',
    'scan.title': '病毒掃描', 'scan.sub': '選擇掃描類型以檢查您的系統', 'scan.quick': '快速掃描', 'scan.quickDesc': '掃描關鍵系統區域，約需 1-2 分鐘',
    'scan.full': '全盤掃描', 'scan.fullDesc': '深度掃描所有檔案，約需 15-30 分鐘', 'scan.custom': '自訂掃描', 'scan.customDesc': '選擇特定資料夾進行掃描',
    'scan.scanning': '正在掃描...', 'scan.preparing': '準備掃描...', 'scan.stop': '停止', 'scan.threats': '威脅', 'scan.scanned': '已掃描',
    'scan.totalFiles': '總檔案', 'scan.speed': '速度', 'scan.elapsed': '用時', 'scan.noThreatsYet': '尚未發現威脅', 'scan.handle': '處理',
    'scan.done': '完成', 'scan.noThreatsFound': '未發現威脅', 'scan.deviceSecure': '您的裝置很安全', 'scan.engineFooter': '威脅檢測引擎 · HeySafe ML x 雲端哈希',
    'prot.title': '防護', 'prot.sub': '管理實時安全功能', 'prot.driver': '驅動防護', 'prot.driverDesc': '通過 XIGUASecurityAgent 提供內核級防護',
    'prot.basic': '基礎防護', 'prot.basicDesc': '實時監控檔案和進程', 'prot.web': '腳本防護', 'prot.webDesc': '阻止惡意腳本和網頁下載',
    'prot.network': '網路安全', 'prot.networkDesc': '監控網路流量中的可疑活動', 'prot.identity': '檔案防護', 'prot.identityDesc': '保護檔案免受篡改和勒索',
    'prot.endpointConfig': '設定', 'prot.back': '返回防護', 'prot.endpointTitle': '端點防護規則', 'prot.endpointSub': '管理 HIPS 防護規則、檔案信任與執行時設定',
    'prot.connectionStatus': '防護連線狀態', 'prot.driverStatus': '驅動防護（AVModel/Agent）', 'prot.serviceStatus': '端點防護服務（Melix.Service）', 'prot.totalProtection': '總防護狀態',
    'prot.addRule': '新增規則', 'prot.refresh': '重新整理', 'prot.deleteRule': '刪除', 'prot.ruleType': '類型', 'prot.ruleAction': '動作', 'prot.ruleNote': '備註',
    'prot.noRules': '暫無規則，點擊「新增規則」建立第一條 HIPS 防護規則', 'prot.loadingRules': '正在載入防護規則...', 'prot.rulesLoadFailed': '載入規則失敗：請確認端點防護服務已啟動（Melix.Service）',
    'prot.ruleName': '規則名稱/行為', 'prot.ruleActor': '主體路徑', 'prot.ruleTarget': '目標路徑', 'prot.ruleCmd': '命令列特徵', 'prot.ruleChoose': '選擇', 'prot.ruleCancel': '取消', 'prot.ruleSave': '儲存',
    'prot.rulesServiceNotRunning': '端點防護服務未執行，無法管理規則',
    'prot.manageRules': '規則管理', 'prot.manageRulesDesc': '檢視/新增/刪除 HIPS 防護規則',
    'prot.manageSettings': '端點防護設定', 'prot.manageSettingsDesc': '防護維度與 AI 研判設定',
    'prot.manageTrust': '檔案信任中心', 'prot.manageTrustDesc': '管理放行檔案與信任清單',
    'prot.manageChain': '行為鏈', 'prot.manageChainDesc': '進程鏈 / 攻擊鏈分析',
    'prot.manageComposite': '組合規則', 'prot.manageCompositeDesc': 'IOA / EDR 組合規則管理',
    'prot.manageLog': '攔截記錄', 'prot.manageLogDesc': '檢視歷史攔截與稽核',
    'prot.interceptLog': '端點防護攔截日誌', 'prot.clearLog': '清空',
    'quar.title': '隔離區', 'quar.sub': '管理被隔離的威脅和可疑檔案', 'quar.emptyTitle': '未發現威脅', 'quar.emptyDesc': '被隔離的項目將顯示在這裡',
    'logs.title': '事件日誌', 'logs.sub': '查看安全事件和掃描歷史', 'logs.clear': '清空全部', 'logs.export': '匯出', 'logs.loading': '載入中...',
    'settings.title': '設置', 'settings.sub': '配置 XIGUASecurity 偏好',
    'settings.general': '通用', 'settings.protection': '防護', 'settings.scan': '掃描', 'settings.whitelistGroup': '白名單', 'settings.rules': '病毒庫', 'settings.preferences': '偏好',
    'settings.whitelistManage': '管理',
    'settings.themeMode': '主題模式', 'settings.themeModeDesc': '淺色 / 深色 / 經典外觀', 'settings.windowStyle': '視窗樣式', 'settings.windowStyleDesc': '無 / 亞克力 / 雲母 / 雲母變體',
    'settings.startWithWin': '開機自啟', 'settings.startWithWinDesc': '系統啟動時自動執行',
    'settings.fileProtection': '檔案防護', 'settings.fileProtectionDesc': '保護檔案免受篡改和勒索',
    'settings.scriptScan': '腳本掃描', 'settings.scriptScanDesc': '實時檢測惡意腳本',
    'settings.cloudHash': '雲端哈希掃描', 'settings.cloudHashDesc': '查詢雲端哈希庫識別未知檔案',
    'settings.cloudQuery': '雲查詢輔助', 'settings.cloudQueryDesc': '啟用雲端輔助威脅分析',
    'settings.whitelist': '進程白名單', 'settings.whitelistDesc': '白名單中的進程不會被封鎖', 'settings.whitelistPlaceholder': '輸入進程名，如: notepad.exe',
    'settings.whitelistAdd': '新增', 'settings.whitelistEmpty': '暫無白名單進程',
    'settings.rulesVersion': '病毒庫版本', 'settings.rulesUpdate': '檢查更新', 'settings.rulesUpdated': '病毒庫已是最新版本',
    'settings.theme': '主題色', 'settings.themeDesc': '選擇主題顏色', 'settings.language': '語言', 'settings.languageDesc': '介面顯示語言',
    'settings.customBg': '自訂背景', 'settings.customBgDesc': '為應用設定自訂背景圖片', 'settings.customBgBtn': '選擇圖片',
    'settings.about': '關於', 'settings.version': '版本', 'settings.aboutDesc': '一款自研的殺毒軟體，提供病毒掃描、即時防護與雲端查殺能力',
    'settings.currentVersion': '目前軟體版本', 'settings.checkUpdate': '軟體檢查更新', 'settings.checkUpdateDesc': '檢查是否有可用更新', 'settings.checkUpdateBtn': '檢查更新',
    'settings.sponsor': '贊助', 'settings.feedback': '反饋問題',
    'settings.endpointProtection': '增強端點防護', 'settings.endpointProtectionDesc': '基於驅動級端點監控攔截高級威脅，帶來更強的防護效果',
    'settings.ransomware': '勒索軟體防護', 'settings.ransomwareDesc': '即時偵測並回滾勒索軟體攻擊',
    'settings.archiveScan': '掃描壓縮包', 'settings.archiveScanDesc': '在掃描中包含壓縮歸檔檔案',
    'settings.resetOptions': '重置選項', 'settings.resetOptionsDesc': '將應用重置回首次啟動設定精靈',
    'settings.resetOOBE': '重置為首次啟動精靈',
    'settings.sponsorDesc': '贊助支持開發者',
    'settings.feedbackDesc': '反饋問題與建議',
    'sponsorDialogTitle': '需要贊助開發者嗎？',
    'sponsorDialogText': '贊助可以幫助我們更好地開發軟體，持續的贊助將用於伺服器維護、功能開發與安全研究。感謝您的支援！',
    'sponsorConfirm': '去贊助',
    'sponsorCancel': '暫不',
    'menu.chat': '雲平台', 'menu.toolbox': '工具箱', 'menu.advanced': '進階設置', 'menu.engine': '引擎概覽', 'menu.demo': '演示模式',
    'notif.title': '通知中心', 'notif.sub': '安全事件與系統通知', 'notif.empty': '暫無通知', 'notif.emptyDesc': '安全事件和系統通知將顯示在這裡',
    'notif.allRead': '全部已讀', 'notif.clear': '清空',
    'toolbox.title': '工具箱', 'toolbox.sub': '實用的系統安全工具', 'toolbox.back': '返回工具箱',
    'toolbox.popup': '彈窗攔截器', 'toolbox.popupDesc': '攔截惡意彈窗廣告', 'toolbox.cleaner': '垃圾清理', 'toolbox.cleanerDesc': '清理系統暫存檔案和快取',
    'toolbox.process': '進程管理器', 'toolbox.processDesc': '查看和管理執行中的進程', 'toolbox.edr': 'EDR 報告', 'toolbox.edrDesc': '查看行為攔截與威脅處理歷史',
    'toolbox.repair': '系統修復', 'toolbox.repairDesc': '掃描並修復系統安全配置',
    'advanced.title': '進階設置', 'advanced.sub': '擴展設置項（新 UI 未包含的功能）',
  },
};

let currentLang: LangKey = 'zh-CN';

function t(key: string): string {
  const dict = I18N[currentLang] || I18N['zh-CN'];
  return dict[key] || I18N['zh-CN'][key] || key;
}

function applyI18n() {
  const saved = localStorage.getItem('language') as LangKey | null;
  currentLang = (saved && I18N[saved]) ? saved : 'zh-CN';
  document.querySelectorAll<HTMLElement>('[data-i18n]').forEach(el => {
    const k = el.getAttribute('data-i18n')!;
    el.textContent = t(k);
  });
  document.querySelectorAll<HTMLElement>('[data-i18n-ph]').forEach(el => {
    el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph')!));
  });
  document.querySelectorAll<HTMLElement>('.nav-btn[data-page]').forEach(btn => {
    const k = btn.getAttribute('data-label-key');
    if (k) btn.setAttribute('data-label', t(k));
  });
}

// 供 public/js/main.js（新 UI 逻辑）读取翻译文本
(window as any).XG_I18N = { t };

function escapeHtml(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ========== 页面导航（新 UI main.js 的 navigateTo 是闭包内部函数，这里补充） ==========
function navigateTo(pageId: string) {
  $$('.nav-btn[data-page]').forEach(b => b.classList.toggle('active', b.dataset.page === pageId));
  $$('.page').forEach(p => p.classList.toggle('active', p.id === `page-${pageId}`));
}

function switchPage(pageId: string) {
  navigateTo(pageId);
}

// ========== 窗口控制 ==========
function initWindowControls() {
  // 新 UI main.js 已通过 Tauri window API 绑定最小化/关闭（优先使用），此处仅作兜底
  let hasWindowApi = false;
  try {
    hasWindowApi = !!getCurrentWindow();
  } catch {}
  if (hasWindowApi) return;
  $('#minimize_btn')?.addEventListener('click', () => {
    invoke('minimize_window').catch(() => {});
  });
  $('#close_btn')?.addEventListener('click', () => {
    invoke('close_window').catch(() => {});
  });
}

// ========== 标题栏菜单 ==========
function initMenu() {
  const menuBtn = $('#menu-btn');
  const dropdown = $('#menu-dropdown');
  if (!menuBtn || !dropdown) return;
  menuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('open');
  });
  document.addEventListener('click', () => dropdown.classList.remove('open'));

  $('#menu-chat')?.addEventListener('click', () => {
    dropdown.classList.remove('open');
    invoke('open_chat_window').catch(() => {});
  });
  $('#menu-toolbox')?.addEventListener('click', () => {
    dropdown.classList.remove('open');
    switchPage('process');
    renderProcessHome();
  });
  $('#menu-advanced-settings')?.addEventListener('click', () => {
    dropdown.classList.remove('open');
    switchPage('advanced_settings');
    renderAdvancedSettings();
  });
  $('#menu-engine-overview')?.addEventListener('click', () => {
    dropdown.classList.remove('open');
    showEngineOverview();
  });
  $('#menu-demo-mode')?.addEventListener('click', () => {
    dropdown.classList.remove('open');
    alert('演示模式：当前新 UI 为完整版，所有功能均已接入真实防护引擎。');
  });

  // 通知铃铛
  $('#notification-btn')?.addEventListener('click', () => {
    switchPage('notifications');
    renderNotifications();
  });
}

// 更新主页防护状态文案与操作按钮：
//  - 核心防护（驱动/端点）未开启 → "威胁防护已停止"，按钮"立即启动防护"（跳防护页）
//  - 核心防护已开启且可选功能（文件/网络/云端哈希）全开 → "设备已受到保护"，按钮"快速扫描"（跳扫描页）
//  - 核心防护已开启但部分可选功能未开 → "已受保护，部分可选功能未开启"，按钮"启用部分防护"（跳防护页）
// 用"用户配置"判断端点（get_endpoint_protection_enabled），而非后台进程残留，
// 并加防抖避免状态查询抖动导致的标题闪烁。
let _homeStatusDebounce: number | null = null;
function updateHomeProtectionStatus() {
  Promise.allSettled([
    invoke<boolean>('get_driver_protection'),
    invoke<boolean>('get_endpoint_protection_enabled'),
    invoke<any>('get_network_protection_state'),
    invoke<boolean>('get_endpoint_protection_status'),
  ]).then((results) => {
    const driver = results[0].status === 'fulfilled' ? results[0].value : false;
    // 端点防护：只按用户配置（get_endpoint_protection_enabled）判断，不使用后台进程残留状态，
    // 避免用户未开启端点但服务残留导致误判为"已开启"。
    const endpointEnabled = results[1].status === 'fulfilled' ? results[1].value : false;
    // "设备已受到保护"的前提：驱动防护 或 端点防护 二选一（缺一不可）。
    // 仅开启基础防护/文件防护不算完整保护（仍属实时防护的一部分，但无驱动/端点的完整拦截能力）。
    const coreOn = driver || endpointEnabled;
    // 可选防护（非必要项）检查，收集未开启项（文件防护属核心，不列入可选）
    const netState = results[2].status === 'fulfilled' ? results[2].value : null;
    const networkOn = netState && typeof netState.enabled === 'boolean' ? netState.enabled : true;
    const checks = [
      { key: 'network', enabled: networkOn },
      { key: 'cloudHash', enabled: isCloudHashEnabled() },
      { key: 'scriptScan', enabled: localStorage.getItem('script_scan_enabled') !== 'false' },
      { key: 'web', enabled: localStorage.getItem('web_protection_enabled') !== 'false' },
    ];
    const offList = checks.filter(c => !c.enabled);
    const optionalOn = offList.length === 0;
    const apply = () => {
      const titleEl = $('#homeTitle');
      const subEl = $('#homeSub');
      const statusEl = $('#homeStatusText');
      const btnText = $('#homeScanBtnText');
      const btn = $('#homeActionBtn');
      const illus = $('#homeIllustration') as HTMLImageElement | null;
      if (!coreOn) {
        // 防护未开启
        if (titleEl) titleEl.textContent = t('home.threatStopped');
        if (subEl) subEl.textContent = t('home.threatStoppedSub');
        if (statusEl) statusEl.textContent = t('home.statusOff');
        if (btnText) btnText.textContent = t('home.actionStart');
        if (btn) btn.setAttribute('data-page', 'protection');
        if (illus) illus.src = 'illustration-action-needed.svg';
      } else if (optionalOn) {
        // 防护全部开启
        if (titleEl) titleEl.textContent = t('home.title');
        if (subEl) subEl.textContent = t('home.sub');
        if (statusEl) statusEl.textContent = t('home.statusOn');
        if (btnText) btnText.textContent = t('home.quickScan');
        if (btn) btn.setAttribute('data-page', 'scan');
        if (illus) illus.src = 'illustration.svg';
      } else {
        // 核心防护开启，但部分可选功能未开启：小字列出具体未开启项
        if (titleEl) titleEl.textContent = t('home.titlePartial');
        if (subEl) {
          const names = offList.map(c => t('home.prot.' + c.key) || c.key).join('、');
          subEl.textContent = t('home.subPartialList') + names;
        }
        if (statusEl) statusEl.textContent = t('home.statusPartial');
        if (btnText) btnText.textContent = t('home.actionEnablePartial');
        if (btn) btn.setAttribute('data-page', 'protection');
        if (illus) illus.src = 'illustration.svg';
      }
    };
    if (_homeStatusDebounce !== null) window.clearTimeout(_homeStatusDebounce);
    _homeStatusDebounce = window.setTimeout(apply, 400);
  }).catch(() => {});
}

// ========== 主页真实统计 ==========
function initHomeStats() {
  // 兼容旧应用的 installDate key（旧 main.ts 使用），无则初始化
  const installKey = 'installDate';
  let install = localStorage.getItem(installKey) || localStorage.getItem('xigua_install_date');
  if (!install) {
    install = new Date().toISOString();
    localStorage.setItem(installKey, install);
  }
  const days = Math.max(1, Math.floor((Date.now() - new Date(install).getTime()) / 86400000));
  const daysEl = $('#stat-days');
  if (daysEl) daysEl.textContent = String(days);

  // 从本地存储恢复计数
  const blocked = parseInt(localStorage.getItem('xigua_threats_blocked') || '0', 10);

  const refresh = () => {
    updateHomeProtectionStatus();
    // 已扫描文件：优先使用本地累计值（每次扫描完成后累加），驱动统计仅在本地无数据时补充，
    // 避免"驱动未连接 → process_check_count=0 → 主页一直显示 0"。
    let scannedNow = parseInt(localStorage.getItem('xigua_files_scanned') || '0', 10);
    invoke('get_driver_stats').then((stats: any) => {
      if (stats && stats.process_check_count !== undefined && Number(stats.process_check_count) > scannedNow) {
        scannedNow = Number(stats.process_check_count);
        localStorage.setItem('xigua_files_scanned', String(scannedNow));
      }
      const sEl = $('#stat-scanned');
      if (sEl) sEl.textContent = scannedNow.toLocaleString();
    }).catch(() => {
      const sEl = $('#stat-scanned');
      if (sEl) sEl.textContent = scannedNow.toLocaleString();
    });
    const bEl = $('#stat-threats');
    if (bEl) bEl.textContent = blocked.toLocaleString();
  };

  refresh();
  setInterval(refresh, 5000);
}

// ========== 增强端点防护：真实开关逻辑（设置页与防护页共享） ==========
// 端点防护的真实运行状态以后台服务进程为准（get_endpoint_protection_status），
// 而"用户是否已启用"以持久化配置为准（get_endpoint_protection_enabled）。
// 这里统一：切换时先启动/停止，再持久化配置，并同步所有开关 UI。
const endpointToggles: (HTMLInputElement | null)[] = [];

function bindEndpointProtectionToggle(toggle: HTMLInputElement | null) {
  if (!toggle) return;
  if (endpointToggles.includes(toggle)) return;
  endpointToggles.push(toggle);

  toggle.addEventListener('change', () => {
    const enabled = toggle!.checked;
    // 调用真实的启动/停止命令
    if (enabled) {
      // 增强端点防护与驱动防护会互相打架：开启端点防护前先关闭驱动防护，
      // 等驱动防护真正停止后再启动端点防护（避免两者同时占用拦截通道）。
      const startEndpoint = () => {
        invoke('start_endpoint_protection').then(() => {
          invoke('set_endpoint_protection_enabled', { enabled: true }).catch(() => {});
          syncEndpointToggles(true);
          showToast('增强端点防护已启动');
        }).catch((e: any) => {
          console.error('[Bridge] start_endpoint_protection failed:', e);
          showToast('启动端点防护失败，请检查权限');
          syncEndpointToggles(false);
        });
      };
      const doStart = () => {
        invoke<boolean>('get_driver_protection').then((driverOn) => {
          if (driverOn) {
            invoke('set_driver_protection', { enabled: false })
              .then(() => waitDriverStopped(startEndpoint))
              .catch(() => startEndpoint());
          } else {
            startEndpoint();
          }
        }).catch(() => startEndpoint());
      };
      // 弹确认窗口：面向专业人员，询问用户是否确定启用
      showChoiceDialog(
        '增强端点防护面向专业人员，非专业人员建议不要启用此防护。\n确定要启用此防护吗？',
        [{ text: '确定启用', primary: true }, { text: '取消' }]
      ).then((choice) => {
        if (choice === 0) {
          doStart();
        } else {
          // 用户取消：回滚开关
          toggle.checked = false;
          syncEndpointToggles(false);
        }
      });
    } else {
      invoke('stop_endpoint_protection').then(() => {
        invoke('set_endpoint_protection_enabled', { enabled: false }).catch(() => {});
        syncEndpointToggles(false);
        showToast('增强端点防护已停止');
      }).catch((e: any) => {
        console.error('[Bridge] stop_endpoint_protection failed:', e);
        showToast('停止端点防护失败');
        syncEndpointToggles(true);
      });
    }
  });
}

// 等待驱动防护完全停止（轮询 get_driver_protection 直到 false 或超时）
function waitDriverStopped(cb: () => void, tries = 30) {
  if (tries <= 0) { cb(); return; }
  invoke<boolean>('get_driver_protection').then((on) => {
    if (!on) { cb(); return; }
    setTimeout(() => waitDriverStopped(cb, tries - 1), 500);
  }).catch(() => cb());
}

// 等待端点防护完全停止（轮询 get_endpoint_protection_status 直到 false 或超时）
function waitEndpointStopped(cb: () => void, tries = 30) {
  if (tries <= 0) { cb(); return; }
  invoke<boolean>('get_endpoint_protection_status').then((on) => {
    if (!on) { cb(); return; }
    setTimeout(() => waitEndpointStopped(cb, tries - 1), 500);
  }).catch(() => cb());
}

// 同步所有端点防护开关 UI 到指定状态（切换/失败回滚/初始化时使用）
function syncEndpointToggles(enabled: boolean) {
  for (const t of endpointToggles) {
    if (t) t.checked = enabled;
  }
}

// 初始化端点防护状态：UI 跟随"用户是否已启用"；若已启用但真实服务未运行，则自动拉起
function initEndpointProtection() {
  Promise.allSettled([
    invoke<boolean>('get_endpoint_protection_enabled'),
    invoke<boolean>('get_endpoint_protection_status'),
  ]).then(([cfgRes, statusRes]) => {
    const configured = cfgRes.status === 'fulfilled' ? cfgRes.value : false;
    const running = statusRes.status === 'fulfilled' ? statusRes.value : false;
    syncEndpointToggles(configured);
    // 已启用但服务未运行 → 自动拉起（满足"启动程序时自动拉起端点防护"）
    if (configured && !running) {
      invoke('start_endpoint_protection').then(() => {
        console.log('[EndpointProtection] 启动时自动拉起端点防护');
      }).catch((e) => {
        console.error('[EndpointProtection] 启动时自动拉起失败:', e);
      });
    }
  }).catch(() => {
    // 兜底：读本地记忆（与旧应用一致）
    syncEndpointToggles(localStorage.getItem('endpoint_protection_enabled') === 'true');
  });
}

// ========== 防护页状态同步 ==========
function initProtectionPage() {
  // 驱动防护开关：驱动防护与端点防护互斥，只能开一个。
  // 开启驱动防护时，自动关闭端点防护并等它完全停止后再开启驱动防护。
  const driverToggle = document.getElementById('driverProtectionToggle') as HTMLInputElement | null;
  if (driverToggle) {
    invoke<boolean>('get_driver_protection').then((on) => { driverToggle.checked = !!on; }).catch(() => {});
    driverToggle.addEventListener('change', async () => {
      if (driverToggle.checked) {
        const startDriver = () => {
          invoke('set_driver_protection', { enabled: true }).catch((e: any) => {
            console.error('[DriverProtection] start failed:', e);
            driverToggle.checked = false;
          });
        };
        // 若端点防护在运行：先关闭它并等待完全停止，再开启驱动防护
        invoke<boolean>('get_endpoint_protection_status').then((running) => {
          if (running) {
            invoke('set_endpoint_protection_enabled', { enabled: false }).catch(() => {});
            invoke('stop_endpoint_protection').then(() => waitEndpointStopped(startDriver)).catch(() => startDriver());
          } else {
            startDriver();
          }
        }).catch(() => startDriver());
      } else {
        invoke('set_driver_protection', { enabled: false }).catch(() => {
          driverToggle.checked = true;
        });
      }
    });
  }

  // 实时防护（基础防护）：启动/停止 R3 进程监控
  const realtimeToggle = document.getElementById('realtimeProtectionToggle') as HTMLInputElement | null;
  if (realtimeToggle) {
    realtimeToggle.checked = localStorage.getItem('basic_protection_enabled') !== 'false';
    realtimeToggle.addEventListener('change', () => {
      setBasicProtectionEnabled(realtimeToggle.checked);
    });
  }

  // 网页防护（对应旧应用的脚本防护）：真实后端命令
  const webToggle = document.getElementById('webProtectionToggle') as HTMLInputElement | null;
  if (webToggle) {
    invoke('get_script_protection_enabled').then((v: unknown) => {
      webToggle.checked = !!v;
    }).catch(() => {});
    webToggle.addEventListener('change', () => {
      invoke('set_script_protection_enabled', { enabled: webToggle.checked }).catch(() => {
        webToggle.checked = !webToggle.checked;
      });
    });
  }

  // 网络安全：真实后端命令（netproxy 进程）
  const networkToggle = document.getElementById('networkProtectionToggle') as HTMLInputElement | null;
  if (networkToggle) {
    invoke('get_network_protection_state').then((s: any) => {
      if (s && typeof s.enabled === 'boolean') networkToggle.checked = s.enabled;
    }).catch(() => {});
    networkToggle.addEventListener('change', () => {
      invoke('set_network_protection_enabled', { enabled: networkToggle.checked }).catch(() => {
        networkToggle.checked = !networkToggle.checked;
      });
    });
  }

  // 身份防护：本地状态记忆
  const identityToggle = document.getElementById('identityProtectionToggle') as HTMLInputElement | null;
  if (identityToggle) {
    identityToggle.checked = localStorage.getItem('protection_identity') !== 'false';
    identityToggle.addEventListener('change', () => {
      localStorage.setItem('protection_identity', String(identityToggle.checked));
    });
  }

  // 增强端点防护（防护页与设置页共享同一套真实开关逻辑）
  bindEndpointProtectionToggle(document.getElementById('endpoint-protection-toggle-prot') as HTMLInputElement | null);

  // 进入增强端点防护管理页
  $('#endpoint-rules-open')?.addEventListener('click', () => {
    navigateTo('endpoint');
    renderEndpointInterceptLog();
    refreshEndpointStatus();
  });
  // 刷新防护连接状态
  $('#endpoint-status-refresh')?.addEventListener('click', () => refreshEndpointStatus());
  // 端点防护功能入口：规则/设置/信任/行为链/组合规则/拦截记录——由 Melix.UI 原生窗口弹出
  document.querySelectorAll('#page-endpoint .endpoint-card[data-cmd]').forEach(card => {
    card.addEventListener('click', async () => {
      const cmd = card.getAttribute('data-cmd')!;
      try {
        await invoke(cmd);
      } catch (e: any) {
        console.error('[Endpoint] open window failed:', cmd, e);
        showToast('打开失败：' + (e?.message || String(e)));
      }
    });
  });
  // 清空拦截日志
  $('#endpoint-log-clear-btn')?.addEventListener('click', () => {
    localStorage.setItem('xigua_endpoint_log', '[]');
    renderEndpointInterceptLog();
  });
  // 返回防护页
  $('#endpoint-back-btn')?.addEventListener('click', () => navigateTo('protection'));
  // 刷新规则
  $('#endpoint-refresh-btn')?.addEventListener('click', loadEndpointRules);
  // 添加规则
  $('#endpoint-add-rule-btn')?.addEventListener('click', showEndpointAddRuleDialog);

  // 监听 Melix 拦截询问事件（PromptRequest）与拦截通知（BlockNotification）
  setupMelixEventListeners();
}

// ========== 实时文件防护（迁移自旧版 FileProtectionManager） ==========
// 旧版在启动时通过 initFileProtection() 启用文件监听并监听 file-protection-event，
// 新 UI 迁移时遗漏了这部分，导致创建危险文件不再拦截/弹窗。此处补全。
let _fpEnabled = false;
let _fpUnlisten: (() => void) | null = null;

async function initRealtimeFileProtection() {
  // 1. 若用户配置开启文件防护，启动后端文件监听（否则监听不会启动 → 不拦截）
  const fileOn = localStorage.getItem('file_protection_enabled') !== 'false';
  _fpEnabled = fileOn;
  if (fileOn) {
    try {
      await invoke('set_file_protection_enabled', { enabled: true, scope: localStorage.getItem('file_protection_scope') || 'all' });
      console.log('[FileProtection] started (init)');
    } catch (e) {
      console.error('[FileProtection] failed to start:', e);
    }
  }

  // 2. 监听后端文件防护事件
  if (_fpUnlisten) return;
  try {
    // 先排空积压事件，避免启动瞬间旧事件涌入
    invoke('get_file_protection_events', { limit: 256 }).catch(() => {});
    _fpUnlisten = await listen<any>('file-protection-event', (event) => {
      if (!_fpEnabled) return;
      const payload = event.payload || {};
      const path = payload.path || '';
      const threatName = payload.threat_name || '';
      if (!path) return;
      if (threatName) {
        // 后端已判定威胁（如银狐木马）：直接隔离 + 弹窗
        handleRealtimeThreat(path, threatName);
        return;
      }
      // 普通文件：交给扫描流程（复用扫描引擎判断）
      handleRealtimeFileEvent(path);
    });
  } catch (e) {
    console.error('[FileProtection] listen failed:', e);
  }
}

// 文件防护：扫描单个文件（PE/脚本等监控扩展名），命中则隔离 + 弹窗
async function handleRealtimeFileEvent(filePath: string) {
  const lower = filePath.toLowerCase();
  const monitored = lower.endsWith('.exe') || lower.endsWith('.scr') || lower.endsWith('.com')
    || lower.endsWith('.pif') || lower.endsWith('.msi') || lower.endsWith('.msp')
    || lower.endsWith('.js') || lower.endsWith('.jse') || lower.endsWith('.vbs')
    || lower.endsWith('.vbe') || lower.endsWith('.bat') || lower.endsWith('.cmd')
    || lower.endsWith('.sh') || lower.endsWith('.ps1') || lower.endsWith('.hta') || lower.endsWith('.cpl');
  if (!monitored) return;
  try {
    const res: any = await invoke('scan_file_basic', { filePath });
    if (res && res.isThreat) {
      handleRealtimeThreat(filePath, res.threatName || 'Trojan.Generic');
    }
  } catch (e) {
    console.error('[FileProtection] scan failed:', filePath, e);
  }
}

// 文件防护：威胁处理（隔离 + 弹窗）
async function handleRealtimeThreat(filePath: string, threatName: string) {
  let accessDenied = false;
  try {
    const qr: any = await invoke('quarantine_threat_file', { filePath, threatName, threatLevel: 'High' });
    if (qr && qr.reason === 'access_denied') {
      // 文件被活动进程占用，后端已自动弹"活动内存威胁"窗口
      accessDenied = true;
    }
  } catch (e) {
    console.warn('[FileProtection] quarantine threw:', filePath, e);
  }
  if (accessDenied) return;
  try {
    await invoke('show_file_protection_alert', { filePath, virusFamily: threatName });
  } catch (e) {
    console.error('[FileProtection] show alert failed:', filePath, e);
  }
}

// ========== 基础防护（R3 进程监控，完整移植自旧版 BasicProtectionManager） ==========
let _bpEnabled = false;
let _bpMonitoring = false;
let _bpUnlisten: (() => void) | null = null;
let _bpPidInterval: number | null = null;
const _bpScannedPids = new Set<number>();
const _bpScanningPaths = new Set<string>();
const _bpCleanPaths = new Map<string, number>();
const _bpLockedFiles = new Set<string>();
const _bpCleanTTL = 10000;
let _bpWhitelist: string[] = ['predict_onnx.exe'];

async function initBasicProtection() {
  _bpEnabled = localStorage.getItem('basic_protection_enabled') !== 'false';
  if (_bpEnabled) {
    await startBasicMonitoring();
  }
}

function isBasicMonitoringOn() {
  return _bpEnabled && _bpMonitoring;
}

function setBasicProtectionEnabled(enabled: boolean) {
  localStorage.setItem('basic_protection_enabled', String(enabled));
  _bpEnabled = enabled;
  if (enabled) { startBasicMonitoring(); } else { stopBasicMonitoring(); }
  updateHomeProtectionStatus();
}

async function startBasicMonitoring() {
  if (_bpMonitoring) return;
  _bpMonitoring = true;
  try {
    await invoke('start_process_watcher');
  } catch (e) { console.error('[BasicProtection] start watcher failed:', e); }
  try {
    _bpWhitelist = await invoke('get_whitelist_processes_command') || [];
  } catch { _bpWhitelist = ['predict_onnx.exe']; }
  try {
    _bpUnlisten = await listen<any>('process-started', (event) => {
      const payload = event.payload || {};
      handleBasicNewProcess({ pid: payload.pid, name: payload.name || '', path: payload.path || null });
    });
  } catch (e) { console.error('[BasicProtection] listen process-started failed:', e); }
  _bpPidInterval = window.setInterval(() => {
    try {
      invoke('get_running_pids').then((pids: any) => {
        const set = new Set(Array.isArray(pids) ? pids : []);
        for (const pid of _bpScannedPids) { if (!set.has(pid)) _bpScannedPids.delete(pid); }
      }).catch(() => {});
    } catch { /* noop */ }
  }, 30000);
  console.log('[BasicProtection] monitoring started');
}

function stopBasicMonitoring() {
  if (!_bpMonitoring) return;
  _bpMonitoring = false;
  try { invoke('stop_process_watcher').catch(() => {}); } catch {}
  if (_bpUnlisten) { try { _bpUnlisten(); } catch {} _bpUnlisten = null; }
  if (_bpPidInterval) { clearInterval(_bpPidInterval); _bpPidInterval = null; }
  _bpScannedPids.clear();
  _bpCleanPaths.clear();
}

function isSystemOrTrustedProcess(p: { path: string; name: string }): boolean {
  const lower = (p.path || '').toLowerCase().replace(/^[a-z]:/, '');
  if (lower.includes('xiguasecurity')) return true;
  const systemDirs = ['\\windows\\system32', '\\windows\\syswow64', '\\windows\\immersivecontrolpanel', '\\windows\\sysnative', '\\programdata\\microsoft\\', '\\windows defender\\', '\\windows\\explorer.exe'];
  return systemDirs.some(d => lower.startsWith(d));
}

async function handleBasicNewProcess(event: { pid: number; name: string; path: string | null }) {
  if (!isBasicMonitoringOn()) return;
  if (_bpScannedPids.has(event.pid)) return;
  _bpScannedPids.add(event.pid);
  if (!event.path) return;
  const lowerPath = event.path.toLowerCase();
  const now = Date.now();
  if (_bpLockedFiles.has(lowerPath)) {
    await terminateBasicProcess(event.pid, event.name);
    notifyBasicThreat(event.path, '已锁定的威胁文件');
    return;
  }
  if (isSystemOrTrustedProcess({ path: event.path, name: event.name })) return;
  const lastClean = _bpCleanPaths.get(lowerPath);
  if (lastClean && (now - lastClean) < _bpCleanTTL) return;
  const nameLower = event.name.toLowerCase();
  if (_bpWhitelist.some(wp => nameLower === wp.toLowerCase())) { _bpCleanPaths.set(lowerPath, now); return; }
  if (_bpScanningPaths.has(lowerPath)) return;
  _bpScanningPaths.add(lowerPath);
  try {
    await scanBasicProcess({ pid: event.pid, path: event.path, name: event.name });
  } finally {
    _bpScanningPaths.delete(lowerPath);
  }
}

async function scanBasicProcess(process: { pid: number; path: string; name: string }) {
  if (!isBasicMonitoringOn()) return;
  const nameLower = process.name.toLowerCase();
  if (_bpWhitelist.some(wp => nameLower === wp.toLowerCase())) { _bpCleanPaths.set(process.path.toLowerCase(), Date.now()); return; }
  try {
    if (_bpLockedFiles.has(process.path.toLowerCase())) {
      await terminateBasicProcess(process.pid, process.name);
      notifyBasicThreat(process.path, '已锁定的威胁文件');
      return;
    }
    // 脚本文件：走脚本引擎
    if (isScriptFile(process.path)) {
      if (localStorage.getItem('script_scan_enabled') !== 'false') {
        try {
          const scriptRes: any = await invoke('scan_script_file_command', { filePath: process.path });
          if (scriptRes && scriptRes.is_malicious) {
            const tn = scriptRes.virus_family || 'Trojan.Win32.BAT.Generic';
            _bpCleanPaths.delete(process.path.toLowerCase());
            _bpLockedFiles.add(process.path.toLowerCase());
            await terminateBasicProcess(process.pid, process.name);
            notifyBasicThreat(process.path, tn);
            return;
          }
        } catch (e) { console.error('[BasicProtection] script scan error:', process.path, e); }
      }
      _bpCleanPaths.set(process.path.toLowerCase(), Date.now());
      return;
    }
    // 云端哈希优先
    if (isCloudHashEnabled()) {
      try {
        const hashes: (string | null)[] = await invoke('calculate_file_hashes_command', { filePaths: [process.path] });
        const hash = hashes?.[0];
        if (hash) {
          const cloudRes: any = await invoke('cloud_hash_check_command', {
            serverUrl: 'https://cloudapi.xiguastudio.top',
            apiKey: 'scan_dcc33b100b8a485fb099a5dce4c4f486',
            request: { hash },
          });
          if (cloudRes) {
            if (cloudRes.result === 'white') { _bpCleanPaths.set(process.path.toLowerCase(), Date.now()); return; }
            if (cloudRes.result === 'black') {
              const tn = cloudRes.family || 'CloudHash';
              _bpCleanPaths.delete(process.path.toLowerCase());
              _bpLockedFiles.add(process.path.toLowerCase());
              await terminateBasicProcess(process.pid, process.name);
              notifyBasicThreat(process.path, tn);
              return;
            }
          }
        }
      } catch (e) { console.error('[BasicProtection] cloud hash failed:', process.name, e); }
    }
    // 本地引擎
    const result: any = await Promise.race([
      invoke('scan_file_basic', { filePath: process.path, pid: process.pid, puaEnabled: localStorage.getItem('pua_protection_enabled') === 'true' }),
      new Promise<any>((_, reject) => setTimeout(() => reject(new Error('scan timeout')), 5000)),
    ]);
    if (result && result.result === 'SUSPICIOUS') return;
    if (result && result.isThreat && result.threatName) {
      if (result.result === 'PUA') return;
      _bpCleanPaths.delete(process.path.toLowerCase());
      _bpLockedFiles.add(process.path.toLowerCase());
      await terminateBasicProcess(process.pid, process.name);
      notifyBasicThreat(process.path, result.threatName);
    } else {
      _bpCleanPaths.set(process.path.toLowerCase(), Date.now());
    }
  } catch (e) {
    console.error('[BasicProtection] scan process failed:', process.name, e);
  }
}

async function terminateBasicProcess(pid: number, processName: string) {
  let killed = false;
  try {
    const driverOn = await invoke<boolean>('get_driver_protection').catch(() => false);
    if (driverOn) {
      try { await invoke('kill_process_via_driver', { pid }); killed = true; } catch {}
    }
  } catch { /* noop */ }
  if (!killed) {
    try { await invoke('terminate_process', { pid }); killed = true; } catch { /* try by name */ }
  }
  if (!killed) {
    try { await invoke('kill_process_by_name_command', { processName: processName.replace(/\.exe$/i, '') }); } catch { /* noop */ }
  }
}

function notifyBasicThreat(path: string, threatName: string) {
  try {
    const processName = path.split('\\').pop() || path.split('/').pop() || 'unknown.exe';
    // 与旧版一致：弹拦截窗口（show_intercept_window），而非 toast
    invoke('show_intercept_window', {
      processName,
      commandLine: path,
      time: new Date().toLocaleString(),
      interceptType: 'basic',
    }).catch((e: any) => console.error('[BasicProtection] show intercept window failed:', e));
    invoke('add_security_log', {
      category: 'Driver', action: 'Blocked', summary: `基础防护拦截: ${threatName}`,
      filePath: path, threatName, result: '已拦截', level: 'High',
    }).catch(() => {});
  } catch { /* noop */ }
}

// ========== Melix 拦截窗口（经 AVGuard 桥接的事件推送） ==========
function setupMelixEventListeners() {
  // PromptRequest：展示拦截询问弹窗，用户裁决后回传
  listen<string>('melix-prompt', (event) => {
    console.log('[Melix] PromptRequest received');
    try {
      const data = typeof event.payload === 'string' ? JSON.parse(event.payload) : event.payload;
      showMelixPrompt(data);
    } catch (e) {
      console.error('[Melix] parse prompt failed:', e);
    }
  }).catch(e => console.error('[Melix] listen prompt failed:', e));

  // BlockNotification：展示拦截通知（无需裁决）
  listen<string>('melix-blocked', (event) => {
    try {
      const data = typeof event.payload === 'string' ? JSON.parse(event.payload) : event.payload;
      showMelixBlocked(data);
    } catch (e) {
      console.error('[Melix] parse blocked failed:', e);
    }
  }).catch(e => console.error('[Melix] listen blocked failed:', e));

  // RulesResponse：更新规则面板（事件驱动，请求只发送、响应异步返回）
  listen<string>('melix-rules', (event) => {
    try {
      const payload = typeof event.payload === 'string' ? event.payload : JSON.stringify(event.payload);
      const parsed = JSON.parse(payload);
      const rules = Array.isArray(parsed?.rules) ? parsed.rules : [];
      renderEndpointRules(rules);
    } catch (e) {
      console.error('[Melix] parse rules failed:', e);
    }
  }).catch(e => console.error('[Melix] listen rules failed:', e));

  // Melix.UI 拦截事件：加入通知中心 + 端点防护拦截日志
  listen<any>('melix-intercepted', (event) => {
    try {
      const d = event.payload;
      const kind = d?.kind === 'prompt' ? '询问' : '已拦截';
      const title = `端点防护${kind}`;
      const msg = (d?.summary) || `检测到可疑行为：${d?.actor || '未知进程'}`;
      addNotification(title, msg, 'system');
      addEndpointLog(d || {});
      console.log('[Melix] intercepted:', msg);
    } catch (e) {
      console.error('[Melix] intercepted notification failed:', e);
    }
  }).catch(e => console.error('[Melix] listen intercepted failed:', e));
}

function parseMelixEvent(data: any): { actorPath: string; target: string; type: string; desc: string; eventId: string } {
  const actorPath = data?.actorPath || data?.processName || data?.actor_path || '未知进程';
  const target = data?.target || data?.targetPath || data?.imagePath || data?.image_path || '';
  const type = data?.type || data?.eventType || '';
  const eventId = data?.eventId || data?.id || data?.securityEventId || '';
  let desc = '';
  if (data?.risk) {
    const risk = data.risk;
    desc = typeof risk === 'string' ? risk : (risk?.description || risk?.label || '');
  }
  if (!desc) desc = data?.description || data?.note || `检测到可疑行为（${type}）`;
  return { actorPath: String(actorPath), target: String(target), type: String(type), desc: String(desc), eventId: String(eventId) };
}

function showMelixPrompt(data: any) {
  const existing = document.getElementById('melix-prompt-modal');
  if (existing) existing.remove();
  const e = parseMelixEvent(data);
  const modal = document.createElement('div');
  modal.id = 'melix-prompt-modal';
  modal.style.cssText = `
    position: fixed; inset: 0; z-index: 10003; background: rgba(0,0,0,0.28);
    display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px);
    font-family: 'Microsoft YaHei UI', 'Microsoft YaHei', 'Segoe UI', system-ui, sans-serif;
  `;
  modal.innerHTML = `
    <div style="background:#fff;border-radius:14px;width:480px;max-width:92%;padding:26px;box-shadow:0 32px 64px rgba(0,0,0,0.25);">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
        <svg viewBox="0 0 24 24" fill="none" stroke="#A80000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:28px;height:28px;flex-shrink:0;"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        <div style="font-size:16px;font-weight:700;color:#1A1A1A;">端点防护拦截</div>
      </div>
      <div style="font-size:13px;color:#5F6B7A;line-height:1.7;margin-bottom:16px;">${escapeHtml(e.desc)}</div>
      <div style="background:#f7f8fa;border-radius:10px;padding:12px 14px;font-size:12px;color:#444;margin-bottom:18px;">
        <div style="margin-bottom:6px;"><b>进程：</b>${escapeHtml(e.actorPath)}</div>
        <div style="margin-bottom:6px;"><b>目标：</b>${escapeHtml(e.target || '—')}</div>
        <div><b>行为：</b>${escapeHtml(e.type || '—')}</div>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px;">
        <button id="mp-allow" style="padding:9px 22px;border:1px solid #d9dee5;border-radius:8px;background:#fff;cursor:pointer;font-size:13px;color:#333;">允许</button>
        <button id="mp-ask" style="padding:9px 22px;border:1px solid #C47800;border-radius:8px;background:#fff;cursor:pointer;font-size:13px;color:#C47800;">继续询问</button>
        <button id="mp-block" style="padding:9px 26px;border:none;border-radius:8px;background:#A80000;color:#fff;cursor:pointer;font-size:13px;font-weight:600;">阻止</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  const close = (action: string) => {
    invoke('melix_prompt_response', { eventId: e.eventId, action, remember: false }).catch(err =>
      console.error('[Melix] prompt response failed:', err));
    modal.remove();
  };
  document.getElementById('mp-allow')?.addEventListener('click', () => close('allow'));
  document.getElementById('mp-ask')?.addEventListener('click', () => close('ask'));
  document.getElementById('mp-block')?.addEventListener('click', () => close('block'));
}

function showMelixBlocked(data: any) {
  const e = parseMelixEvent(data);
  const existing = document.getElementById('melix-blocked-toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.id = 'melix-blocked-toast';
  toast.style.cssText = `
    position: fixed; top: 20px; right: 20px; z-index: 10004; background:#fff;
    border:1px solid #f0d0d0; border-left:4px solid #A80000; border-radius:10px;
    padding:14px 18px; box-shadow:0 12px 32px rgba(0,0,0,0.15); max-width:360px;
    font-family: 'Microsoft YaHei UI','Microsoft YaHei','Segoe UI',system-ui,sans-serif;
    animation: oobePop 0.3s ease;
  `;
  toast.innerHTML = `
    <div style="font-size:14px;font-weight:700;color:#A80000;margin-bottom:4px;">已拦截恶意行为</div>
    <div style="font-size:12.5px;color:#5F6B7A;line-height:1.6;">${escapeHtml(e.desc)}</div>
    <div style="font-size:11.5px;color:#999;margin-top:6px;">进程：${escapeHtml(e.actorPath)}</div>`;
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.transition = 'opacity 0.4s'; toast.style.opacity = '0'; setTimeout(() => toast.remove(), 400); }, 5000);
}

// ========== 端点防护拦截日志 ==========
// 拦截/询问事件由 Melix.UI 推送 → 主程序 emit melix-intercepted → 前端记录到本地并渲染。
function getEndpointLog(): any[] {
  try { return JSON.parse(localStorage.getItem('xigua_endpoint_log') || '[]'); }
  catch { return []; }
}

function addEndpointLog(entry: any) {
  const list = getEndpointLog();
  list.unshift({ id: Date.now().toString(36), time: Date.now(), ...entry });
  localStorage.setItem('xigua_endpoint_log', JSON.stringify(list.slice(0, 200)));
  renderEndpointInterceptLog();
}

// 刷新端点防护页的防护连接状态：跟随 Melix.UI(WPF) 端显示的真实引擎状态
// （内核已启用/用户态监控/内核未启用/正在连接驱动/服务连接状态等）。
async function refreshEndpointStatus() {
  const setBadge = (id: string, ok: boolean, okText: string, failText: string) => {
    const el = document.getElementById(id) as HTMLElement | null;
    if (!el) return;
    el.textContent = ok ? okText : failText;
    el.style.background = ok ? 'rgba(16,137,62,0.12)' : 'rgba(209,52,56,0.12)';
    el.style.color = ok ? '#10893e' : '#d13438';
  };

  const totalEl = document.getElementById('ep-status-total') as HTMLElement | null;
  const driverEl = document.getElementById('ep-status-driver') as HTMLElement | null;
  const serviceEl = document.getElementById('ep-status-service') as HTMLElement | null;

  try {
    const st = await invoke<any>('melix_ui_get_status');
    // 总防护徽章显示完整引擎状态（跟随 WPF）
    if (totalEl) {
      totalEl.textContent = st?.engine || '未知状态';
      const ok = !!(st?.kernel_connected || st?.protection_enabled || st?.connected);
      totalEl.style.background = ok ? 'rgba(16,137,62,0.12)' : 'rgba(209,52,56,0.12)';
      totalEl.style.color = ok ? '#10893e' : '#d13438';
    }
    // 驱动徽章：内核是否连接
    setBadge('ep-status-driver', !!st?.kernel_connected, '内核已连接', '内核未连接');
    // 服务徽章：UI 是否连接服务
    setBadge('ep-status-service', !!st?.connected, '服务已连接', '服务未连接');
  } catch (e) {
    console.error('[Endpoint] get status failed:', e);
    setBadge('ep-status-total', false, '无法获取', '无法获取');
    if (driverEl) { driverEl.textContent = '—'; }
    if (serviceEl) { serviceEl.textContent = '—'; }
  }
}

function renderEndpointInterceptLog() {
  const container = document.getElementById('endpoint-log-container');
  if (!container) return;
  const list = getEndpointLog();
  if (list.length === 0) {
    container.innerHTML = `<div class="endpoint-empty">暂无拦截记录</div>`;
    return;
  }
  container.innerHTML = list.map((e: any) => {
    const kind = e.kind === 'prompt' ? '询问' : '已拦截';
    const cls = e.kind === 'prompt' ? 'ask' : 'block';
    const time = new Date(e.time || Date.now()).toLocaleString();
    return `
      <div class="endpoint-rule-item">
        <div class="endpoint-rule-info">
          <h4>${escapeHtml(e.actor || '未知进程')}</h4>
          <p>${escapeHtml(e.summary || e.risk || '')}</p>
        </div>
        <div class="endpoint-rule-actions">
          <span class="endpoint-rule-action ${cls}">${kind}</span>
          <span style="font-size:11px;color:#9AA3AF;white-space:nowrap;">${time}</span>
        </div>
      </div>`;
  }).join('');
}

// ========== 端点防护规则面板 ==========

// 加载防护规则：只发送请求（事件驱动），规则数据随后经 melix-rules 事件异步返回。
async function loadEndpointRules() {
  const container = document.getElementById('endpoint-rules-container');
  if (!container) return;
  container.innerHTML = `<div class="endpoint-loading">${t('prot.loadingRules')}</div>`;
  try {
    await invoke('melix_get_rules');
  } catch (e: any) {
    container.innerHTML = `<div class="endpoint-empty">${t('prot.rulesLoadFailed')}<br><span style="font-size:11px;color:#999">${(e?.message || String(e))}</span></div>`;
  }
}

// 渲染规则列表（由 melix-rules 事件触发）
function renderEndpointRules(rules: any[]) {
  const container = document.getElementById('endpoint-rules-container');
  if (!container) return;
  if (!Array.isArray(rules) || rules.length === 0) {
    container.innerHTML = `<div class="endpoint-empty">${t('prot.noRules')}</div>`;
    return;
  }
  container.innerHTML = rules.map(r => renderEndpointRule(r)).join('');
  // 绑定删除按钮
  container.querySelectorAll('[data-del-rule]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-del-rule')!;
      if (!confirm('确定删除该规则？')) return;
      try {
        await invoke('melix_delete_rule', { ruleId: id });
        loadEndpointRules();
      } catch (e: any) {
        alert('删除失败：' + (e?.message || String(e)));
      }
    });
  });
}

function renderEndpointRule(r: any): string {
  const type = r?.type || '—';
  const action = String(r?.action || '').toLowerCase();
  const actionLabel = action === 'allow' ? '放行' : action === 'block' ? '拦截' : '询问';
  const cls = action === 'allow' ? 'allow' : action === 'block' ? 'block' : 'ask';
  const name = r?.note || r?.actorPath || r?.targetPattern || '未命名规则';
  const desc = [
    r?.actorPath ? `主体: ${r.actorPath}` : '',
    r?.targetPattern ? `目标: ${r.targetPattern}` : '',
    r?.commandLinePattern ? `命令行: ${r.commandLinePattern}` : '',
  ].filter(Boolean).join(' · ');
  return `
    <div class="endpoint-rule-item">
      <div class="endpoint-rule-info">
        <h4>${escapeHtml(name)}</h4>
        <p>${type}${desc ? ' · ' + escapeHtml(desc) : ''}</p>
      </div>
      <div class="endpoint-rule-actions">
        <span class="endpoint-rule-action ${cls}">${actionLabel}</span>
        <button class="btn btn-secondary" data-del-rule="${escapeHtml(r?.id || '')}" style="padding:5px 10px;font-size:12px;">${t('prot.deleteRule')}</button>
      </div>
    </div>`;
}

// 添加规则对话框
function showEndpointAddRuleDialog() {
  const existing = document.getElementById('endpoint-rule-modal');
  if (existing) existing.remove();
  const modal = document.createElement('div');
  modal.id = 'endpoint-rule-modal';
  modal.style.cssText = `
    position: fixed; inset: 0; z-index: 10002; background: rgba(0,0,0,0.25);
    display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px);
    font-family: 'Microsoft YaHei UI', 'Microsoft YaHei', 'Segoe UI', system-ui, sans-serif;
  `;
  modal.innerHTML = `
    <div style="background:#fff;border-radius:12px;width:520px;max-width:92%;padding:24px;box-shadow:0 32px 64px rgba(0,0,0,0.2);">
      <div style="font-size:16px;font-weight:600;margin-bottom:16px;">${t('prot.addRule')}</div>
      <div style="display:flex;flex-direction:column;gap:12px;">
        <label style="font-size:12px;color:#5F5F5F;">${t('prot.ruleType')}
          <select id="er-type" style="display:block;width:100%;margin-top:4px;padding:8px;border:1px solid #d9dee5;border-radius:8px;font-size:13px;">
            <option value="ProcessCreate">进程创建 (ProcessCreate)</option>
            <option value="ImageLoad">模块加载 (ImageLoad)</option>
            <option value="ProcessTerminate">进程结束 (ProcessTerminate)</option>
            <option value="NetworkConnect">网络连接 (NetworkConnect)</option>
            <option value="RegistryWrite">注册表写入 (RegistryWrite)</option>
            <option value="FileWrite">文件写入 (FileWrite)</option>
            <option value="DriverLoad">驱动加载 (DriverLoad)</option>
          </select>
        </label>
        <label style="font-size:12px;color:#5F5F5F;">${t('prot.ruleActor')}
          <input id="er-actor" placeholder="C:\\Windows\\System32\\*.exe" style="display:block;width:100%;margin-top:4px;padding:8px;border:1px solid #d9dee5;border-radius:8px;font-size:13px;box-sizing:border-box;">
        </label>
        <label style="font-size:12px;color:#5F5F5F;">${t('prot.ruleTarget')}
          <input id="er-target" placeholder="C:\\Users\\*\\AppData\\*" style="display:block;width:100%;margin-top:4px;padding:8px;border:1px solid #d9dee5;border-radius:8px;font-size:13px;box-sizing:border-box;">
        </label>
        <label style="font-size:12px;color:#5F5F5F;">${t('prot.ruleAction')}
          <select id="er-action" style="display:block;width:100%;margin-top:4px;padding:8px;border:1px solid #d9dee5;border-radius:8px;font-size:13px;">
            <option value="block">拦截 (Block)</option>
            <option value="allow">放行 (Allow)</option>
            <option value="ask">询问 (Ask)</option>
          </select>
        </label>
        <label style="font-size:12px;color:#5F5F5F;">${t('prot.ruleNote')}
          <input id="er-note" placeholder="规则备注" style="display:block;width:100%;margin-top:4px;padding:8px;border:1px solid #d9dee5;border-radius:8px;font-size:13px;box-sizing:border-box;">
        </label>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:20px;">
        <button id="er-cancel" style="padding:8px 20px;border:1px solid #d9dee5;border-radius:8px;background:#fff;cursor:pointer;font-size:13px;">${t('prot.ruleCancel')}</button>
        <button id="er-save" style="padding:8px 24px;border:none;border-radius:8px;background:#00BFA5;color:#fff;cursor:pointer;font-size:13px;font-weight:600;">${t('prot.ruleSave')}</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
  $('#er-cancel')?.addEventListener('click', () => modal.remove());
  $('#er-save')?.addEventListener('click', async () => {
    const type = ($('#er-type') as HTMLSelectElement)?.value || '';
    const actor = ($('#er-actor') as HTMLInputElement)?.value.trim() || null;
    const target = ($('#er-target') as HTMLInputElement)?.value.trim() || null;
    const action = ($('#er-action') as HTMLSelectElement)?.value || 'block';
    const note = ($('#er-note') as HTMLInputElement)?.value.trim() || null;
    if (!actor && !target) {
      alert('请至少填写主体路径或目标路径');
      return;
    }
    try {
      await invoke('melix_add_rule', { actorPath: actor, type, targetPattern: target, action, note });
      modal.remove();
      loadEndpointRules();
    } catch (e: any) {
      alert('添加失败：' + (e?.message || String(e)));
    }
  });
}

// ========== 设置页 ==========
function initSettingsPage() {
  const startupToggle = $('#startup-toggle') as HTMLInputElement | null;

  if (startupToggle) {
    invoke('is_in_startup_folder').then((v: unknown) => {
      startupToggle.checked = !!v;
    }).catch(() => {});
    startupToggle.addEventListener('change', async () => {
      try {
        if (startupToggle.checked) {
          await invoke('add_to_startup_folder');
        } else {
          await invoke('remove_from_startup_folder');
        }
      } catch (e) {
        console.log('Startup toggle failed:', e);
        startupToggle.checked = !startupToggle.checked;
      }
    });
  }

  // 文件防护（真实后端命令 + 本地状态）
  const fileToggle = $('#file-protection-toggle') as HTMLInputElement | null;
  if (fileToggle) {
    fileToggle.checked = localStorage.getItem('file_protection_enabled') !== 'false';
    fileToggle.addEventListener('change', () => {
      localStorage.setItem('file_protection_enabled', String(fileToggle.checked));
      _fpEnabled = fileToggle.checked;
      invoke('set_file_protection_enabled', { enabled: fileToggle.checked, scope: 'all' }).catch(() => {});
      updateHomeProtectionStatus();
    });
  }

  // 脚本扫描
  const scriptToggle = $('#script-scan-toggle') as HTMLInputElement | null;
  if (scriptToggle) {
    scriptToggle.checked = localStorage.getItem('script_scan_enabled') !== 'false';
    scriptToggle.addEventListener('change', () => {
      localStorage.setItem('script_scan_enabled', String(scriptToggle.checked));
      invoke('set_script_protection_enabled', { enabled: scriptToggle.checked }).catch(() => {
        scriptToggle.checked = !scriptToggle.checked;
      });
    });
  }

  // 云端哈希扫描
  // 注意：扫描逻辑与旧版 CloudHashManager 均读取 cloud_hash_enabled_v2，
  // 因此开关必须写入该 key，否则设置页开关与真实扫描相互脱节（云端 HTTP 不会被调用）。
  const cloudHashToggle = $('#cloud-hash-toggle') as HTMLInputElement | null;
  if (cloudHashToggle) {
    cloudHashToggle.checked = isCloudHashEnabled();
    cloudHashToggle.addEventListener('change', () => {
      setCloudHashEnabled(cloudHashToggle.checked);
    });
  }

  // 云查询辅助
  const cloudQueryToggle = $('#cloud-query-toggle') as HTMLInputElement | null;
  if (cloudQueryToggle) {
    cloudQueryToggle.checked = localStorage.getItem('auxiliary_cloud_scan_enabled') !== 'false';
    cloudQueryToggle.addEventListener('change', () => {
      localStorage.setItem('auxiliary_cloud_scan_enabled', String(cloudQueryToggle.checked));
    });
  }

  // 增强端点防护（与防护页共享同一套真实开关逻辑）
  bindEndpointProtectionToggle($('#endpoint-protection-toggle') as HTMLInputElement | null);

  // 勒索软件防护（真实后端命令，默认关闭）
  const ransomwareToggle = $('#ransomware-protection-toggle') as HTMLInputElement | null;
  if (ransomwareToggle) {
    invoke<any>('get_ransomware_protection_state').then((s: any) => {
      if (s && typeof s.enabled === 'boolean') ransomwareToggle.checked = s.enabled;
    }).catch(() => {});
    ransomwareToggle.addEventListener('change', () => {
      invoke<any>('set_ransomware_protection_enabled', { enabled: ransomwareToggle.checked }).then(() => {
        if (ransomwareToggle.checked) showToast('勒索软件防护已启动');
        else showToast('勒索软件防护已停止');
      }).catch(() => {
        ransomwareToggle.checked = !ransomwareToggle.checked;
        showToast('切换勒索软件防护失败');
      });
    });
  }

  // 扫描压缩包（本地记忆，默认开启）
  const archiveScanToggle = $('#archive-scan-toggle') as HTMLInputElement | null;
  if (archiveScanToggle) {
    archiveScanToggle.checked = localStorage.getItem('archive_scan_enabled') !== 'false';
    archiveScanToggle.addEventListener('change', () => {
      localStorage.setItem('archive_scan_enabled', String(archiveScanToggle.checked));
    });
  }

  // 重置返回 OOBE（清除首次启动标记并重新加载）
  const resetOobeBtn = $('#reset-oobe-btn');
  if (resetOobeBtn) {
    resetOobeBtn.addEventListener('click', () => {
      if (confirm('确定要将应用重置为首次启动设置向导吗？当前设置将被清除。')) {
        localStorage.removeItem('oobe_completed');
        localStorage.removeItem('endpoint_protection_enabled');
        localStorage.removeItem('archive_scan_enabled');
        // 保留主题/语言等个性化设置，重置 OOBE 后用户可重新配置
        showToast('已重置，正在进入首次启动向导...');
        setTimeout(() => { location.reload(); }, 600);
      }
    });
  }

  // 进程白名单（弹窗管理：进程 / 路径 / 域名 三组，真实后端命令）
  $('#whitelist-open-btn')?.addEventListener('click', () => openWhitelistDialog());
  // 病毒库规则
  const rulesVersion = $('#rules-version');
  const loadRules = () => {
    invoke('get_rules_status_command').then((s: any) => {
      if (rulesVersion && s) {
        const v = s.version || s.updated_at || '-';
        rulesVersion.textContent = String(v);
      }
    }).catch(() => {
      if (rulesVersion) rulesVersion.textContent = '-';
    });
  };
  loadRules();
  $('#rules-update-btn')?.addEventListener('click', async () => {
    try {
      await invoke('update_rules_command');
      loadRules();
      addNotification(t('settings.rulesVersion'), t('settings.rulesUpdated'), 'system');
    } catch (e) {
      alert(`更新失败：${e}`);
    }
  });

  // 当前软件版本（填充）
  const versionEl = $('#current-version');
  if (versionEl) {
    const fillVersion = (v: string) => { if (v) versionEl.textContent = v; };
    if (window.__TAURI__ && window.__TAURI__.app && window.__TAURI__.app.getVersion) {
      window.__TAURI__.app.getVersion().then(fillVersion).catch(() => {});
    } else {
      invoke('get_version_command').then((v: unknown) => fillVersion(String(v))).catch(() => {
        invoke('get_app_version').then((v: unknown) => fillVersion(String(v))).catch(() => {});
      });
    }
  }

  // 软件检查更新（手动触发）
  $('#about-update-btn')?.addEventListener('click', async () => {
    try {
      const result = await invoke<string>('check_update_command');
      const updateInfo = JSON.parse(result) as UpdateInfo;
      if (updateInfo && updateInfo.has_update) {
        showUpdateNotification(updateInfo);
      } else {
        showToast('当前已是最新版本');
      }
    } catch (e) {
      console.error('[Settings] Check update failed:', e);
      showToast('检查更新失败：' + String(e));
    }
  });

  // 赞助（独立设置项）
  $('#about-sponsor-btn')?.addEventListener('click', () => {
    showSponsorDialog();
  });

  // 反馈（独立设置项）
  $('#about-feedback-btn')?.addEventListener('click', async () => {
    try {
      await invoke('open_survey_url');
    } catch (e) {
      console.log('Feedback not available:', e);
    }
  });

  // 自定义背景
  $('#custom-bg-btn')?.addEventListener('click', async () => {
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({
        multiple: false,
        filters: [{ name: 'Images', extensions: ['png', 'jpg', 'jpeg', 'bmp', 'gif'] }]
      });
      if (selected) {
        localStorage.setItem('custom_bg_path', String(selected));
        applyCustomBg(String(selected));
      }
    } catch (e) {
      console.log('Custom bg not supported:', e);
    }
  });

}

// ========== 赞助弹窗 ==========
function showSponsorDialog() {
  if (document.getElementById('sponsor-dialog')) return;
  const dialog = document.createElement('div');
  dialog.id = 'sponsor-dialog';
  dialog.innerHTML = `
    <div class="sponsor-dialog-overlay"></div>
    <div class="sponsor-dialog-content">
      <div style="padding: 24px;">
        <div style="display:flex;align-items:flex-start;gap:16px;margin-bottom:16px;">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:2px;">
            <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>
          </svg>
          <div style="flex:1;">
            <div style="font-size:18px;font-weight:600;color:var(--text-primary);line-height:1.4;margin-bottom:12px;">${t('sponsorDialogTitle')}</div>
            <div style="font-size:14px;color:var(--text-secondary);line-height:1.6;">
              <p style="margin:0 0 8px 0;">${t('sponsorDialogText')}</p>
            </div>
          </div>
        </div>
        <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px;">
          <button id="sponsor-cancel-btn" class="btn btn-secondary" style="padding:6px 16px;">${t('sponsorCancel')}</button>
          <button id="sponsor-confirm-btn" class="btn btn-primary" style="padding:6px 16px;">${t('sponsorConfirm')}</button>
        </div>
      </div>
    </div>
    <style>
      #sponsor-dialog {
        position: fixed; top: 0; left: 0; right: 0; bottom: 0;
        z-index: 100002; display: flex; align-items: center; justify-content: center;
      }
      .sponsor-dialog-overlay {
        position: absolute; top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0,0,0,0.25); backdrop-filter: blur(4px);
      }
      .sponsor-dialog-content {
        position: relative; background: var(--bg-panel); border-radius: 8px;
        max-width: 480px; width: 90%;
        box-shadow: var(--shadow-lg);
        animation: sponsorDialogShow 0.2s cubic-bezier(0.0, 0.0, 0.2, 1);
      }
      @keyframes sponsorDialogShow {
        from { opacity: 0; transform: scale(0.95) translateY(-10px); }
        to { opacity: 1; transform: scale(1) translateY(0); }
      }
    </style>
  `;
  document.body.appendChild(dialog);
  document.getElementById('sponsor-cancel-btn')?.addEventListener('click', () => dialog.remove());
  document.getElementById('sponsor-confirm-btn')?.addEventListener('click', async () => {
    dialog.remove();
    try {
      await invoke('open_sponsor_url');
    } catch (e) {
      console.error('Failed to open sponsor page:', e);
    }
  });
}

// ========== 隔离区 ==========
function renderQuarantine() {
  const container = $('#quarantine-list');
  if (!container) return;
  container.innerHTML = '<div class="logs-empty">Loading...</div>';

  invoke('get_quarantined_files').then((result: any) => {
    const list: any[] = (result && Array.isArray(result.files)) ? result.files : (Array.isArray(result) ? result : []);
    if (list.length === 0) {
      container.innerHTML = `
        <div class="quarantine-empty">
          <img class="page-illustration" src="illustration-quarantine.svg" alt="No threats">
          <h3>No Threats Detected</h3>
          <p>Your quarantined items will appear here</p>
        </div>`;
      return;
    }
    const formatSize = (bytes: number): string => {
      if (!bytes) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };
    container.innerHTML = `
      <div class="card" style="padding: 8px;">
        ${list.map((f: any) => `
          <div style="padding: 14px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; gap: 12px;">
            <div style="flex: 1; min-width: 0;">
              <div style="font-weight: 600; margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(f.file_name)}</div>
              <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 3px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">原始位置: ${escapeHtml(f.original_path)}</div>
              <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 3px;">威胁类型: <span style="color: var(--danger);">${escapeHtml(f.threat_name)}</span></div>
              <div style="font-size: 12px; color: var(--text-secondary);">隔离时间: ${escapeHtml(f.quarantine_date)} | 大小: ${formatSize(f.file_size)}</div>
            </div>
            <div style="display: flex; gap: 8px; flex-shrink: 0;">
              <button class="btn btn-secondary btn-sm" data-qid="${escapeHtml(f.id)}" data-qaction="restore">恢复</button>
              <button class="btn btn-danger btn-sm" data-qid="${escapeHtml(f.id)}" data-qaction="delete">删除</button>
            </div>
          </div>`).join('')}
      </div>`;

    container.querySelectorAll<HTMLButtonElement>('[data-qaction]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.qid;
        const action = btn.dataset.qaction;
        try {
          if (action === 'restore') {
            await invoke('restore_quarantined_file', { id });
          } else {
            await invoke('delete_quarantined_file', { id });
          }
          renderQuarantine();
        } catch (e) {
          alert(`操作失败：${e}`);
        }
      });
    });
  }).catch(() => {
    container.innerHTML = `
      <div class="quarantine-empty">
        <img class="page-illustration" src="illustration-quarantine.svg" alt="No threats">
        <h3>No Threats Detected</h3>
        <p>Your quarantined items will appear here</p>
      </div>`;
  });
}

// ========== 安全日志 ==========
function renderLogs() {
  const container = $('#logs-container');
  if (!container) return;
  container.innerHTML = '<div class="logs-empty">Loading...</div>';

  invoke('get_security_logs', {
    startDate: null, endDate: null, category: null, keyword: null, page: 0, pageSize: 200,
  }).then((result: any) => {
    const logs: any[] = (result && result.logs) || [];
    if (logs.length === 0) {
      container.innerHTML = '<div class="logs-empty">暂无日志记录</div>';
      return;
    }
    const typeOf = (r?: string) =>
      r === 'blocked' || r === 'danger' ? 'log-danger'
        : (r === 'allowed' || r === 'success' ? 'log-success'
          : (r === 'warning' ? 'log-warning' : 'log-info'));
    container.innerHTML = logs.map((log: any) => `
      <div class="log-entry">
        <span class="log-time">${escapeHtml(log.timestamp)}</span>
        <span class="log-type ${typeOf(log.result)}">${escapeHtml(log.category || 'INFO')}</span>
        <span class="log-msg">${escapeHtml(log.summary || log.function || '')}</span>
      </div>`).join('');
  }).catch(() => {
    container.innerHTML = '<div class="logs-empty">暂无日志记录</div>';
  });
}

function initLogsToolbar() {
  $('#clear_logs_btn')?.addEventListener('click', () => {
    const c = $('#logs-container');
    if (c) c.innerHTML = '<div class="logs-empty">日志已清空</div>';
  });
  $('#export_logs_btn')?.addEventListener('click', () => {
    alert('日志导出功能即将上线。');
  });
}

// ========== 通知中心（公告系统） ==========
interface BridgeNotification {
  id: string;
  type: string;
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
}

function getNotifications(): BridgeNotification[] {
  try {
    return JSON.parse(localStorage.getItem('xigua_notifications') || '[]');
  } catch {
    return [];
  }
}

function addNotification(title: string, message: string, type = 'system') {
  const list = getNotifications();
  list.unshift({
    id: Date.now().toString(36),
    type,
    title,
    message,
    timestamp: new Date().toLocaleString('zh-CN', { hour12: false }),
    read: false,
  });
  localStorage.setItem('xigua_notifications', JSON.stringify(list.slice(0, 50)));
  updateNotificationBadge();
}

function updateNotificationBadge() {
  const unread = getNotifications().filter(n => !n.read).length;
  const badge = $('#notification-badge');
  if (badge) badge.style.display = unread > 0 ? 'block' : 'none';
}

function renderNotifications() {
  const container = $('#notifications-container');
  if (!container) return;
  const list = getNotifications();

  if (list.length === 0) {
    container.innerHTML = `
      <div class="card" style="text-align: center; padding: 60px 20px;">
        <div style="font-size: 15px; color: var(--text-secondary);">${t('notif.empty')}</div>
        <div style="font-size: 13px; color: var(--text-muted); margin-top: 6px;">${t('notif.emptyDesc')}</div>
      </div>`;
    return;
  }

  container.innerHTML = `
    <div style="display: flex; justify-content: flex-end; gap: 8px; margin-bottom: 12px;">
      <button class="btn btn-secondary btn-sm" id="mark-all-read">全部已读</button>
      <button class="btn btn-secondary btn-sm" id="clear-notifications">清空</button>
    </div>
    <div class="card" style="padding: 8px;">
      ${list.map(n => `
        <div class="log-entry" data-nid="${n.id}" style="${n.read ? 'opacity: 0.6;' : ''}">
          <span class="log-type ${n.type === 'threat' ? 'log-danger' : n.type === 'scan' ? 'log-info' : 'log-success'}">${escapeHtml(n.type.toUpperCase())}</span>
          <div style="flex: 1; min-width: 0;">
            <div style="font-weight: 600; font-size: 13px;">${escapeHtml(n.title)}</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">${escapeHtml(n.message)}</div>
          </div>
          <span class="log-time">${escapeHtml(n.timestamp)}</span>
        </div>`).join('')}
    </div>`;

  container.querySelectorAll('.log-entry[data-nid]').forEach(el => {
    el.addEventListener('click', () => {
      const id = el.getAttribute('data-nid');
      const list2 = getNotifications().map(n => n.id === id ? { ...n, read: true } : n);
      localStorage.setItem('xigua_notifications', JSON.stringify(list2));
      updateNotificationBadge();
      el.setAttribute('style', 'opacity: 0.6;');
    });
  });

  $('#mark-all-read')?.addEventListener('click', () => {
    localStorage.setItem('xigua_notifications', JSON.stringify(getNotifications().map(n => ({ ...n, read: true }))));
    renderNotifications();
    updateNotificationBadge();
  });
  $('#clear-notifications')?.addEventListener('click', () => {
    localStorage.setItem('xigua_notifications', '[]');
    renderNotifications();
    updateNotificationBadge();
  });
}

// ========== 工具箱 ==========
function renderProcessHome() {
  const container = $('#process-container');
  if (!container) return;
  const tools: Array<[string, string, string, string]> = [
    ['toolbox_popup', t('toolbox.popup'), t('toolbox.popupDesc'), 'shield'],
    ['toolbox_cleaner', t('toolbox.cleaner'), t('toolbox.cleanerDesc'), 'trash'],
    ['toolbox_process_manager', t('toolbox.process'), t('toolbox.processDesc'), 'grid'],
    ['toolbox_edr_reports', t('toolbox.edr'), t('toolbox.edrDesc'), 'activity'],
    ['toolbox_system_repair', t('toolbox.repair'), t('toolbox.repairDesc'), 'wrench'],
  ];
  const icons: Record<string, string> = {
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>',
    grid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/></svg>',
    activity: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/></svg>',
    wrench: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>',
  };

  container.innerHTML = `
    <div class="page-header">
      <h1>${t('toolbox.title')}</h1>
      <p>${t('toolbox.sub')}</p>
    </div>
    <div class="action-grid">
      ${tools.map(([id, title, desc, icon]) => `
        <button class="action-card" data-tool-page="${id}">
          <div class="action-icon">${icons[icon]}</div>
          <div class="action-content">
            <div class="action-title">${title}</div>
            <div class="action-desc">${desc}</div>
          </div>
          <svg class="action-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
        </button>`).join('')}
    </div>`;

  container.querySelectorAll<HTMLButtonElement>('[data-tool-page]').forEach(btn => {
    btn.addEventListener('click', () => {
      const page = btn.dataset.toolPage!;
      switchPage(page);
      if (page === 'toolbox_popup') renderToolboxPopup();
      else if (page === 'toolbox_cleaner') renderToolboxCleaner();
      else if (page === 'toolbox_process_manager') renderToolboxProcessManager();
      else if (page === 'toolbox_edr_reports') renderToolboxEdrReports();
      else if (page === 'toolbox_system_repair') renderToolboxSystemRepair();
    });
  });
}

// --- 弹窗拦截器 ---
function renderToolboxPopup() {
  const container = $('#toolbox-popup-container');
  if (!container) return;
  container.innerHTML = '<div class="logs-empty">Loading...</div>';

  const load = () => {
    Promise.all([
      invoke('get_popup_interceptor_state'),
      invoke('get_popup_rules'),
      invoke('get_hidden_popups'),
    ]).then(([state, rules, hidden]: any[]) => {
      const enabled = !!(state && state.enabled);
      container.innerHTML = `
        <div class="page-header" style="display: flex; align-items: flex-start; justify-content: space-between;">
          <div>
            <h1>${t('toolbox.popup')}</h1>
            <p>${t('toolbox.popupDesc')}</p>
          </div>
          <button class="btn btn-secondary" id="popup-back-btn" style="flex-shrink: 0;">${t('toolbox.back')}</button>
        </div>
        <div class="settings-group">
          <h3>开关</h3>
          <div class="setting-item">
            <div class="setting-info">
              <span>启用弹窗拦截</span>
              <span class="setting-desc">拦截系统弹窗广告与恶意窗口</span>
            </div>
            <label class="toggle">
              <input type="checkbox" id="popup-enabled" ${enabled ? 'checked' : ''}>
              <span class="toggle-slider"></span>
            </label>
          </div>
        </div>
        <div class="settings-group">
          <h3>拦截规则（${(rules || []).length}）</h3>
          <div style="display: flex; gap: 8px; margin-bottom: 8px;">
            <input id="popup-rule-input" placeholder="输入规则关键词，如: 广告" style="flex: 1; padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 13px; background: var(--bg-input); color: var(--text-primary); outline: none;">
            <button class="btn btn-primary" id="popup-rule-add">添加</button>
          </div>
          <div class="card" style="padding: 8px;">
            ${(rules || []).length === 0 ? '<div class="logs-empty">暂无规则</div>' : (rules as string[]).map((r: string) => `
              <div class="log-entry">
                <span style="flex: 1; font-size: 13px;">${escapeHtml(r)}</span>
                <button class="btn btn-danger btn-sm" data-rule="${escapeHtml(r)}">删除</button>
              </div>`).join('')}
          </div>
        </div>
        <div class="settings-group">
          <h3>已拦截弹窗（${(hidden || []).length}）</h3>
          <div class="card" style="padding: 8px;">
            ${(hidden || []).length === 0 ? '<div class="logs-empty">暂无记录</div>' : (hidden as any[]).map((h: any) => `
              <div class="log-entry">
                <span style="flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px;">${escapeHtml(h.title || '未知窗口')} <span style="color: var(--text-muted);">(${escapeHtml(h.process_name || '')})</span></span>
                <button class="btn btn-secondary btn-sm" data-hwnd="${escapeHtml(String(h.hwnd))}">恢复</button>
              </div>`).join('')}
          </div>
        </div>`;

      $('#popup-back-btn')?.addEventListener('click', () => { switchPage('process'); renderProcessHome(); });
      const enabledToggle = $('#popup-enabled') as HTMLInputElement | null;
      enabledToggle?.addEventListener('change', () => {
        if (enabledToggle.checked) {
          invoke('start_popup_interceptor').catch(() => {
            enabledToggle.checked = false;
          });
        } else {
          invoke('stop_popup_interceptor').catch(() => {
            enabledToggle.checked = true;
          });
        }
      });
      $('#popup-rule-add')?.addEventListener('click', async () => {
        const input = $('#popup-rule-input') as HTMLInputElement | null;
        const rule = input?.value.trim();
        if (!rule) return;
        try {
          await invoke('add_popup_rule', { rule });
          if (input) input.value = '';
          load();
        } catch (e) { alert(`添加失败：${e}`); }
      });
      container.querySelectorAll<HTMLButtonElement>('[data-rule]').forEach(btn => {
        btn.addEventListener('click', async () => {
          try {
            await invoke('remove_popup_rule', { rule: btn.dataset.rule });
            load();
          } catch (e) { alert(`删除失败：${e}`); }
        });
      });
      container.querySelectorAll<HTMLButtonElement>('[data-hwnd]').forEach(btn => {
        btn.addEventListener('click', async () => {
          try {
            await invoke('restore_popup', { hwnd: Number(btn.dataset.hwnd) });
            load();
          } catch (e) { /* ignore */ }
        });
      });
    }).catch(() => {
      container.innerHTML = '<div class="logs-empty">无法加载弹窗拦截器状态</div>';
    });
  };
  load();
}

// --- 垃圾清理 ---
function renderToolboxCleaner() {
  const container = $('#toolbox-cleaner-container');
  if (!container) return;
  const categories: Array<[string, string]> = [
    ['temp', '临时文件'],
    ['prefetch', '预读取缓存'],
    ['recycle', '回收站'],
    ['browser', '浏览器缓存'],
  ];
  container.innerHTML = `
    <div class="page-header" style="display: flex; align-items: flex-start; justify-content: space-between;">
      <div>
        <h1>${t('toolbox.cleaner')}</h1>
        <p>${t('toolbox.cleanerDesc')}</p>
      </div>
      <button class="btn btn-secondary" id="cleaner-back-btn" style="flex-shrink: 0;">${t('toolbox.back')}</button>
    </div>
    <div class="settings-group">
      <h3>扫描项目</h3>
      <div class="card" style="padding: 8px;">
        ${categories.map(([id, label]) => `
          <div class="log-entry">
            <label style="display: flex; align-items: center; gap: 10px; flex: 1; cursor: pointer; font-size: 13px;">
              <input type="checkbox" class="junk-cb" data-cat="${id}" checked style="width: 16px; height: 16px; accent-color: var(--primary);">
              ${label}
            </label>
            <span class="junk-size" style="font-size: 12px; color: var(--text-muted);">-</span>
          </div>`).join('')}
      </div>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn btn-primary" id="junk-scan-btn">扫描垃圾</button>
      <button class="btn btn-secondary" id="junk-clean-btn" disabled>清理选中</button>
    </div>
    <div id="junk-result" style="margin-top: 16px;"></div>`;

  $('#cleaner-back-btn')?.addEventListener('click', () => { switchPage('process'); renderProcessHome(); });
  $('#junk-scan-btn')?.addEventListener('click', async () => {
    const cats = Array.from(container.querySelectorAll<HTMLInputElement>('.junk-cb:checked')).map(c => c.dataset.cat);
    const result = $('#junk-result');
    if (result) result.innerHTML = '<div class="logs-empty">正在扫描...</div>';
    try {
      const res: any = await invoke('scan_junk_command', { categories: cats });
      const details: any = res && res.details ? res.details : (res || {});
      let html = '';
      for (const [id, label] of categories) {
        const size = details[id] || details[id + '_size'] || 0;
        const sizeEl = container.querySelector<HTMLElement>(`.junk-size[data-cat="${id}"]`);
        if (sizeEl) sizeEl.textContent = formatBytes(size);
        html += `<div class="log-entry"><span>${label}</span><span style="margin-left: auto; color: var(--text-secondary);">${formatBytes(size)}</span></div>`;
      }
      if (result) result.innerHTML = `<div class="card" style="padding: 8px; margin-top: 12px;"><div style="font-weight: 600; margin-bottom: 4px;">扫描完成</div>${html}</div>`;
      const cleanBtn = $('#junk-clean-btn') as HTMLButtonElement | null;
      if (cleanBtn) cleanBtn.disabled = false;
    } catch (e) {
      if (result) result.innerHTML = `<div class="logs-empty">扫描失败：${escapeHtml(e)}</div>`;
    }
  });
  $('#junk-clean-btn')?.addEventListener('click', async () => {
    const cats = Array.from(container.querySelectorAll<HTMLInputElement>('.junk-cb:checked')).map(c => c.dataset.cat);
    const result = $('#junk-result');
    if (result) result.innerHTML = '<div class="logs-empty">正在清理...</div>';
    try {
      const res: any = await invoke('clean_junk_command', { categories: cats });
      const freed = (res && (res.total_freed || res.freed)) || 0;
      if (result) result.innerHTML = `<div class="card" style="padding: 16px; text-align: center;">清理完成，释放空间：${formatBytes(freed)}</div>`;
      addNotification('垃圾清理完成', `清理垃圾文件，释放 ${formatBytes(freed)} 空间`, 'system');
      renderToolboxCleaner();
    } catch (e) {
      if (result) result.innerHTML = `<div class="logs-empty">清理失败：${escapeHtml(e)}</div>`;
    }
  });
}

function formatBytes(bytes: number): string {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// --- 进程管理器 ---
function renderToolboxProcessManager() {
  const container = $('#toolbox-process-manager-container');
  if (!container) return;
  container.innerHTML = `
    <div class="page-header" style="display: flex; align-items: flex-start; justify-content: space-between;">
      <div>
        <h1>${t('toolbox.process')}</h1>
        <p>${t('toolbox.processDesc')}</p>
      </div>
      <button class="btn btn-secondary" id="pm-back-btn" style="flex-shrink: 0;">${t('toolbox.back')}</button>
    </div>
    <div style="display: flex; gap: 8px; margin-bottom: 12px;">
      <input id="pm-search" placeholder="搜索进程名称..." style="flex: 1; padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 13px; background: var(--bg-input); color: var(--text-primary); outline: none;">
      <button class="btn btn-secondary" id="pm-refresh">刷新</button>
    </div>
    <div class="card" style="padding: 8px; max-height: 480px; overflow-y: auto;" id="pm-list"></div>`;

  const loadList = () => {
    const listEl = $('#pm-list');
    if (!listEl) return;
    listEl.innerHTML = '<div class="logs-empty">Loading...</div>';
    const keyword = (($('#pm-search') as HTMLInputElement)?.value || '').trim().toLowerCase();
    invoke('get_process_list').then((procs: any) => {
      const filtered = (procs || []).filter((p: any) => !keyword || String(p.name || '').toLowerCase().includes(keyword));
      if (filtered.length === 0) {
        listEl.innerHTML = '<div class="logs-empty">未找到进程</div>';
        return;
      }
      listEl.innerHTML = filtered.slice(0, 300).map((p: any) => `
        <div class="log-entry">
          <span style="flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px;">${escapeHtml(p.name)}</span>
          <span style="font-size: 12px; color: var(--text-muted); font-family: monospace;">PID ${escapeHtml(String(p.pid))}</span>
          <button class="btn btn-danger btn-sm" data-pid="${escapeHtml(String(p.pid))}" data-name="${escapeHtml(p.name)}">结束</button>
        </div>`).join('');
      listEl.querySelectorAll<HTMLButtonElement>('[data-pid]').forEach(btn => {
        btn.addEventListener('click', async () => {
          if (!confirm(`确定结束进程 ${btn.dataset.name} (PID ${btn.dataset.pid}) 吗？`)) return;
          try {
            await invoke('kill_process_via_driver', { pid: Number(btn.dataset.pid) }).catch(() => invoke('kill_process', { pid: Number(btn.dataset.pid) }));
            loadList();
          } catch (e) { alert(`结束失败：${e}`); }
        });
      });
    }).catch(() => {
      listEl.innerHTML = '<div class="logs-empty">无法加载进程列表</div>';
    });
  };

  $('#pm-back-btn')?.addEventListener('click', () => { switchPage('process'); renderProcessHome(); });
  $('#pm-refresh')?.addEventListener('click', loadList);
  $('#pm-search')?.addEventListener('input', loadList);
  loadList();
}

// --- EDR 报告 ---
function renderToolboxEdrReports() {
  const container = $('#toolbox-edr-reports-container');
  if (!container) return;
  container.innerHTML = `
    <div class="page-header" style="display: flex; align-items: flex-start; justify-content: space-between;">
      <div>
        <h1>${t('toolbox.edr')}</h1>
        <p>${t('toolbox.edrDesc')}</p>
      </div>
      <button class="btn btn-secondary" id="edr-back-btn" style="flex-shrink: 0;">${t('toolbox.back')}</button>
    </div>
    <div class="card" style="padding: 8px;" id="edr-report-list"></div>`;

  $('#edr-back-btn')?.addEventListener('click', () => { switchPage('process'); renderProcessHome(); });
  const listEl = $('#edr-report-list');
  if (listEl) {
    listEl.innerHTML = '<div class="logs-empty">暂无 EDR 报告记录</div>';
  }
}

// --- 系统修复 ---
function renderToolboxSystemRepair() {
  const container = $('#toolbox-system-repair-container');
  if (!container) return;
  container.innerHTML = `
    <div class="page-header" style="display: flex; align-items: flex-start; justify-content: space-between;">
      <div>
        <h1>${t('toolbox.repair')}</h1>
        <p>${t('toolbox.repairDesc')}</p>
      </div>
      <button class="btn btn-secondary" id="repair-back-btn" style="flex-shrink: 0;">${t('toolbox.back')}</button>
    </div>
    <div style="display: flex; gap: 8px; margin-bottom: 12px;">
      <button class="btn btn-primary" id="repair-scan-btn">扫描问题</button>
    </div>
    <div class="card" style="padding: 8px;" id="repair-list"></div>`;

  $('#repair-back-btn')?.addEventListener('click', () => { switchPage('process'); renderProcessHome(); });
  const listEl = $('#repair-list');
  $('#repair-scan-btn')?.addEventListener('click', async () => {
    if (!listEl) return;
    listEl.innerHTML = '<div class="logs-empty">正在扫描系统安全配置...</div>';
    try {
      const result: any = await invoke('system_repair_scan');
      const issues = (result && (result.issues || result)) || [];
      if (Array.isArray(issues) && issues.length === 0) {
        listEl.innerHTML = '<div class="logs-empty">未发现系统安全问题</div>';
        return;
      }
      const list = Array.isArray(issues) ? issues : [issues];
      listEl.innerHTML = list.map((i: any) => `
        <div class="log-entry">
          <span class="log-type ${String(i.severity || 'medium').toLowerCase() === 'high' ? 'log-danger' : String(i.severity || 'medium').toLowerCase() === 'low' ? 'log-success' : 'log-warning'}">${escapeHtml(i.severity || 'INFO')}</span>
          <div style="flex: 1; min-width: 0;">
            <div style="font-weight: 600; font-size: 13px;">${escapeHtml(i.name || i.category || '')}</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">${escapeHtml(i.description || '')}</div>
          </div>
        </div>`).join('');
    } catch (e) {
      listEl.innerHTML = `<div class="logs-empty">扫描失败：${escapeHtml(e)}</div>`;
    }
  });
}

// ========== 高级设置 ==========
function renderAdvancedSettings() {
  const container = $('#advanced-settings-container');
  if (!container) return;
  const themes: Array<[string, string]> = [
    ['blue', '默认（新 UI 青绿色）'],
    ['purple', '紫色'],
    ['green', '绿色'],
    ['orange', '橙色'],
    ['pink', '粉色'],
    ['teal', '青色'],
  ];
  const currentTheme = localStorage.getItem('theme') || 'blue';

  container.innerHTML = `
    <div class="page-header">
      <h1>${t('advanced.title')}</h1>
      <p>${t('advanced.sub')}</p>
    </div>
    <div class="settings-group">
      <h3>外观</h3>
      <div class="setting-item">
        <div class="setting-info">
          <span>主题色</span>
          <span class="setting-desc">选择应用主题颜色</span>
        </div>
        <select id="theme-select" style="padding: 6px 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 13px; background: var(--bg-input); color: var(--text-primary);">
          ${themes.map(([v, l]) => `<option value="${v}" ${v === currentTheme ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
      </div>
      <div class="setting-item">
        <div class="setting-info">
          <span>语言</span>
          <span class="setting-desc">界面显示语言</span>
        </div>
        <select id="language-select" style="padding: 6px 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 13px; background: var(--bg-input); color: var(--text-primary);">
          <option value="zh-CN" ${(localStorage.getItem('language') || 'zh-CN') === 'zh-CN' ? 'selected' : ''}>简体中文</option>
          <option value="en" ${localStorage.getItem('language') === 'en' ? 'selected' : ''}>English</option>
          <option value="zh-TW" ${localStorage.getItem('language') === 'zh-TW' ? 'selected' : ''}>繁體中文</option>
        </select>
      </div>
    </div>
    <div class="settings-group">
      <h3>防护</h3>
      <div class="setting-item">
        <div class="setting-info">
          <span>驱动防护配置</span>
          <span class="setting-desc">启用内核级驱动防护配置</span>
        </div>
        <label class="toggle">
          <input type="checkbox" id="driver-config-toggle" checked>
          <span class="toggle-slider"></span>
        </label>
      </div>
    </div>
    <div class="settings-group">
      <h3>关于</h3>
      <div class="card" style="font-size: 13px; color: var(--text-secondary); line-height: 1.7;">
        XIGUASecurity 10x<br>
        基于 Tauri 2 + 本地 ONNX 机器学习引擎 + 云端哈希库构建。<br>
        内核驱动防护、实时行为拦截、勒索软件防护均已集成。
      </div>
    </div>`;

  const themeSelect = $('#theme-select') as HTMLSelectElement | null;
  themeSelect?.addEventListener('change', () => {
    localStorage.setItem('theme', themeSelect.value);
    applyTheme(themeSelect.value);
  });
  const langSelect = $('#language-select') as HTMLSelectElement | null;
  langSelect?.addEventListener('change', () => {
    localStorage.setItem('language', langSelect.value);
    invoke('set_language', { lang: langSelect.value }).catch(() => {});
  });
  const driverConfig = $('#driver-config-toggle') as HTMLInputElement | null;
  if (driverConfig) {
    invoke('get_driver_protection_config_enabled').then((v: unknown) => { driverConfig.checked = !!v; }).catch(() => {});
    driverConfig.addEventListener('change', () => {
      invoke('set_driver_protection_config_enabled', { enabled: driverConfig.checked }).catch(() => {
        driverConfig.checked = !driverConfig.checked;
      });
    });
  }
}

function applyTheme(theme: string) {
  const accents: Record<string, [string, string]> = {
    blue: ['#00BFA5', '#00897B'],
    purple: ['#7c3aed', '#6d28d9'],
    green: ['#059669', '#047857'],
    orange: ['#ea580c', '#c2410c'],
    pink: ['#db2777', '#be185d'],
    teal: ['#0d9488', '#0f766e'],
  };
  const [main, dark] = accents[theme] || accents.blue;
  const root = document.documentElement;
  root.style.setProperty('--primary', main);
  root.style.setProperty('--primary-dark', dark);
  root.style.setProperty('--primary-alpha', hexToRgba(main, 0.1));
  root.style.setProperty('--accent-primary', main);
}

// 应用主题模式（深浅色）：classic / colorful / dark
function applyThemeMode(mode: string) {
  document.documentElement.setAttribute('data-theme-mode', mode);
}

// 应用窗口材质（backdrop）：none / acrylic / mica / micaAlt
function applyWindowBackdrop(backdrop: string) {
  const root = document.documentElement;
  root.setAttribute('data-backdrop', backdrop);
  root.setAttribute('data-acrylic', (backdrop !== 'none').toString());
  const themeMode = localStorage.getItem('themeMode') || 'colorful';
  invoke('set_window_backdrop', { backdrop, themeMode }).catch((e: any) => {
    console.error('[Backdrop] Failed:', e);
  });
}

function hexToRgba(hex: string, alpha: number): string {
  const h = hex.replace('#', '');
  const r = parseInt(h.substring(0, 2), 16);
  const g = parseInt(h.substring(2, 4), 16);
  const b = parseInt(h.substring(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function applyCustomBg(path: string) {
  const app = document.getElementById('app');
  if (!app) return;
  app.style.backgroundImage = `url("file://${path}")`;
  app.style.backgroundSize = 'cover';
  app.style.backgroundPosition = 'center';
  app.style.backgroundRepeat = 'no-repeat';
}

// ========== 真实扫描（覆盖新 UI main.js 中不兼容的后端命令） ==========
const SCAN_BATCH_SIZE = 100; // 与旧版 main.js 的 BATCH=100 保持一致（云端哈希批量检查）
let scanState = {
  running: false, stop: false, files: [] as string[], index: 0, threats: 0,
  startTime: 0, lastCount: 0, lastTs: 0, speed: 0,
};

function showScanView(view: 'mode' | 'progress' | 'result') {
  const modeView = $('#scanModeView');
  const progressView = $('#scanProgressView');
  const resultView = $('#scanResultView');
  if (modeView) modeView.classList.toggle('hidden', view !== 'mode');
  if (progressView) progressView.classList.toggle('hidden', view !== 'progress');
  if (resultView) resultView.classList.toggle('hidden', view !== 'result');
}

function resetScanUI() {
  const title = $('#scanCardTitle'); if (title) title.textContent = 'Scanning...';
  const path = $('#scanFilePath'); if (path) path.textContent = 'Preparing to scan...';
  const fill = $('#scanProgressFill') as HTMLElement | null; if (fill) fill.style.width = '0%';
  const text = $('#scanProgressText'); if (text) text.textContent = '0%';
  ['statThreats', 'statScanned', 'statTotal'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '0';
  });
  const speed = $('#statSpeed'); if (speed) speed.textContent = '0';
  const elapsed = $('#statElapsed'); if (elapsed) elapsed.textContent = '0s';
  const area = $('#scanThreatsArea'); if (area) area.innerHTML = '';
  const empty = $('#scanThreatsEmpty'); if (empty) empty.style.display = 'flex';
  const bar = $('#scanProgressBar'); if (bar) bar.classList.remove('indeterminate', 'danger');
  const fillEl = $('#scanProgressFill') as HTMLElement | null; if (fillEl) fillEl.classList.remove('danger');
  const stopBtn = $('#scanStopBtn'); if (stopBtn) stopBtn.textContent = 'Stop';
}

function updateScanUIState() {
  const pct = scanState.files.length ? Math.min(100, Math.floor(scanState.index / scanState.files.length * 100)) : 0;
  const fill = $('#scanProgressFill') as HTMLElement | null; if (fill) fill.style.width = pct + '%';
  const text = $('#scanProgressText'); if (text) text.textContent = pct + '%';
  const scanned = $('#statScanned'); if (scanned) scanned.textContent = scanState.index.toLocaleString();
  const total = $('#statTotal'); if (total) total.textContent = scanState.files.length.toLocaleString();
  const elapsed = $('#statElapsed');
  if (elapsed) elapsed.textContent = Math.floor((Date.now() - scanState.startTime) / 1000) + 's';

  // 速度采用「平均速度」而非瞬时 EMA 采样：
  // 云端哈希是串行批次扫描，index 跳跃式增长，瞬时采样（count/dt）会因 dt 极短而飙到数万，严重失真。
  const elapsedSec = Math.max(1, (Date.now() - scanState.startTime) / 1000);
  scanState.speed = scanState.index / elapsedSec;
  const speedEl = $('#statSpeed');
  if (speedEl) speedEl.textContent = scanState.speed > 0.1 ? Math.round(scanState.speed) + '/s' : '0';

  const pathEl = $('#scanFilePath');
  if (pathEl && scanState.index > 0) {
    pathEl.textContent = scanState.files[Math.min(scanState.index - 1, scanState.files.length - 1)] || '';
  }
}

// 根据病毒家族名智能推断中文分类（与旧版 getThreatCategory 一致）
function inferThreatCategory(virusFamily?: string, familyCategory?: string): string | undefined {
  // 后端已提供分类，直接使用
  if (familyCategory) return familyCategory;
  const name = virusFamily;
  if (!name) return undefined;
  const lower = name.toLowerCase();

  // 勒索病毒
  if (lower.includes('ransom') || lower.includes('locky') || lower.includes('wannacry')) return '勒索病毒';
  // 蠕虫病毒
  if (lower.includes('worm') || lower.includes('nimda') || lower.includes('ramnit')) return '蠕虫病毒';
  // 挖矿程序
  if (lower.includes('miner') || lower.includes('xmrig')) return '挖矿程序';
  // 远程控制木马
  if (lower.includes('/asyncrat') || lower.includes('darkcomet') || lower.includes('dcrat')
    || lower.includes('gh0st') || lower.includes('nanocore') || lower.includes('poisonivy')
    || lower.includes('quasar') || lower.includes('remcos') || lower.includes('xworm')
    || lower.includes('/rat')) return '远程控制木马';
  // 银狐木马
  if (lower.includes('silverfox')) return '银狐木马';
  // 云端通用检测
  if (lower.includes('cloud/virus') || lower.includes('cloudscan/virus')) return '木马病毒';
  // 窃密木马
  if (lower.includes('agenttesla') || lower.includes('formbook') || lower.includes('redline')
    || lower.includes('spark') || lower.includes('vidar')) return '窃密木马';
  // 银行木马
  if (lower.includes('emotet')) return '银行木马';
  // 破坏性病毒
  if (lower.includes('killdisk') || lower.includes('raptor') || lower.includes('smileghost')
    || lower.includes('stonecutter') || lower.includes('unfixable') || lower.includes('vinememz')) return '破坏性病毒';
  // 恶意程序
  if (lower.includes('systemkiller') || lower.includes('terminator')) return '恶意程序';
  // 恶意安装程序
  if (lower.includes('rogue')) return '恶意安装程序';
  // 木马病毒（兜底）
  if (lower.includes('trojan') || lower.includes('heuristic')) return '木马病毒';

  return undefined;
}

function addScanThreatEntry(virusFamily: string, filePath: string, probability?: number, familyCategory?: string) {
  scanState.threats++;
  const empty = $('#scanThreatsEmpty');
  if (empty) empty.style.display = 'none';
  const area = $('#scanThreatsArea');
  if (area) {
    const entry = document.createElement('div');
    entry.className = 'scan-threat-entry';
    // 优先使用后端分类，否则根据病毒家族智能推断中文分类
    const cat = familyCategory || inferThreatCategory(virusFamily);
    const badge = cat ? `<span class="threat-category-badge">${escapeHtml(cat)}</span>` : '';
    entry.setAttribute('data-path', filePath);
    entry.innerHTML = `
      <input type="checkbox" class="threat-checkbox" checked>
      ${badge}
      <span class="threat-name">${escapeHtml(virusFamily || 'Malware')}</span>
      <span class="threat-path-simple" title="${escapeHtml(filePath)}">${escapeHtml(filePath)}</span>`;
    area.prepend(entry);
    while (area.children.length > 30) area.removeChild(area.lastChild!);
  }
  const tEl = $('#statThreats'); if (tEl) tEl.textContent = String(scanState.threats);
  const title = $('#scanCardTitle');
  if (title) title.innerHTML = `Detected <span class="scan-threat-count">${scanState.threats}</span> threats`;
  const bar = $('#scanProgressBar'); if (bar) bar.classList.add('danger');
  const fill = $('#scanProgressFill') as HTMLElement | null; if (fill) fill.classList.add('danger');
}

function showScanResultView(summary: string) {
  scanState.running = false;
  showScanView('result');
  const sEl = $('#scanResultSummary'); if (sEl) sEl.textContent = summary;
  const list = $('#scanResultList');
  const empty = $('#scanResultEmpty');
  const handleBtn = $('#scanHandleThreatsBtn');
  if (scanState.threats > 0) {
    if (empty) empty.classList.add('hidden');
    if (list) {
      list.classList.remove('hidden');
      list.innerHTML = Array.from(document.querySelectorAll('#scanThreatsArea .scan-threat-entry')).map(el => el.outerHTML).join('');
    }
    if (handleBtn) handleBtn.classList.remove('hidden');
  } else {
    if (list) list.classList.add('hidden');
    if (empty) empty.classList.remove('hidden');
    if (handleBtn) handleBtn.classList.add('hidden');
  }
}

const CLOUD_HASH_URL = 'https://cloudapi.xiguastudio.top';
const CLOUD_HASH_KEY = 'scan_dcc33b100b8a485fb099a5dce4c4f486';
const SCRIPT_EXTENSIONS = ['.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.sh'];

// ========== 云端哈希开关状态（统一迁移逻辑） ==========
// 旧版 CloudHashManager 使用 cloud_hash_enabled_v2 作为权威 key（默认开启）。
// 新 UI 早期误用 cloud_hash_enabled，导致「UI 开关显示开、扫描却读到 v2=false 关闭」。
// 这里统一以 cloud_hash_enabled_v2 为权威，并在读取时做迁移校正：
//   - 若 v2 未设置 → 采用旧 UI key 状态，默认开启；
//   - 若 v2 残留为 false 但旧 UI key / UI 显示为开 → 校正为开启（迁移用户意图）。
function isCloudHashEnabled(): boolean {
  const v2 = localStorage.getItem('cloud_hash_enabled_v2');
  if (v2 !== null) {
    // v2 已存在且为 true → 开启
    if (v2 === 'true') return true;
    // v2 为 false：若旧 UI key 表明用户是开的（非显式 false），则迁移为开
    const legacy = localStorage.getItem('cloud_hash_enabled');
    if (legacy !== 'false') {
      console.log('[CloudHash] v2=false 但 UI 为开，迁移为启用');
      localStorage.setItem('cloud_hash_enabled_v2', 'true');
      return true;
    }
    return false;
  }
  // v2 从未设置：默认继承旧 key，旧 key 未设置则默认开启（与旧版 CloudHashManager 一致）
  const legacy = localStorage.getItem('cloud_hash_enabled');
  const enabled = legacy === null || legacy === 'true';
  localStorage.setItem('cloud_hash_enabled_v2', String(enabled));
  return enabled;
}

function setCloudHashEnabled(enabled: boolean): void {
  localStorage.setItem('cloud_hash_enabled_v2', String(enabled));
  localStorage.setItem('cloud_hash_enabled', String(enabled));
}

function isScriptFile(fp: string): boolean {
  const lower = fp.toLowerCase();
  return SCRIPT_EXTENSIONS.some(ext => lower.endsWith(ext));
}

// 处理一批文件：脚本走脚本引擎，常规文件走「云端哈希 + 本地批量引擎」
async function scanBatchSlice(batch: string[]) {
  const scripts: string[] = [];
  const regular: string[] = [];
  for (const fp of batch) {
    if (isScriptFile(fp)) scripts.push(fp); else regular.push(fp);
  }

  // 脚本文件：脚本扫描引擎
  for (const fp of scripts) {
    if (scanState.stop) return;
    try {
      const res: any = await invoke('scan_script_file_command', { filePath: fp });
      if (res && res.is_malicious) {
        addScanThreatEntry(res.virus_family || 'Trojan.Win32.BAT.Generic', fp, res.threat_level || 0.9, '脚本威胁');
      }
    } catch (e) {
      // 脚本扫描失败时跳过
    }
  }

  if (regular.length === 0) return;

  // 1. 批量计算哈希
  let hashes: (string | null)[] = [];
  try {
    hashes = await invoke('calculate_file_hashes_command', { filePaths: regular });
  } catch (e) {
    hashes = regular.map(() => null);
  }

  const cloudEnabled = isCloudHashEnabled();
  console.log('[Scan] cloud_hash_enabled_v2 =', localStorage.getItem('cloud_hash_enabled_v2'), '=> cloudEnabled', cloudEnabled, ', batch size =', batch.length, ', valid hashes =', (hashes || []).filter(h => h).length);
  let localFiles = regular;
  let localHashes = hashes;

  // 2. 云端哈希批量查询（黑名单直接报毒，白名单跳过，其余回退本地）
  if (cloudEnabled) {
    const valid: { fp: string; hash: string | null }[] = regular
      .map((fp, i) => ({ fp, hash: hashes[i] || null }))
      .filter(x => x.hash);
    if (valid.length > 0) {
      try {
        const cloudRes: any = await invoke('cloud_hash_batch_command', {
          serverUrl: CLOUD_HASH_URL,
          apiKey: CLOUD_HASH_KEY,
          request: { hashes: valid.map(v => v.hash) },
        });
        // 与旧版一致：云端返回的 hash 可能与本地计算的大小写不同，统一转小写匹配
        console.log('[Scan] cloud batch response:', cloudRes);
        const cloudMap: Record<string, any> = {};
        for (const item of (cloudRes?.results || [])) cloudMap[String(item.hash).toLowerCase()] = item;
        const unknown: { fp: string; hash: string | null }[] = [];
        for (const v of valid) {
          const item = cloudMap[String(v.hash).toLowerCase()];
          if (!item) { unknown.push(v); continue; }
          if (item.result === 'black') {
            addScanThreatEntry(item.family || 'CloudHash', v.fp, 0.95, '云端威胁');
          } else if (item.result !== 'white') {
            unknown.push(v);
          }
        }
        localFiles = unknown.map(u => u.fp);
        localHashes = unknown.map(u => u.hash);
      } catch (e) {
        console.log('[Scan] cloud batch error, fallback local:', e);
      }
    }
  }

  if (localFiles.length === 0) return;

  // 3. 本地引擎批量扫描（带哈希可命中本地黑白名单）
  try {
    const res: any = await invoke('scan_batch_direct_with_hashes', { filePaths: localFiles, hashes: localHashes });
    const results = JSON.parse(res);
    for (const r of results) {
      if (scanState.stop) return;
      if (r && r.result === 'MALICIOUS') {
        addScanThreatEntry(r.virus_family || 'Trojan.Generic', r.file_path, r.probability || 0.9, r.family_category || '恶意威胁');
      }
    }
  } catch (e) {
    // 批量失败时逐文件兜底（修复 isThreat 键名）
    for (const fp of localFiles) {
      if (scanState.stop) return;
      try {
        const res: any = await invoke('scan_file_basic', { filePath: fp });
        if (res && res.isThreat) {
          addScanThreatEntry(res.threatName || 'Trojan.Generic', fp, res.confidence || 0.9, '恶意威胁');
        }
      } catch (e2) {
        // 单文件扫描失败时跳过
      }
    }
  }
}

async function startRealScan(mode: string) {
  if (scanState.running) return;
  resetScanUI();
  scanState = {
    running: true, stop: false, files: [], index: 0, threats: 0,
    startTime: Date.now(), lastCount: 0, lastTs: 0, speed: 0,
  };
  showScanView('progress');

  const scanType = mode === 'full' ? '全盘扫描' : (mode === 'custom' ? '自定义扫描' : '快速扫描');

  // 记录扫描开始事件（安全日志 + 时间线）
  try {
    await invoke('add_scan_timeline_event', {
      eventType: 'start',
      title: `${scanType}开始`,
      description: `开始执行${scanType}`,
      scannedFiles: 0,
      threatsFound: 0,
    });
  } catch (e) {
    console.error('[Scan] Failed to add start timeline event:', e);
  }

  // 快速扫描开局：先扫描内存活动模块（运行中的进程镜像）
  if (mode === 'quick') {
    try {
      const memOutcome: any = await invoke('scan_running_processes_command');
      if (memOutcome && Array.isArray(memOutcome.threats)) {
        for (const t of memOutcome.threats) {
          if (!t || t.is_memory_threat !== true || t.result !== 'MALICIOUS') continue;
          addScanThreatEntry(
            t.virus_family || 'Memory Threat',
            `${t.process_name || ''} (PID ${t.pid}) -> ${t.image_path || ''}`,
            t.probability || 0.9,
            '内存活动威胁',
          );
        }
      }
    } catch (e) {
      console.warn('[Scan] Memory scan failed, continue:', e);
    }
  }

  try {
    let files: string[] = [];
    if (mode === 'quick') {
      files = await invoke('get_scan_files');
    } else if (mode === 'full') {
      files = await invoke('get_full_scan_files');
    } else {
      const selected = await window.__TAURI__.dialog.open({
        directory: true, multiple: false, title: '选择要扫描的文件夹',
      });
      if (typeof selected !== 'string' || !selected) {
        scanState.running = false;
        showScanView('mode');
        return;
      }
      files = await invoke('get_scan_files_direct', { paths: [selected] });
    }

    scanState.files = files || [];
    const total = $('#statTotal');
    if (total) total.textContent = scanState.files.length.toLocaleString();
    if (scanState.files.length === 0) {
      showScanResultView('扫描完成：没有找到可扫描的文件');
      return;
    }

    // 多路并发批次流水线（每路独立拉取批次，互不重叠）
    const CONCURRENCY = 4;
    let nextStart = 0;
    const grabBatch = (): string[] | null => {
      if (nextStart >= scanState.files.length) return null;
      const start = nextStart;
      nextStart += SCAN_BATCH_SIZE;
      return scanState.files.slice(start, start + SCAN_BATCH_SIZE);
    };
    // 定时刷新 UI（云端查询等待期间速度/进度也能持续更新，而非仅 batch 完成时跳变）
    const refreshTimer = window.setInterval(() => { updateScanUIState(); }, 250);
    const workers = Array.from({ length: CONCURRENCY }, async () => {
      while (!scanState.stop) {
        const batch = grabBatch();
        if (!batch) break;
        await scanBatchSlice(batch);
        scanState.index += batch.length;
        updateScanUIState();
        await new Promise(r => setTimeout(r, 16));
      }
    });
    await Promise.all(workers);
    window.clearInterval(refreshTimer);

    if (scanState.stop) {
      // 累计本次扫描文件数，刷新主页"已扫描文件"
      const prev = parseInt(localStorage.getItem('xigua_files_scanned') || '0', 10);
      localStorage.setItem('xigua_files_scanned', String(prev + scanState.index));
      showScanResultView(`扫描已停止：已扫描 ${scanState.index.toLocaleString()} 个文件，发现 ${scanState.threats} 个威胁`);
      initHomeStats(); // 刷新主页"已扫描文件"
      return;
    }
    localStorage.setItem('xigua_threats_blocked', String(scanState.threats));
    // 累计本次扫描文件数，刷新主页"已扫描文件"
    {
      const prev = parseInt(localStorage.getItem('xigua_files_scanned') || '0', 10);
      localStorage.setItem('xigua_files_scanned', String(prev + scanState.index));
    }
    const elapsed = Math.floor((Date.now() - scanState.startTime) / 1000);
    showScanResultView(`扫描完成：发现 ${scanState.threats} 个威胁，扫描 ${scanState.index.toLocaleString()} 个文件，用时 ${elapsed} 秒`);
    initHomeStats(); // 刷新主页"已扫描文件"

    // 记录扫描完成事件
    try {
      await invoke('add_scan_timeline_event', {
        eventType: 'completed',
        title: '扫描完成',
        description: `扫描完成，发现 ${scanState.threats} 个威胁`,
        scannedFiles: scanState.index,
        threatsFound: scanState.threats,
      });
    } catch (e) {
      console.error('[Scan] Failed to add complete timeline event:', e);
    }
  } catch (e) {
    console.log('[Scan] error:', e);
    scanState.running = false;
    showScanView('mode');
  }
}

function initRealScan() {
  // capture 阶段拦截，覆盖新 UI main.js 中不兼容后端命令的扫描逻辑
  document.querySelectorAll<HTMLButtonElement>('.action-card[data-mode]').forEach(card => {
    card.addEventListener('click', (e) => {
      e.stopImmediatePropagation();
      e.preventDefault();
      startRealScan(card.dataset.mode || 'quick');
    }, true);
  });
  $('#scanStopBtn')?.addEventListener('click', (e) => {
    e.stopImmediatePropagation();
    if (scanState.running) {
      scanState.stop = true;
    } else {
      showScanView('mode');
    }
  }, true);
  $('#scanDoneBtn')?.addEventListener('click', (e) => {
    e.stopImmediatePropagation();
    showScanView('mode');
  }, true);
  $('#scanHandleThreatsBtn')?.addEventListener('click', async (e) => {
    e.stopImmediatePropagation();
    // 收集所有勾选的威胁条目路径
    const selected: string[] = [];
    $$('#scanThreatsArea .scan-threat-entry').forEach(el => {
      const cb = el.querySelector<HTMLInputElement>('.threat-checkbox');
      if (cb && cb.checked) {
        const path = el.getAttribute('data-path');
        if (path) selected.push(path);
      }
    });
    if (selected.length === 0) {
      showToast('未选中任何威胁项');
      return;
    }
    try {
      const res: any = await invoke('quarantine_scan_files', { paths: selected });
      const quarantined = res?.quarantined ?? 0;
      showToast(`已隔离 ${quarantined} 个威胁项`);
      renderQuarantine();
    } catch (err) {
      console.error('[Scan] quarantine failed:', err);
      showToast('处理失败：' + String(err));
    }
    showScanView('mode');
  }, true);
}

// ========== 页面切换时的数据加载 ==========
function initPageDataHooks() {
  const navBtns = $$('.nav-btn[data-page]');
  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const page = btn.dataset.page;
      if (page === 'quarantine') renderQuarantine();
      else if (page === 'logs') renderLogs();
    });
  });

  // 主页操作按钮：跳转目标跟随 data-page（防护未开启/部分开启→防护页，正常→扫描页）
  $('.home-scan-btn')?.addEventListener('click', (e) => {
    const btn = e.currentTarget as HTMLElement;
    navigateTo(btn.dataset.page || 'scan');
  });
}

// ========== 白名单管理弹窗（进程 / 路径 / 域名） ==========
function openWhitelistDialog() {
  const existing = document.getElementById('whitelist-dialog');
  if (existing) existing.remove();
  const modal = document.createElement('div');
  modal.id = 'whitelist-dialog';
  modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 9999;';
  modal.innerHTML = `
    <div style="background: #fff; border-radius: 12px; width: 560px; max-width: 92vw; max-height: 82vh; overflow: auto; box-shadow: 0 16px 48px rgba(0,0,0,0.2); font-family: 'Segoe UI Variable', 'Segoe UI', 'Microsoft YaHei UI', system-ui, sans-serif;">
      <div style="display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid #eee;">
        <div style="font-size: 16px; font-weight: 600;">${t('settings.whitelist')}</div>
        <button id="whitelist-dialog-close" style="border: none; background: transparent; font-size: 18px; cursor: pointer; color: #888;">×</button>
      </div>
      <div style="padding: 16px 20px; display: flex; flex-direction: column; gap: 18px;">
        <div>
          <div style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">Process</div>
          <div style="display: flex; gap: 8px; margin-bottom: 8px;">
            <input id="wl-process-input" placeholder="notepad.exe" style="flex: 1; padding: 8px 12px; border: 1px solid #e5e5ea; border-radius: 6px; font-size: 13px; outline: none;">
            <button class="btn btn-primary btn-sm" id="wl-process-add">${t('settings.whitelistAdd')}</button>
          </div>
          <div id="wl-process-list" style="max-height: 140px; overflow-y: auto; border: 1px solid #eee; border-radius: 6px; padding: 4px;"></div>
        </div>
        <div>
          <div style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">Path</div>
          <div style="display: flex; gap: 8px; margin-bottom: 8px;">
            <input id="wl-path-input" placeholder="C:\\Program Files\\..." style="flex: 1; padding: 8px 12px; border: 1px solid #e5e5ea; border-radius: 6px; font-size: 13px; outline: none;">
            <button class="btn btn-primary btn-sm" id="wl-path-add">${t('settings.whitelistAdd')}</button>
          </div>
          <div id="wl-path-list" style="max-height: 140px; overflow-y: auto; border: 1px solid #eee; border-radius: 6px; padding: 4px;"></div>
        </div>
        <div>
          <div style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">Domain</div>
          <div style="display: flex; gap: 8px; margin-bottom: 8px;">
            <input id="wl-domain-input" placeholder="example.com" style="flex: 1; padding: 8px 12px; border: 1px solid #e5e5ea; border-radius: 6px; font-size: 13px; outline: none;">
            <button class="btn btn-primary btn-sm" id="wl-domain-add">${t('settings.whitelistAdd')}</button>
          </div>
          <div id="wl-domain-list" style="max-height: 140px; overflow-y: auto; border: 1px solid #eee; border-radius: 6px; padding: 4px;"></div>
        </div>
      </div>
    </div>`;
  document.body.appendChild(modal);

  const renderList = (el: HTMLElement | null, items: string[], removeFn: (v: string) => Promise<unknown>) => {
    if (!el) return;
    if (items.length === 0) {
      el.innerHTML = '<div style="padding: 12px; color: #999; font-size: 13px; text-align: center;">-</div>';
      return;
    }
    el.innerHTML = items.map(it => `
      <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; border-bottom: 1px solid #f5f5f5; font-size: 13px;">
        <span style="font-family: Consolas, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(it)}</span>
        <button class="wl-remove" data-v="${escapeHtml(it)}" style="border: none; background: transparent; color: #ff3b30; cursor: pointer; font-size: 15px; flex-shrink: 0;">×</button>
      </div>`).join('');
    el.querySelectorAll<HTMLButtonElement>('.wl-remove').forEach(btn => {
      btn.addEventListener('click', async () => {
        try { await removeFn(btn.dataset.v!); refreshAll(); } catch (e) { /* ignore */ }
      });
    });
  };

  const refreshAll = () => {
    invoke('get_whitelist_processes_command').then((p: any) => renderList($('#wl-process-list'), p || [], (v) => invoke('remove_whitelist_process_command', { name: v }))).catch(() => {});
    invoke('get_whitelist_paths_command').then((p: any) => renderList($('#wl-path-list'), p || [], (v) => invoke('remove_whitelist_path_command', { path: v }))).catch(() => {});
    invoke('get_whitelist_domains_command').then((p: any) => renderList($('#wl-domain-list'), p || [], (v) => invoke('remove_whitelist_domain_command', { domain: v }))).catch(() => {});
  };

  const bindAdd = (inputId: string, addBtnId: string, cmd: string, argKey: string) => {
    const input = document.getElementById(inputId) as HTMLInputElement | null;
    const btn = document.getElementById(addBtnId);
    const doAdd = async () => {
      const v = input?.value.trim();
      if (!v) return;
      try {
        await invoke(cmd, { [argKey]: v });
        if (input) input.value = '';
        refreshAll();
      } catch (e) { alert(`添加失败：${e}`); }
    };
    btn?.addEventListener('click', doAdd);
    input?.addEventListener('keydown', (e) => { if (e.key === 'Enter') doAdd(); });
  };
  bindAdd('wl-process-input', 'wl-process-add', 'add_whitelist_process_command', 'name');
  bindAdd('wl-path-input', 'wl-path-add', 'add_whitelist_path_command', 'path');
  bindAdd('wl-domain-input', 'wl-domain-add', 'add_whitelist_domain_command', 'domain');

  refreshAll();
  $('#whitelist-dialog-close')?.addEventListener('click', () => modal.remove());
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
}

// ========== 窗口拖动（通过 Tauri IPC 实现） ==========
function initWindowDrag() {
  const titlebar = document.querySelector<HTMLElement>('.titlebar');
  if (!titlebar) return;

  titlebar.addEventListener('mousedown', async (e: MouseEvent) => {
    if (e.button !== 0) return;
    const target = e.target as HTMLElement;
    // 排除按钮和交互元素
    if (target.closest('button, input, select, .ctrl-btn, .titlebar-menu-dropdown, .toggle, .sidebar-toggle')) return;

    // Tauri 2 原生拖拽 API
    try {
      await getCurrentWindow().startDragging();
      return;
    } catch {}

    // 回退：通过 IPC invoke 调用
    try {
      await invoke('plugin:window|start_dragging');
      return;
    } catch {}

    // 回退：旧版 __TAURI__ API
    try {
      if (window.__TAURI__?.window?.getCurrentWindow) {
        await window.__TAURI__.window.getCurrentWindow().startDragging();
      }
    } catch {}
  });

  titlebar.addEventListener('dragstart', (e) => e.preventDefault());
}

// ========== 自定义下拉框 ==========
function initCustomSelects() {
  document.querySelectorAll<HTMLElement>('.custom-select').forEach(container => {
    const trigger = container.querySelector('.custom-select-trigger') as HTMLElement;
    const options = container.querySelector('.custom-select-options') as HTMLElement;
    const target = container.getAttribute('data-target'); // 'theme-select' or 'language-select'
    const valueEl = container.querySelector('.custom-select-value') as HTMLElement;

    // 设置初始值
    if (target === 'theme-select') {
      const saved = localStorage.getItem('theme') || 'blue';
      const opt = options.querySelector<HTMLElement>(`[data-value="${saved}"]`);
      if (opt) {
        valueEl.textContent = opt.textContent;
        options.querySelectorAll('[data-selected]').forEach(o => o.removeAttribute('data-selected'));
        opt.setAttribute('data-selected', '');
      }
    } else if (target === 'theme-mode-select') {
      const saved = localStorage.getItem('themeMode') || 'colorful';
      const opt = options.querySelector<HTMLElement>(`[data-value="${saved}"]`);
      if (opt) {
        valueEl.textContent = opt.textContent;
        options.querySelectorAll('[data-selected]').forEach(o => o.removeAttribute('data-selected'));
        opt.setAttribute('data-selected', '');
      }
    } else if (target === 'window-backdrop-select') {
      const saved = localStorage.getItem('windowBackdrop') || 'none';
      const opt = options.querySelector<HTMLElement>(`[data-value="${saved}"]`);
      if (opt) {
        valueEl.textContent = opt.textContent;
        options.querySelectorAll('[data-selected]').forEach(o => o.removeAttribute('data-selected'));
        opt.setAttribute('data-selected', '');
      }
    } else if (target === 'language-select') {
      const saved = localStorage.getItem('language') || 'zh-CN';
      const opt = options.querySelector<HTMLElement>(`[data-value="${saved}"]`);
      if (opt) {
        valueEl.textContent = opt.textContent;
        options.querySelectorAll('[data-selected]').forEach(o => o.removeAttribute('data-selected'));
        opt.setAttribute('data-selected', '');
      }
    }

    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      // 关闭其他已打开的 dropdown
      document.querySelectorAll<HTMLElement>('.custom-select.open').forEach(el => {
        if (el !== container) el.classList.remove('open');
      });
      container.classList.toggle('open');
    });

    options.querySelectorAll<HTMLElement>('.custom-select-option').forEach(opt => {
      opt.addEventListener('click', () => {
        const value = opt.getAttribute('data-value') || '';
        const text = opt.textContent || '';
        valueEl.textContent = text;
        options.querySelectorAll('[data-selected]').forEach(o => o.removeAttribute('data-selected'));
        opt.setAttribute('data-selected', '');
        container.classList.remove('open');

        if (target === 'theme-select') {
          localStorage.setItem('theme', value);
          applyTheme(value);
        } else if (target === 'theme-mode-select') {
          localStorage.setItem('themeMode', value);
          applyThemeMode(value);
        } else if (target === 'window-backdrop-select') {
          localStorage.setItem('windowBackdrop', value);
          applyWindowBackdrop(value);
        } else if (target === 'language-select') {
          localStorage.setItem('language', value);
          invoke('set_language', { lang: value }).catch(() => {});
          location.reload();
        }
      });
    });
  });

  // 点击外部关闭
  document.addEventListener('click', () => {
    document.querySelectorAll<HTMLElement>('.custom-select.open').forEach(el => el.classList.remove('open'));
  });
}

// ========== 自动更新与公告 ==========
interface UpdateInfo {
  has_update: boolean;
  current_version: string;
  latest_version: string;
  download_url?: string;
  release_notes?: string;
}

async function checkUpdateOnStartup() {
  try {
    console.log('[AutoUpdate] Checking for updates on startup...');
    const result = await invoke<string>('check_update_command');
    const updateInfo = JSON.parse(result) as UpdateInfo;
    if (updateInfo && updateInfo.has_update) {
      console.log(`[AutoUpdate] New version available: ${updateInfo.latest_version}`);
      showUpdateNotification(updateInfo);
    } else {
      console.log('[AutoUpdate] No updates available');
      fetchAndShowAnnouncement();
    }
  } catch (error) {
    console.error('[AutoUpdate] Failed to check update:', error);
    fetchAndShowAnnouncement();
  }
}

async function fetchAndShowAnnouncement() {
  try {
    console.log('[Announcement] Fetching latest announcement...');
    const announcement = await invoke<{id: string, title: string, content: string, publish_date: string} | null>('fetch_announcement_command');
    if (announcement) {
      console.log(`[Announcement] Got announcement: ${announcement.title}, id: ${announcement.id}`);
      const shownAnnouncements: string[] = JSON.parse(localStorage.getItem('shownAnnouncements') || '[]');
      if (!shownAnnouncements.includes(announcement.id)) {
        showAnnouncementNotification(announcement);
        shownAnnouncements.push(announcement.id);
        localStorage.setItem('shownAnnouncements', JSON.stringify(shownAnnouncements));
      } else {
        console.log('[Announcement] Already shown this announcement');
      }
    } else {
      console.log('[Announcement] No announcement available');
    }
  } catch (error) {
    console.error('[Announcement] Failed to fetch announcement:', error);
  }
}

function showAnnouncementNotification(announcement: {id: string, title: string, content: string, publish_date: string}) {
  const el = document.createElement('div');
  el.className = 'app-notification-popup';
  el.style.cssText = `position:fixed;top:60px;right:20px;background:var(--bg-panel,#fff);border:1px solid var(--border-color,#e0e0e0);border-radius:12px;padding:16px 20px;box-shadow:0 8px 32px rgba(0,0,0,0.15);z-index:99999;width:360px;max-height:400px;animation:slideIn 0.3s ease;pointer-events:auto;display:flex;flex-direction:column;gap:10px;`;
  const contentHtml = announcement.content
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/&lt;(\/?)(b|br|strong|em|i|u|p|span|div|a|ul|ol|li|h[1-6])\b[^&]*&gt;/gi, '<$1$2>');
  el.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
      <div style="font-weight:600;font-size:14px;color:var(--text-primary,#333);">${announcement.title}</div>
      <div style="font-size:11px;color:var(--text-secondary,#999);white-space:nowrap;">${new Date(announcement.publish_date).toLocaleDateString('zh-CN')}</div>
    </div>
    <div style="font-size:13px;color:var(--text-secondary,#666);line-height:1.5;overflow-y:auto;max-height:300px;">${contentHtml}</div>
    <button class="popup-close-btn" style="position:absolute;top:12px;right:12px;background:none;border:none;color:#999;font-size:18px;cursor:pointer;padding:2px 6px;border-radius:4px;line-height:1;">×</button>
  `;
  document.body.appendChild(el);
  el.querySelector('.popup-close-btn')?.addEventListener('click', () => {
    el.style.animation = 'slideOut 0.3s ease forwards';
    setTimeout(() => el.remove(), 300);
  });
  setTimeout(() => { if (el.parentNode) { el.style.animation = 'slideOut 0.3s ease forwards'; setTimeout(() => el.remove(), 300); } }, 180000);
}

function showUpdateNotification(updateInfo: UpdateInfo) {
  const el = document.createElement('div');
  el.className = 'app-notification-popup';
  el.style.cssText = `position:fixed;top:60px;right:20px;background:var(--bg-panel,#fff);border:1px solid var(--border-color,#e0e0e0);border-radius:12px;padding:20px 24px;box-shadow:0 8px 32px rgba(0,0,0,0.15);z-index:99999;width:420px;animation:slideIn 0.3s ease;pointer-events:auto;`;
  let releaseNotes = updateInfo.release_notes || '暂无更新说明';
  if (releaseNotes.length > 500) releaseNotes = releaseNotes.substring(0, 500) + '...';
  const notesHtml = releaseNotes
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/&lt;(\/?)(b|br|strong|em|i|u|p|span|div|a|ul|ol|li|h[1-6])\b[^&]*&gt;/gi, '<$1$2>');
  el.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;gap:12px;">
      <div style="font-weight:600;font-size:15px;color:var(--text-primary,#333);">发现新版本 v${updateInfo.latest_version}</div>
      <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
        <button class="update-download-btn" style="padding:6px 16px;background:var(--primary,#00BFA5);color:#fff;border:none;border-radius:6px;font-size:13px;cursor:pointer;font-weight:500;">立即更新</button>
        <button class="popup-close-btn" style="background:none;border:none;color:#999;font-size:18px;cursor:pointer;padding:2px 6px;border-radius:4px;line-height:1;">×</button>
      </div>
    </div>
    <div style="font-size:12px;color:var(--text-secondary,#666);margin-bottom:8px;">点击按钮即可下载更新</div>
    <div style="margin-top:10px;padding:12px;background:var(--bg-hover,#f8f9fa);border-radius:8px;max-height:180px;overflow-y:auto;border:1px solid var(--border-color,#e9ecef);font-size:12px;color:var(--text-secondary,#555);line-height:1.6;">
      <div style="font-size:12px;font-weight:600;color:var(--text-primary,#333);margin-bottom:8px;">更新内容</div>
      <div>${notesHtml}</div>
    </div>
    <div class="update-progress" style="display:none;margin-top:8px;">
      <div style="height:4px;background:var(--bg-hover,#e9ecef);border-radius:2px;overflow:hidden;">
        <div class="update-progress-bar" style="height:100%;width:0%;background:var(--primary,#00BFA5);border-radius:2px;transition:width 0.3s;"></div>
      </div>
      <div class="update-progress-text" style="font-size:11px;color:var(--text-secondary,#999);margin-top:4px;">准备下载...</div>
    </div>
  `;
  document.body.appendChild(el);

  el.querySelector('.popup-close-btn')?.addEventListener('click', () => {
    el.style.animation = 'slideOut 0.3s ease forwards';
    setTimeout(() => { el.remove(); fetchAndShowAnnouncement(); }, 300);
  });
  el.querySelector('.update-download-btn')?.addEventListener('click', async () => {
    const btn = el.querySelector('.update-download-btn') as HTMLButtonElement;
    const progressContainer = el.querySelector('.update-progress') as HTMLElement;
    const progressBar = el.querySelector('.update-progress-bar') as HTMLElement;
    const progressText = el.querySelector('.update-progress-text') as HTMLElement;
    if (!updateInfo.download_url) { showToast('下载地址不可用'); return; }
    btn.disabled = true;
    btn.textContent = '下载中...';
    progressContainer.style.display = 'block';
    try {
      await invoke('download_update_command', { url: updateInfo.download_url });
      progressBar.style.width = '100%';
      progressText.textContent = '下载完成，请重启应用以安装更新';
      btn.textContent = '完成';
    } catch (e) {
      console.error('[AutoUpdate] Download failed:', e);
      progressText.textContent = '下载失败，请稍后重试';
      btn.disabled = false;
      btn.textContent = '重试';
    }
  });
}

// ========== 引擎概览（含 AVIC 云端情报、云端哈希状态） ==========
function showEngineOverview() {
  const existing = document.getElementById('engine-overlay');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'engine-overlay';
  modal.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.25); display: flex; align-items: center; justify-content: center;
    z-index: 10001; backdrop-filter: blur(4px); font-family: 'Segoe UI Variable','Segoe UI',system-ui,sans-serif;
  `;

  const cloudHashOn = isCloudHashEnabled();
  const rows: Array<{ name: string; status: string; desc: string; version: string; color: string }> = [
    { name: 'HeySafe ML (ONNX)', status: '已就绪', desc: '本地机器学习引擎', version: '1.0.0', color: '#107C10' },
    { name: 'Signature Engine', status: '已加载', desc: '本地特征码引擎', version: '1.0.0', color: '#107C10' },
    { name: 'Cloud Hash 哈希库', status: cloudHashOn ? '已启用' : '未启用', desc: '云端哈希批量查杀（http://cloudapi.xiguastudio.top）', version: 'v2', color: cloudHashOn ? '#107C10' : '#9D9D9D' },
  ];

  modal.innerHTML = `
    <div style="background:#fff;border-radius:8px;max-width:640px;width:92%;box-shadow:0 32px 64px rgba(0,0,0,0.15),0 0 0 1px rgba(0,0,0,0.05);overflow:hidden;max-height:80vh;display:flex;flex-direction:column;">
      <div style="padding:24px 24px 0 24px;">
        <div style="font-size:18px;font-weight:600;color:#1C1C1C;margin-bottom:4px;">${t('menu.engine')}</div>
        <div style="font-size:13px;color:#5F5F5F;margin-bottom:12px;" id="engine-overview-sub">正在检测引擎状态...</div>
      </div>
      <div style="flex:1;overflow-y:auto;padding:0 24px;min-height:80px;">
        <table style="width:100%;border-collapse:collapse;font-size:13px;" id="engine-overview-table">
          <thead>
            <tr style="border-bottom:2px solid #EDEDED;">
              <th style="text-align:left;padding:8px 12px;color:#5F5F5F;font-weight:500;">引擎名称</th>
              <th style="text-align:left;padding:8px 12px;color:#5F5F5F;font-weight:500;">状态</th>
              <th style="text-align:left;padding:8px 12px;color:#5F5F5F;font-weight:500;">说明</th>
              <th style="text-align:left;padding:8px 12px;color:#5F5F5F;font-weight:500;">版本</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map(r => `
              <tr style="border-bottom:1px solid #F3F3F3;">
                <td style="padding:10px 12px;font-weight:500;color:#1A1A1A;">${r.name}</td>
                <td style="padding:10px 12px;">
                  <span style="display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:500;background:${r.color}18;color:${r.color};">
                    <span style="width:6px;height:6px;border-radius:50%;background:${r.color};"></span>${r.status}
                  </span>
                </td>
                <td style="padding:10px 12px;color:#5F5F5F;">${r.desc}</td>
                <td style="padding:10px 12px;color:#9D9D9D;font-size:12px;">${r.version}</td>
              </tr>`).join('')}
            <tr id="avic-row" style="border-bottom:1px solid #F3F3F3;">
              <td style="padding:10px 12px;font-weight:500;color:#1A1A1A;">AVIC 云端情报库</td>
              <td style="padding:10px 12px;"><span id="avic-status" style="display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:500;background:#9D9D9D18;color:#9D9D9D;"><span style="width:6px;height:6px;border-radius:50%;background:#9D9D9D;"></span>检测中</span></td>
              <td style="padding:10px 12px;color:#5F5F5F;">主动防御·云端威胁信誉库（驱动/文件/进程防护前置拦截）</td>
              <td style="padding:10px 12px;color:#9D9D9D;font-size:12px;">v1</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div style="display:flex;justify-content:flex-end;padding:16px 24px 24px 24px;background:#F3F3F3;border-top:1px solid rgba(0,0,0,0.05);">
        <button id="engine-close-btn" style="padding:6px 16px;border:none;background:#005FB8;border-radius:4px;font-size:14px;color:#fff;cursor:pointer;min-width:80px;">${t('scan.done')}</button>
      </div>
    </div>`;
  document.body.appendChild(modal);

  document.getElementById('engine-close-btn')?.addEventListener('click', () => modal.remove());
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });

  // 检测 AVIC 云端情报库连接状态
  const avicStatus = document.getElementById('avic-status');
  Promise.allSettled([
    invoke<boolean>('avic_is_configured'),
    invoke<string>('test_avic_connection'),
  ]).then(([cfg, conn]) => {
    const configured = cfg.status === 'fulfilled' ? cfg.value : false;
    const ok = conn.status === 'fulfilled' && /ok|connected|success|已连接|成功/i.test(String(conn.value));
    if (avicStatus) {
      if (configured && ok) {
        avicStatus.innerHTML = '<span style="width:6px;height:6px;border-radius:50%;background:#107C10;"></span>已连接';
        avicStatus.style.cssText = 'display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:500;background:#107C10!important;color:#107C10;';
      } else {
        avicStatus.innerHTML = '<span style="width:6px;height:6px;border-radius:50%;background:#A80000;"></span>未连接';
        avicStatus.style.cssText = 'display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:500;background:#A80000!important;color:#A80000;';
      }
    }
    const sub = document.getElementById('engine-overview-sub');
    if (sub) sub.textContent = `共 ${rows.length + 1} 个引擎 · 云端引擎实时检测`;
  }).catch(() => {
    if (avicStatus) {
      avicStatus.innerHTML = '<span style="width:6px;height:6px;border-radius:50%;background:#9D9D9D;"></span>未知';
    }
  });
}

// ========== 首次启动气泡功能导览（OOBE Tour） ==========
// 进入主界面后，用高亮遮罩 + 指向真实侧边栏按钮的气泡，在真实页面间切换并逐个介绍功能。
function showOOBE() {
  if (document.getElementById('oobe-root')) return;

  // 每个步骤：高亮某个侧边栏按钮(data-page)，气泡展示说明，并切到对应真实页面
  const steps = [
    { page: 'home', sel: '.nav-btn[data-page="home"]', t: '概览', d: '这里是防护总览，显示保护状态、拦截统计与建议操作。', pos: 'right' },
    { page: 'scan', sel: '.nav-btn[data-page="scan"]', t: '病毒扫描', d: '提供快速扫描、全盘扫描和自定义扫描，扫描时通过云端哈希批量查杀未知威胁。', pos: 'right' },
    { page: 'protection', sel: '.nav-btn[data-page="protection"]', t: '实时防护', d: '实时守护系统，包括文件、网页、网络、身份与增强端点防护，发现威胁立即拦截。', pos: 'right' },
    { page: 'quarantine', sel: '.nav-btn[data-page="quarantine"]', t: '隔离区', d: '存放被拦截的可疑文件，可查看详情、恢复误报或彻底删除。', pos: 'right' },
    { page: 'logs', sel: '.nav-btn[data-page="logs"]', t: '安全日志', d: '记录每次扫描与拦截事件，支持导出，方便回溯排查。', pos: 'right' },
    { page: 'settings', sel: '.nav-btn[data-page="settings"]', t: '设置', d: '在这里可配置主题、语言、开机自启、白名单、病毒库更新与重置等。', pos: 'right' },
    { page: 'home', sel: '.home-scan-btn', t: '快速开始', d: '点击这里即可一键快速扫描。现在你已经掌握全部核心功能了！', pos: 'bottom' },
  ];

  let step = 0;

  const overlay = document.createElement('div');
  overlay.id = 'oobe-root';
  overlay.style.cssText = `
    position: fixed; inset: 0; z-index: 99998; pointer-events: none;
    font-family: 'Microsoft YaHei UI', 'Microsoft YaHei', 'Segoe UI', system-ui, sans-serif;
  `;

  // 高亮遮罩（用 box-shadow 在目标元素周围打亮）
  const spotlight = document.createElement('div');
  spotlight.style.cssText = `
    position: fixed; z-index: 1; border-radius: 10px; transition: all 0.35s cubic-bezier(0.22, 1, 0.36, 1);
    box-shadow: 0 0 0 9999px rgba(10, 15, 30, 0.55), 0 0 0 2px rgba(0,191,165,0.8), 0 8px 32px rgba(0,0,0,0.3);
  `;
  // 气泡（必须 pointer-events: auto，否则父级 overlay 的 pointer-events:none 会让按钮点不到）
  const bubble = document.createElement('div');
  bubble.style.cssText = `
    position: fixed; z-index: 2; width: 300px; background: #fff; border-radius: 14px;
    box-shadow: 0 16px 48px rgba(0,0,0,0.25); padding: 20px; pointer-events: auto;
    transition: all 0.35s cubic-bezier(0.22, 1, 0.36, 1); transform-origin: left center;
  `;

  overlay.appendChild(spotlight);
  overlay.appendChild(bubble);
  document.body.appendChild(overlay);

  function render() {
    const s = steps[step];
    const target = document.querySelector<HTMLElement>(s.sel);
    if (!target) { step++; render(); return; }
    // 切换到真实页面
    navigateTo(s.page);
    const r = target.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    // 高亮框
    spotlight.style.left = (r.left - 6) + 'px';
    spotlight.style.top = (r.top - 6) + 'px';
    spotlight.style.width = (r.width + 12) + 'px';
    spotlight.style.height = (r.height + 12) + 'px';
    // 先写入气泡内容（含按钮），以便测量真实尺寸后再定位
    bubble.style.left = '0px';
    bubble.style.top = '0px';
    bubble.style.animation = 'none';
    bubble.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
        <span style="font-size:13px;font-weight:700;color:#00BFA5;letter-spacing:1px;">${step + 1} / ${steps.length}</span>
        <button id="oobe-close" style="border:none;background:transparent;color:#9AA3AF;cursor:pointer;font-size:16px;line-height:1;">×</button>
      </div>
      <div style="font-size:16px;font-weight:700;color:#1A1A1A;margin-bottom:6px;">${s.t}</div>
      <div style="font-size:13.5px;color:#5F6B7A;line-height:1.7;margin-bottom:16px;">${s.d}</div>
      <div style="display:flex;justify-content:flex-end;gap:8px;">
        ${step > 0 ? `<button id="oobe-prev" style="padding:8px 16px;border:1px solid #d9dee5;border-radius:8px;background:#fff;cursor:pointer;font-size:13px;color:#555;">上一步</button>` : ''}
        ${step < steps.length - 1 ? `<button id="oobe-skip" style="padding:8px 12px;border:none;background:transparent;cursor:pointer;font-size:13px;color:#9AA3AF;">跳过</button>` : ''}
        <button id="oobe-next" style="padding:8px 20px;border:none;border-radius:8px;background:#00BFA5;color:#fff;cursor:pointer;font-size:13px;font-weight:600;">${step === steps.length - 1 ? '完成' : '下一步'}</button>
      </div>`;

    bubble.querySelector('#oobe-close')?.addEventListener('click', finish);
    bubble.querySelector('#oobe-prev')?.addEventListener('click', () => { step = Math.max(0, step - 1); render(); });
    bubble.querySelector('#oobe-skip')?.addEventListener('click', finish);
    bubble.querySelector('#oobe-next')?.addEventListener('click', () => {
      if (step === steps.length - 1) { finish(); return; }
      step++; render();
    });

    // 依据气泡真实尺寸定位，并确保完全在视口内（底部按钮/侧边栏底部按钮不再超出窗口）
    const bw = bubble.offsetWidth || 300;
    const bh = bubble.offsetHeight || 220;
    const GAP = 16;
    const MARGIN = 12;
    let left: number;
    let top: number;
    if (s.pos === 'right') {
      // 侧边栏按钮在左 → 气泡放右侧；若放不下再放左侧
      if (r.right + GAP + bw <= vw - MARGIN) {
        left = r.right + GAP;
      } else if (r.left - GAP - bw >= MARGIN) {
        left = r.left - GAP - bw;
      } else {
        left = vw - MARGIN - bw;
      }
      // 垂直方向对齐目标中间，并钳制到视口内
      top = r.top + r.height / 2 - bh / 2;
    } else {
      // 下方优先，放不下则放上方
      if (r.bottom + GAP + bh <= vh - MARGIN) {
        top = r.bottom + GAP;
      } else {
        top = r.top - GAP - bh;
      }
      left = r.left + r.width / 2 - bw / 2;
    }
    left = Math.max(MARGIN, Math.min(left, vw - MARGIN - bw));
    top = Math.max(MARGIN, Math.min(top, vh - MARGIN - bh));
    bubble.style.left = left + 'px';
    bubble.style.top = top + 'px';
    bubble.style.animation = 'oobePop 0.3s cubic-bezier(0.22,1,0.36,1)';
  }

  function finish() {
    localStorage.setItem('oobe_completed', 'true');
    overlay.style.transition = 'opacity 0.3s';
    overlay.style.opacity = '0';
    setTimeout(() => overlay.remove(), 300);
  }

  render();
}

function init() {
  // 初始化自定义下拉框
  initCustomSelects();
  // 初始化主题（本地设置）与界面语言
  applyI18n();
  const savedTheme = localStorage.getItem('theme') || 'blue';
  applyTheme(savedTheme);
  // 主题模式（深浅色）；窗口材质已隐藏/弃用，启动时固定为 none，避免亚克力/云母 bug
  applyThemeMode(localStorage.getItem('themeMode') || 'colorful');
  localStorage.setItem('windowBackdrop', 'none');
  applyWindowBackdrop('none');
  const savedBg = localStorage.getItem('custom_bg_path');
  if (savedBg) applyCustomBg(savedBg);

  initWindowControls();
  initWindowDrag();
  initMenu();
  initHomeStats();
  initProtectionPage();
  initSettingsPage();
  initEndpointProtection();
  initRealtimeFileProtection();
  initBasicProtection();
  initLogsToolbar();
  initRealScan();
  initPageDataHooks();
  updateNotificationBadge();

  // 首次渲染隔离区/日志（页面已存在于 DOM）
  setTimeout(() => {
    renderQuarantine();
    renderLogs();
  }, 300);

  // 首次启动：等待页面渲染完成后启动气泡功能导览
  if (localStorage.getItem('oobe_completed') !== 'true') {
    setTimeout(() => {
      if (localStorage.getItem('oobe_completed') !== 'true') showOOBE();
    }, 600);
  }

  // 记录启动通知（首次启动）
  if (!localStorage.getItem('xigua_welcomed')) {
    localStorage.setItem('xigua_welcomed', '1');
    addNotification('欢迎使用 XIGUASecurity 10x', '新 UI 已启用，所有防护功能均已接入真实引擎。', 'system');
  }

  console.log('[Bridge] XIGUASecurity 新 UI 桥接层已加载');

  // 启动后延迟3秒检查更新（避免影响启动速度）
  setTimeout(() => {
    checkUpdateOnStartup();
  }, 3000);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
