// Engine Management System - 直接使用Rust内置扫描器
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// ── 深度分析通知 ──
let deepAnalysisNotifEl: HTMLDivElement | null = null;

function showDeepAnalysisNotification() {
  hideDeepAnalysisNotification();
  const el = document.createElement('div');
  el.className = 'cloud-scan-notification';
  el.innerHTML = `
    <div class="cloud-scan-notification-content">
      <div class="cloud-scan-notification-title">正在提交云端沙箱分析</div>
      <div class="cloud-scan-progress-container">
        <div class="cloud-scan-progress-bar" id="da-progress-bar"></div>
      </div>
      <div class="cloud-scan-progress-text" id="da-progress-text">准备上传...</div>
    </div>
    <button class="cloud-scan-notification-close">×</button>
  `;
  el.style.cssText = `
    position: fixed; top: 60px; right: 20px;
    background: #ffffff; border: 1px solid #e0e0e0;
    border-radius: 12px; padding: 16px 20px;
    display: flex; align-items: center; gap: 16px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.15);
    z-index: 99999; animation: slideIn 0.3s ease;
    pointer-events: auto; min-width: 300px;
  `;
  const closeBtn = el.querySelector('.cloud-scan-notification-close') as HTMLButtonElement;
  closeBtn?.addEventListener('click', () => {
    el.style.animation = 'slideOut 0.3s ease forwards';
    setTimeout(() => { el.remove(); deepAnalysisNotifEl = null; }, 300);
  });
  document.body.appendChild(el);
  deepAnalysisNotifEl = el;

  // 注入 CSS（如果还未注入）
  if (!document.getElementById('da-notif-css')) {
    const s = document.createElement('style');
    s.id = 'da-notif-css';
    s.textContent = `
      .cloud-scan-notification-content { flex: 1; }
      .cloud-scan-notification-title { font-weight: 600; color: #333; margin-bottom: 4px; font-size: 14px; }
      .cloud-scan-progress-container {
        width: 100%; height: 4px; background: #e5e7eb;
        border-radius: 2px; margin-top: 8px; overflow: hidden;
      }
      .cloud-scan-progress-bar {
        height: 100%; background: #3b82f6; border-radius: 2px;
        width: 0%; transition: width 0.3s ease;
      }
      .cloud-scan-progress-text { font-size: 11px; color: #666; margin-top: 4px; }
      .cloud-scan-notification-close {
        background: none; border: none; color: #999;
        font-size: 20px; cursor: pointer; padding: 0 4px;
        line-height: 1; flex-shrink: 0;
      }
      .cloud-scan-notification-close:hover { color: #666; }
    `;
    document.head.appendChild(s);
  }
}

function updateDeepAnalysisProgress(percent: number, status: string) {
  const bar = document.getElementById('da-progress-bar');
  const text = document.getElementById('da-progress-text');
  if (bar) bar.style.width = `${Math.min(percent, 100)}%`;
  if (text) text.textContent = status;
}

function hideDeepAnalysisNotification() {
  if (deepAnalysisNotifEl) {
    deepAnalysisNotifEl.remove();
    deepAnalysisNotifEl = null;
  }
}

// Engine Types
export interface EngineConfig {
  id: string;
  name: string;
  version: string;
  type: 'local' | 'remote' | 'cloud';
  enabled: boolean;
  path?: string;
  pipeName?: string;
  description: string;
}

export interface ScanResult {
  file_path: string;
  file_hash?: string;
  result: 'CLEAN' | 'MALICIOUS' | 'ERROR' | 'TIMEOUT';
  probability: number;
  signature_status?: string;
  is_trusted?: boolean;
  error?: string;
  virus_family?: string;
  family_category?: string;
  is_infector?: boolean;
}

export interface EngineStatus {
  id: string;
  isRunning: boolean;
  isReady: boolean;
  lastError?: string;
}

// Default engines configuration - 现在只是UI展示用
export const DEFAULT_ENGINES: EngineConfig[] = [
  {
    id: 'melix-v2',
    name: 'Melix Engine V2',
    version: '2.0.0',
    type: 'local',
    enabled: true,
    description: '基于 ONNX 机器学习的本地扫描引擎，支持深度模式检测'
  },
  {
    id: 'signature-engine',
    name: 'Signature Engine',
    version: '1.0.0',
    type: 'local',
    enabled: true,
    description: '基于特征码的传统杀毒引擎'
  },
  {
    id: 'heuristic-engine',
    name: 'Heuristic Engine',
    version: '1.0.0',
    type: 'local',
    enabled: false,
    description: '启发式分析引擎，用于检测未知威胁'
  },
  {
    id: 'cloud-engine',
    name: 'Cloud Engine',
    version: '1.0.0',
    type: 'cloud',
    enabled: false,
    description: '云端查杀引擎，提供最新威胁情报'
  }
];

// Engine Manager - 简化版，直接使用Rust内置扫描器
export class EngineManager {
  private engines: EngineConfig[] = [];
  private engineStatuses: Map<string, EngineStatus> = new Map();
  private currentEngineId: string = 'melix-v2';

  constructor() {
    this.loadEngines();
  }

  private loadEngines() {
    // Force reset - clear old config
    localStorage.removeItem('engines');
    localStorage.removeItem('enginesVersion');
    
    // Always use default engines for now
    this.engines = [...DEFAULT_ENGINES];
    this.saveEngines();
    localStorage.setItem('enginesVersion', '2.0.2');

    const savedCurrent = localStorage.getItem('currentEngine');
    if (savedCurrent) {
      this.currentEngineId = savedCurrent;
    }
  }

  private saveEngines() {
    localStorage.setItem('engines', JSON.stringify(this.engines));
    localStorage.setItem('currentEngine', this.currentEngineId);
  }

  getEngines(): EngineConfig[] {
    return this.engines;
  }

  getEnabledEngines(): EngineConfig[] {
    return this.engines.filter(e => e.enabled);
  }

  getCurrentEngine(): EngineConfig | undefined {
    return this.engines.find(e => e.id === this.currentEngineId);
  }

  setCurrentEngine(id: string) {
    this.currentEngineId = id;
    this.saveEngines();
  }

  updateEngine(config: EngineConfig) {
    const index = this.engines.findIndex(e => e.id === config.id);
    if (index >= 0) {
      this.engines[index] = config;
      this.saveEngines();
    }
  }

  addEngine(config: EngineConfig) {
    this.engines.push(config);
    this.saveEngines();
  }

  removeEngine(id: string) {
    this.engines = this.engines.filter(e => e.id !== id);
    this.saveEngines();
  }

  toggleEngine(id: string, enabled: boolean) {
    const engine = this.engines.find(e => e.id === id);
    if (engine) {
      engine.enabled = enabled;
      this.saveEngines();
    }
  }

  // Check if engine is ready - 直接返回true，因为扫描器内置在Rust中
  async checkEngineStatus(engineId: string): Promise<EngineStatus> {
    const engine = this.engines.find(e => e.id === engineId);
    if (!engine) {
      return { id: engineId, isRunning: false, isReady: false, lastError: 'Engine not found' };
    }

    // 直接返回就绪状态，因为扫描器内置在Rust中
    const status: EngineStatus = { 
      id: engineId, 
      isRunning: true, 
      isReady: true 
    };
    this.engineStatuses.set(engineId, status);
    return status;
  }

  // Start local engine process - 不需要启动，扫描器内置
  async startEngine(_engineId: string): Promise<boolean> {
    // 扫描器内置在Rust中，不需要启动外部进程
    return true;
  }

  // Scan file using direct Rust scanner (with deep analysis support)
  async scanFile(filePath: string, _fileHash?: string): Promise<ScanResult> {
    // 注册深度分析事件监听
    const unlisteners: Array<() => void> = [];
    try {
      // deep-analysis-start
      const unlisten1 = await listen<any>('deep-analysis-start', () => {
        showDeepAnalysisNotification();
      });
      unlisteners.push(unlisten1);

      // deep-analysis-progress
      const unlisten2 = await listen<any>('deep-analysis-progress', (event) => {
        const { percent, status } = event.payload;
        updateDeepAnalysisProgress(percent || 0, status || '');
      });
      unlisteners.push(unlisten2);

      // deep-analysis-done
      const unlisten3 = await listen<any>('deep-analysis-done', (event) => {
        const { verdict, threatScore, threatFamily, malicious } = event.payload;
        const statusText = malicious
          ? `检测为恶意 (${verdict}) 威胁评分:${threatScore} 家族:${threatFamily || '未知'}`
          : `分析完成 (${verdict}) 威胁评分:${threatScore}`;
        updateDeepAnalysisProgress(100, statusText);
        setTimeout(hideDeepAnalysisNotification, 3000);
      });
      unlisteners.push(unlisten3);

      // deep-analysis-error
      const unlisten4 = await listen<any>('deep-analysis-error', (event) => {
        const { error } = event.payload;
        updateDeepAnalysisProgress(0, `失败: ${error || '未知错误'}`);
        setTimeout(hideDeepAnalysisNotification, 5000);
      });
      unlisteners.push(unlisten4);

      const result = await invoke<string>('scan_file_with_deep_analysis', { filePath });
      return JSON.parse(result) as ScanResult;
    } catch (error) {
      return {
        file_path: filePath,
        result: 'ERROR',
        probability: 0,
        error: String(error)
      };
    } finally {
      // 清理监听器
      unlisteners.forEach(fn => fn());
    }
  }

  // Batch scan files using direct Rust scanner
  async scanBatch(filePaths: string[]): Promise<ScanResult[]> {
    try {
      const result = await invoke<string>('scan_batch_direct', { filePaths });
      return JSON.parse(result) as ScanResult[];
    } catch (error) {
      return filePaths.map(fp => ({
        file_path: fp,
        result: 'ERROR' as const,
        probability: 0,
        error: String(error)
      }));
    }
  }

  // Batch scan files with precomputed hashes to avoid re-reading files
  async scanBatchWithHashes(filePaths: string[], hashMap: Map<string, string>): Promise<ScanResult[]> {
    try {
      const hashes: (string | null)[] = filePaths.map(fp => hashMap.get(fp) || null);
      const result = await invoke<string>('scan_batch_direct_with_hashes', { filePaths, hashes });
      return JSON.parse(result) as ScanResult[];
    } catch (error) {
      return filePaths.map(fp => ({
        file_path: fp,
        result: 'ERROR' as const,
        probability: 0,
        error: String(error)
      }));
    }
  }

}

// Export singleton instance
export const engineManager = new EngineManager();

// Update Types
export interface UpdateInfo {
  has_update: boolean;
  current_version: string;
  latest_version: string;
  download_url?: string;
  release_notes: string;
  file_hash?: string;
}

// Update Manager
export class UpdateManager {
  private currentVersion: string = '';

  async getCurrentVersion(): Promise<string> {
    try {
      this.currentVersion = await invoke<string>('get_version_command');
      return this.currentVersion;
    } catch (error) {
      console.error('Failed to get version:', error);
      return '0.1.0';
    }
  }

  async checkUpdate(): Promise<UpdateInfo | null> {
    try {
      const result = await invoke<string>('check_update_command');
      return JSON.parse(result) as UpdateInfo;
    } catch (error) {
      console.error('Failed to check update:', error);
      return null;
    }
  }

  async downloadUpdate(url: string): Promise<boolean> {
    try {
      await invoke('download_update_command', { url });
      return true;
    } catch (error) {
      console.error('Failed to download update:', error);
      return false;
    }
  }
}

// Export singleton instance
export const updateManager = new UpdateManager();
