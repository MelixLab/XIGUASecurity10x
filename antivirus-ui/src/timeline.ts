// 时间线事件类型
interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: 'block' | 'warning' | 'scan' | 'update' | 'system' | 'info';
  title: string;
  description: string;
  process_name?: string;
  result?: string;
}

// 图标 SVG
const Icons = {
  block: `<svg viewBox="0 0 24 24" fill="none" stroke="#dc3545" stroke-width="2" shape-rendering="geometricPrecision"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>`,
  warning: `<svg viewBox="0 0 24 24" fill="none" stroke="#ffc107" stroke-width="2" shape-rendering="geometricPrecision"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><circle cx="12" cy="17" r="1" fill="#ffc107" stroke="none"/></svg>`,
  scan: `<svg viewBox="0 0 24 24" fill="none" stroke="#2196F3" stroke-width="2" shape-rendering="geometricPrecision"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>`,
  update: `<svg viewBox="0 0 24 24" fill="none" stroke="#28a745" stroke-width="2" shape-rendering="geometricPrecision"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 21h5v-5"/></svg>`,
  system: `<svg viewBox="0 0 24 24" fill="none" stroke="#17a2b8" stroke-width="2" shape-rendering="geometricPrecision"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  info: `<svg viewBox="0 0 24 24" fill="none" stroke="#6c757d" stroke-width="2" shape-rendering="geometricPrecision"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><circle cx="12" cy="8" r="1" fill="#6c757d" stroke="none"/></svg>`,
};

// 按日期分组的事件
interface GroupedEvents {
  [date: string]: TimelineEvent[];
}

// 时间线管理器
class TimelineManager {
  private events: TimelineEvent[] = [];
  private currentFilter: string = 'all';
  private container: HTMLElement | null = null;

  constructor() {
    this.container = document.getElementById('timeline-container');
    this.init();
  }

  private async init() {
    this.setupFilters();
    await this.loadEvents();
    this.render();

    // 定期刷新
    setInterval(() => this.refresh(), 5000);
  }

  private setupFilters() {
    const filters = document.querySelectorAll('.timeline-filter');
    filters.forEach(filter => {
      filter.addEventListener('click', (e) => {
        const target = e.target as HTMLElement;
        const filterType = target.dataset.filter || 'all';
        
        // 更新激活状态
        filters.forEach(f => f.classList.remove('active'));
        target.classList.add('active');
        
        this.currentFilter = filterType;
        this.render();
      });
    });
  }

  private async loadEvents() {
    try {
      // 从后端获取真实的时间线事件
      const { invoke } = await import('@tauri-apps/api/core');
      const events = await invoke<TimelineEvent[]>('get_timeline_events');
      this.events = events;
      console.log('[Timeline] Loaded', events.length, 'events from backend');
    } catch (e) {
      console.error('Failed to load timeline events:', e);
      // 如果后端获取失败，显示空状态
      this.events = [];
    }
  }

  private getFilteredEvents(): TimelineEvent[] {
    if (this.currentFilter === 'all') {
      return this.events;
    }
    return this.events.filter(e => e.event_type === this.currentFilter);
  }

  // 按日期分组事件
  private groupEventsByDate(events: TimelineEvent[]): GroupedEvents {
    const grouped: GroupedEvents = {};
    
    events.forEach(event => {
      const date = new Date(event.timestamp);
      const dateKey = date.toLocaleDateString('zh-CN', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        weekday: 'long'
      });
      
      if (!grouped[dateKey]) {
        grouped[dateKey] = [];
      }
      grouped[dateKey].push(event);
    });
    
    return grouped;
  }

  private formatRelativeTime(timestamp: string): string {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return '刚刚';
    if (minutes < 60) return `${minutes} 分钟前`;
    if (hours < 24) return `${hours} 小时前`;
    if (days < 30) return `${days} 天前`;
    return date.toLocaleDateString('zh-CN');
  }

  private formatTime(timestamp: string): string {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('zh-CN', { 
      hour: '2-digit', 
      minute: '2-digit'
    });
  }

  private render() {
    if (!this.container) return;

    const filtered = this.getFilteredEvents();

    if (filtered.length === 0) {
      this.container.innerHTML = `
        <div class="timeline-empty">
          <svg class="timeline-empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 6v6l4 2"/>
          </svg>
          <h3>暂无记录</h3>
          <p>防护事件将在这里显示</p>
        </div>
      `;
      return;
    }

    // 按日期分组
    const grouped = this.groupEventsByDate(filtered);
    
    // 渲染分组后的内容
    let html = '';
    Object.entries(grouped).forEach(([date, events]) => {
      html += this.renderDateGroup(date, events);
    });
    
    this.container.innerHTML = html;
  }

  private renderDateGroup(date: string, events: TimelineEvent[]): string {
    const eventsHtml = events.map((event, index) => this.renderEvent(event, index, events.length)).join('');
    
    return `
      <div class="timeline-date-group">
        <div class="timeline-date-header">
          <span class="timeline-date-label">${date}</span>
          <span class="timeline-date-count">${events.length} 个事件</span>
        </div>
        <div class="timeline-date-events">
          ${eventsHtml}
        </div>
      </div>
    `;
  }

  private renderEvent(event: TimelineEvent, index: number, totalInGroup: number): string {
    const icon = Icons[event.event_type as keyof typeof Icons] || Icons.info;
    const relativeTime = this.formatRelativeTime(event.timestamp);
    const time = this.formatTime(event.timestamp);
    const isLastInGroup = index === totalInGroup - 1;

    return `
      <div class="timeline-item" data-id="${event.id}">
        <div class="timeline-left">
          <div class="timeline-dot ${event.event_type}"></div>
          ${!isLastInGroup ? '<div class="timeline-line"></div>' : ''}
          <div class="timeline-time">${time}</div>
        </div>
        <div class="timeline-content">
          <div class="timeline-card">
            <div class="timeline-card-header">
              <div class="timeline-icon">${icon}</div>
              <div class="timeline-title">${event.title}</div>
              <div class="timeline-relative-time">${relativeTime}</div>
            </div>
            <div class="timeline-description">${event.description}</div>
            ${this.renderMeta(event)}
          </div>
        </div>
      </div>
    `;
  }

  private renderMeta(event: TimelineEvent): string {
    const metaItems: string[] = [];
    
    if (event.process_name) {
      metaItems.push(`
        <div class="timeline-meta-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
            <line x1="8" y1="21" x2="16" y2="21"/>
            <line x1="12" y1="17" x2="12" y2="21"/>
          </svg>
          ${event.process_name}
        </div>
      `);
    }
    
    if (event.result) {
      metaItems.push(`
        <div class="timeline-meta-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          ${event.result}
        </div>
      `);
    }

    if (metaItems.length === 0) return '';

    return `<div class="timeline-meta">${metaItems.join('')}</div>`;
  }

  private async refresh() {
    // 重新加载数据
    await this.loadEvents();
    // 重新渲染以更新相对时间
    this.render();
  }
}

// 初始化
const timelineManager = new TimelineManager();

// 导出供其他模块使用
(window as any).timelineManager = timelineManager;
