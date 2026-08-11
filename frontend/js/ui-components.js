// ERROR-PANEL — Professional UI Components Kit
// Toast, Confirm Modal, Skeleton Loader, Empty States, Offline Detection

'use strict';

// ── Toast System (Enhanced) ──────────────────────────────────────────────
const TOAST_ICONS = {
  success: '✓',
  error: '✗',
  warning: '⚠',
  info: 'ℹ',
};

class ToastManager {
  constructor() {
    this.container = document.getElementById('toast-container');
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.id = 'toast-container';
      this.container.className = 'toast-container';
      document.body.appendChild(this.container);
    }
  }

  show(message, type = 'info', duration = 3500) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icon = document.createElement('span');
    icon.className = 'toast-icon';
    icon.textContent = TOAST_ICONS[type] || TOAST_ICONS.info;
    
    const text = document.createElement('span');
    text.className = 'toast-text';
    text.textContent = message;
    
    const progress = document.createElement('div');
    progress.className = 'toast-progress';
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'toast-close';
    closeBtn.innerHTML = '&times;';
    closeBtn.onclick = () => this.dismiss(toast);
    
    toast.appendChild(icon);
    toast.appendChild(text);
    toast.appendChild(progress);
    toast.appendChild(closeBtn);
    
    this.container.appendChild(toast);
    
    // Animate progress bar
    progress.style.animation = `toastProgress ${duration}ms linear`;
    
    // Auto dismiss
    const timer = setTimeout(() => this.dismiss(toast), duration);
    
    // Pause on hover
    toast.addEventListener('mouseenter', () => {
      clearTimeout(timer);
      progress.style.animationPlayState = 'paused';
    });
    
    toast.addEventListener('mouseleave', () => {
      progress.style.animationPlayState = 'running';
      setTimeout(() => this.dismiss(toast), 1000);
    });
    
    return toast;
  }

  dismiss(toast) {
    if (!toast || !toast.parentNode) return;
    toast.classList.add('toast-out');
    setTimeout(() => toast.remove(), 300);
  }
}

const toastManager = new ToastManager();
function toast(message, type = 'info', duration = 3500) {
  return toastManager.show(message, type, duration);
}

// ── Confirm Modal (Professional) ─────────────────────────────────────────
class ConfirmModal {
  constructor() {
    this.overlay = null;
    this.modal = null;
    this.resolve = null;
    this.init();
  }

  init() {
    this.overlay = document.createElement('div');
    this.overlay.className = 'confirm-overlay';
    this.overlay.innerHTML = `
      <div class="confirm-modal">
        <div class="confirm-icon-wrapper">
          <div class="confirm-icon">⚠</div>
        </div>
        <h3 class="confirm-title">تایید عملیات</h3>
        <p class="confirm-message"></p>
        <div class="confirm-actions">
          <button class="btn btn-ghost confirm-cancel">انصراف</button>
          <button class="btn btn-danger confirm-ok">تایید</button>
        </div>
      </div>
    `;
    
    document.body.appendChild(this.overlay);
    
    this.modal = this.overlay.querySelector('.confirm-modal');
    this.messageEl = this.overlay.querySelector('.confirm-message');
    this.okBtn = this.overlay.querySelector('.confirm-ok');
    this.cancelBtn = this.overlay.querySelector('.confirm-cancel');
    
    this.okBtn.addEventListener('click', () => this.handleConfirm(true));
    this.cancelBtn.addEventListener('click', () => this.handleConfirm(false));
    this.overlay.addEventListener('click', (e) => {
      if (e.target === this.overlay) this.handleConfirm(false);
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (this.overlay.classList.contains('open')) {
        if (e.key === 'Escape') this.handleConfirm(false);
        if (e.key === 'Enter') this.handleConfirm(true);
      }
    });
  }

  show(message, title = 'تایید عملیات', options = {}) {
    this.overlay.querySelector('.confirm-title').textContent = title;
    this.messageEl.textContent = message;
    
    if (options.danger) {
      this.okBtn.className = 'btn btn-danger confirm-ok';
      this.okBtn.textContent = options.confirmText || 'حذف';
    } else {
      this.okBtn.className = 'btn btn-accent confirm-ok';
      this.okBtn.textContent = options.confirmText || 'تایید';
    }
    this.cancelBtn.textContent = options.cancelText || 'انصراف';
    
    this.overlay.classList.add('open');
    
    return new Promise((resolve) => {
      this.resolve = resolve;
      this.okBtn.focus();
    });
  }

  handleConfirm(result) {
    this.overlay.classList.remove('open');
    if (this.resolve) {
      this.resolve(result);
      this.resolve = null;
    }
  }
}

const confirmModal = new ConfirmModal();
async function confirmAction(message, options = {}) {
  return await confirmModal.show(message, options.title, options);
}

// ── Skeleton Loader ──────────────────────────────────────────────────────
class SkeletonLoader {
  static table(container, rows = 5, cols = 6) {
    let html = '';
    for (let i = 0; i < rows; i++) {
      html += '<tr>';
      for (let j = 0; j < cols; j++) {
        const width = 60 + Math.random() * 40;
        html += `<td><div class="skeleton skeleton-line" style="width:${width}%"></div></td>`;
      }
      html += '</tr>';
    }
    container.innerHTML = html;
  }

  static cards(container, count = 3) {
    let html = '';
    for (let i = 0; i < count; i++) {
      html += `
        <div class="source-card">
          <div class="skeleton skeleton-title"></div>
          <div class="skeleton skeleton-line" style="width:80%;margin-top:12px"></div>
          <div class="skeleton skeleton-line" style="width:60%;margin-top:8px"></div>
          <div class="skeleton skeleton-line" style="width:40%;margin-top:8px"></div>
        </div>
      `;
    }
    container.innerHTML = html;
  }

  static kpi(container, count = 4) {
    let html = '';
    for (let i = 0; i < count; i++) {
      html += `
        <div class="kpi-card">
          <div class="skeleton skeleton-value"></div>
          <div class="skeleton skeleton-label"></div>
        </div>
      `;
    }
    container.innerHTML = html;
  }
}

// ── Empty States ─────────────────────────────────────────────────────────
class EmptyState {
  static render(container, { icon = '📭', title = 'داده‌ای یافت نشد', message = 'هنوز هیچ آیتمی اضافه نشده است', action = null } = {}) {
    const html = `
      <div class="empty-state">
        <div class="empty-icon">${icon}</div>
        <h3 class="empty-title">${title}</h3>
        <p class="empty-message">${message}</p>
        ${action ? `<button class="btn btn-accent empty-action" onclick="${action.handler}">${action.label}</button>` : ''}
      </div>
    `;
    container.innerHTML = html;
  }
}

// ── Loading Button Wrapper ───────────────────────────────────────────────
class LoadingButton {
  static async wrap(button, asyncFn) {
    const originalHTML = button.innerHTML;
    const originalDisabled = button.disabled;
    
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span> در حال انجام...';
    button.classList.add('btn-loading');
    
    try {
      const result = await asyncFn();
      return result;
    } finally {
      button.disabled = originalDisabled;
      button.innerHTML = originalHTML;
      button.classList.remove('btn-loading');
    }
  }
}

// ── Offline Detection ────────────────────────────────────────────────────
class OfflineDetector {
  constructor() {
    this.banner = null;
    this.init();
  }

  init() {
    this.banner = document.createElement('div');
    this.banner.className = 'offline-banner';
    this.banner.innerHTML = `
      <span class="offline-icon">📡</span>
      <span class="offline-text">اتصال به سرور قطع شده است</span>
      <button class="offline-retry" onclick="offlineDetector.retry()">تلاش مجدد</button>
    `;
    document.body.insertBefore(this.banner, document.body.firstChild);
    
    this.checkStatus();
    setInterval(() => this.checkStatus(), 10000);
  }

  async checkStatus() {
    try {
      const res = await fetch(API_BASE + '/health', { 
        method: 'GET',
        cache: 'no-cache',
        signal: AbortSignal.timeout(3000)
      });
      if (res.ok) {
        this.hide();
      } else {
        this.show();
      }
    } catch (e) {
      this.show();
    }
  }

  show() {
    if (this.banner.classList.contains('visible')) return;
    this.banner.classList.add('visible');
  }

  hide() {
    this.banner.classList.remove('visible');
  }

  async retry() {
    this.banner.querySelector('.offline-text').textContent = 'در حال تلاش مجدد...';
    await this.checkStatus();
  }
}

const offlineDetector = new OfflineDetector();

// ── Keyboard Shortcuts ───────────────────────────────────────────────────
class KeyboardShortcuts {
  constructor() {
    this.shortcuts = new Map();
    this.init();
  }

  init() {
    document.addEventListener('keydown', (e) => {
      // Ignore if user is typing in an input
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      
      // Ctrl/Cmd + F = Focus search
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        const search = document.getElementById('servers-search');
        if (search) search.focus();
      }
      
      // Ctrl/Cmd + R = Refresh current tab
      if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
        e.preventDefault();
        const activeTab = document.querySelector('.nav-list a.active');
        if (activeTab) {
          const tab = activeTab.getAttribute('data-tab');
          onTabSwitch(tab);
        }
      }
      
      // Number keys 1-7 to switch tabs (with Alt)
      if (e.altKey && e.key >= '1' && e.key <= '7') {
        e.preventDefault();
        const tabs = ['dashboard', 'servers', 'sources', 'quarantine', 'analytics', 'settings', 'logs'];
        const tab = tabs[parseInt(e.key) - 1];
        const link = document.querySelector(`.nav-list a[data-tab="${tab}"]`);
        if (link) link.click();
      }
    });
  }
}

const keyboardShortcuts = new KeyboardShortcuts();

// ── Auto Retry for Failed Requests ───────────────────────────────────────
async function fetchWithRetry(url, options = {}, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(url, options);
      if (res.ok) return res;
      if (res.status < 500 && res.status !== 429) {
        // Client error, don't retry
        return res;
      }
    } catch (e) {
      if (i === retries - 1) throw e;
    }
    
    // Exponential backoff
    await new Promise(r => setTimeout(r, 1000 * Math.pow(2, i)));
  }
}
