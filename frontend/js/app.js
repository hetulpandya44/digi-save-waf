// Digi Save WAF - Shared JavaScript Utilities
const API_BASE = '/api';

// ============ AUTH ============
function getToken() { return localStorage.getItem('ds_token'); }
function setToken(token) { localStorage.setItem('ds_token', token); }
function getUsername() { return localStorage.getItem('ds_username'); }
function setUsername(name) { localStorage.setItem('ds_username', name); }

function requireAuth() {
    if (!getToken()) { window.location.href = '/login'; return false; }
    return true;
}

function logout() {
    localStorage.removeItem('ds_token');
    localStorage.removeItem('ds_username');
    window.location.href = '/login';
}

// ============ API HELPER ============
async function api(path, options = {}) {
    const url = `${API_BASE}${path}`;
    const headers = { 'Content-Type': 'application/json' };
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
        const resp = await fetch(url, { ...options, headers: { ...headers, ...(options.headers || {}) } });
        if (resp.status === 401) { logout(); return null; }
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Request failed');
        return data;
    } catch (err) {
        console.error('API Error:', err);
        throw err;
    }
}

async function apiGet(path) { return api(path); }
async function apiPost(path, body) { return api(path, { method: 'POST', body: JSON.stringify(body) }); }
async function apiPut(path, body) { return api(path, { method: 'PUT', body: JSON.stringify(body) }); }
async function apiDelete(path) { return api(path, { method: 'DELETE' }); }

// ============ TOAST ============
function showToast(message, type = 'info') {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(30px)'; setTimeout(() => toast.remove(), 300); }, 3500);
}

// ============ MODAL ============
function openModal(id) { document.getElementById(id)?.classList.add('active'); }
function closeModal(id) { document.getElementById(id)?.classList.remove('active'); }

// ============ FORMAT ============
function formatNumber(n) {
    if (n == null) return '0';
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toLocaleString();
}

function formatTimestamp(ts) {
    if (!ts) return '-';
    const d = new Date(typeof ts === 'number' ? ts * 1000 : ts);
    return d.toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function timeAgo(ts) {
    const seconds = Math.floor((Date.now() - new Date(typeof ts === 'number' ? ts * 1000 : ts).getTime()) / 1000);
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
    return Math.floor(seconds / 86400) + 'd ago';
}

// ============ RISK/ACTION COLORS ============
function getRiskBadge(level) {
    const map = {
        'Low': 'badge-info', 'Medium': 'badge-warning',
        'High': 'badge-danger', 'Critical': 'badge-critical',
        0: 'badge-info', 1: 'badge-warning', 2: 'badge-danger', 3: 'badge-critical'
    };
    const labels = { 0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical' };
    const cls = map[level] || 'badge-muted';
    const label = labels[level] || level || 'Unknown';
    return `<span class="badge-status ${cls}">${label}</span>`;
}

function getActionBadge(action) {
    if (action === 1 || action === 'Blocked')
        return '<span class="badge-status badge-danger"><span class="action-icon">⛔</span> BLOCKED</span>';
    return '<span class="badge-status badge-success"><span class="action-icon">✅</span> Passed</span>';
}

function getEnabledBadge(enabled) {
    return enabled
        ? '<span class="badge-status badge-success">● Active</span>'
        : '<span class="badge-status badge-muted">○ Disabled</span>';
}

// ============ SIDEBAR ============
function initSidebar(activePage) {
    const user = getUsername() || 'Admin';
    document.getElementById('sidebar-user-name').textContent = user;
    document.getElementById('sidebar-user-avatar').textContent = user.charAt(0).toUpperCase();

    document.querySelectorAll('.nav-item').forEach(item => {
        if (item.dataset.page === activePage) item.classList.add('active');
    });

    // Mobile toggle
    const toggle = document.getElementById('sidebar-toggle');
    if (toggle) {
        toggle.addEventListener('click', () => {
            document.querySelector('.sidebar').classList.toggle('open');
        });
    }
}

// ============ SIDEBAR HTML (reusable) ============
function getSidebarHTML(activePage) {
    const allPages = [
        { id: 'dashboard', icon: '📊', label: 'Dashboard', href: '/dashboard' },
        { id: 'sites', icon: '🌐', label: 'Protected Sites', href: '/sites' },
        { id: 'logs', icon: '🛡️', label: 'Detection Logs', href: '/logs' },
        { id: 'rules', icon: '📋', label: 'Policy Rules', href: '/rules' },
        { id: 'settings', icon: '⚙️', label: 'Settings', href: '/settings' },
    ];

    const renderNavItems = (pages) => pages.map(p => `
        <a href="${p.href}" class="nav-item ${p.id === activePage ? 'active' : ''}" data-page="${p.id}">
            <span class="nav-icon">${p.icon}</span>
            <span class="nav-label">${p.label}</span>
        </a>
    `).join('');

    return `
    <div class="sidebar" id="sidebar">
        <div class="sidebar-logo">
            <div class="logo-icon">🛡️</div>
            <div>
                <h2>Digi Save</h2>
                <span class="logo-subtitle">Web App Firewall</span>
            </div>
        </div>
        <nav class="sidebar-nav">
            <div class="nav-section">
                <div class="nav-section-title">Main Menu</div>
                ${renderNavItems(allPages)}
            </div>
        </nav>
        <div class="sidebar-footer">
            <div class="sidebar-user" onclick="logout()">
                <div class="avatar" id="sidebar-user-avatar">A</div>
                <div class="user-info">
                    <div class="user-name" id="sidebar-user-name">Admin</div>
                    <div class="user-role">Administrator</div>
                </div>
            </div>
        </div>
    </div>`;
}
