/**
 * Extic 访问监控与安全模块
 * - 记录访问日志
 * - Web 管理面板
 * - IP 黑名单
 * - 自动拉黑扫描器
 */

const fs = require('fs');
const path = require('path');
const chalk = require('chalk');

class SecurityManager {
    constructor(options = {}) {
        this.dataDir = options.dataDir || path.join(process.cwd(), '.extic');
        this.blacklistFile = path.join(this.dataDir, 'blacklist.json');
        this.accessLogFile = path.join(this.dataDir, 'access.json');
        this.loginLogFile = path.join(this.dataDir, 'login-attempts.json');
        this.geoCache = {}; // IP 地理位置缓存

        // 配置
        this.config = {
            // 404 次数阈值，超过则自动拉黑
            notFoundThreshold: options.notFoundThreshold || 10,
            // 统计时间窗口（毫秒）
            timeWindow: options.timeWindow || 60000, // 1分钟
            // 管理面板路径
            adminPath: options.adminPath || '/__extic_admin__',
            // 管理面板密码（建议设置）
            adminPassword: options.adminPassword || null,
            // 白名单 IP（永不拉黑）
            whitelist: options.whitelist || ['127.0.0.1', '::1', '::ffff:127.0.0.1'],
            // 登录失败限制
            loginMaxAttempts: options.loginMaxAttempts || 5,
            loginWindowMs: options.loginWindowMs || 10 * 60 * 1000, // 10分钟
            loginLockoutMs: options.loginLockoutMs || 60 * 60 * 1000 // 锁定1小时
        };

        // 运行时数据
        this.blacklist = new Set();
        this.accessLog = [];
        this.notFoundCounter = {}; // { ip: [timestamp, timestamp, ...] }
        this.loginAttempts = {}; // { ip: { attempts: [], lockedUntil: timestamp } }
        this.loginLog = []; // 登录尝试日志

        this._ensureDataDir();
        this._loadData();
    }

    _ensureDataDir() {
        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
        }
    }

    _loadData() {
        // 加载黑名单
        try {
            if (fs.existsSync(this.blacklistFile)) {
                const data = JSON.parse(fs.readFileSync(this.blacklistFile, 'utf8'));
                this.blacklist = new Set(data.ips || []);
                console.log(chalk.cyan(`[Security] 已加载 ${this.blacklist.size} 个黑名单 IP`));
            }
        } catch (e) {
            console.error(chalk.red('[Security] 加载黑名单失败:', e.message));
        }

        // 加载今日访问日志
        try {
            if (fs.existsSync(this.accessLogFile)) {
                const data = JSON.parse(fs.readFileSync(this.accessLogFile, 'utf8'));
                const today = new Date().toDateString();
                this.accessLog = (data.logs || []).filter(log =>
                    new Date(log.time).toDateString() === today
                );
            }
        } catch (e) {
            console.error(chalk.red('[Security] 加载访问日志失败:', e.message));
        }

        // 加载登录日志
        try {
            if (fs.existsSync(this.loginLogFile)) {
                const data = JSON.parse(fs.readFileSync(this.loginLogFile, 'utf8'));
                const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
                this.loginLog = (data.logs || []).filter(log =>
                    new Date(log.time).getTime() > weekAgo
                );
            }
        } catch (e) {
            console.error(chalk.red('[Security] 加载登录日志失败:', e.message));
        }
    }

    _saveBlacklist() {
        try {
            fs.writeFileSync(this.blacklistFile, JSON.stringify({
                ips: Array.from(this.blacklist),
                updatedAt: new Date().toISOString()
            }, null, 2));
        } catch (e) {
            console.error(chalk.red('[Security] 保存黑名单失败:', e.message));
        }
    }

    _saveAccessLog() {
        try {
            fs.writeFileSync(this.accessLogFile, JSON.stringify({
                logs: this.accessLog,
                updatedAt: new Date().toISOString()
            }, null, 2));
        } catch (e) {
            console.error(chalk.red('[Security] 保存访问日志失败:', e.message));
        }
    }

    _saveLoginLog() {
        try {
            fs.writeFileSync(this.loginLogFile, JSON.stringify({
                logs: this.loginLog,
                updatedAt: new Date().toISOString()
            }, null, 2));
        } catch (e) {
            console.error(chalk.red('[Security] 保存登录日志失败:', e.message));
        }
    }

    // 检查登录是否被锁定
    isLoginLocked(ip) {
        const record = this.loginAttempts[ip];
        if (!record) return false;
        if (record.lockedUntil && Date.now() < record.lockedUntil) return true;
        if (record.lockedUntil && Date.now() >= record.lockedUntil) {
            delete this.loginAttempts[ip];
        }
        return false;
    }

    // 获取锁定剩余时间（分钟）
    getLockoutRemaining(ip) {
        const record = this.loginAttempts[ip];
        if (!record || !record.lockedUntil) return 0;
        return Math.ceil((record.lockedUntil - Date.now()) / 60000);
    }

    // 记录登录失败
    recordLoginFailure(ip, password) {
        const now = Date.now();
        
        // 记录到日志
        this.loginLog.push({
            time: new Date().toISOString(),
            ip,
            password: password ? password.substring(0, 20) + (password.length > 20 ? '...' : '') : '(空)',
            success: false
        });
        
        // 只保留最近7天
        const weekAgo = now - 7 * 24 * 60 * 60 * 1000;
        this.loginLog = this.loginLog.filter(log => new Date(log.time).getTime() > weekAgo);
        setImmediate(() => this._saveLoginLog());
        
        // 白名单不限制
        if (this.config.whitelist.includes(ip)) return false;
        
        if (!this.loginAttempts[ip]) {
            this.loginAttempts[ip] = { attempts: [], lockedUntil: null };
        }
        
        this.loginAttempts[ip].attempts = this.loginAttempts[ip].attempts.filter(
            t => now - t < this.config.loginWindowMs
        );
        this.loginAttempts[ip].attempts.push(now);
        
        console.log(chalk.yellow(`[Security] 登录失败: IP=${ip}, 尝试=${this.loginAttempts[ip].attempts.length}/${this.config.loginMaxAttempts}`));
        
        if (this.loginAttempts[ip].attempts.length >= this.config.loginMaxAttempts) {
            this.loginAttempts[ip].lockedUntil = now + this.config.loginLockoutMs;
            console.log(chalk.red(`[Security] IP ${ip} 登录尝试过多，已锁定 ${this.config.loginLockoutMs / 60000} 分钟`));
            return true;
        }
        return false;
    }

    // 记录登录成功
    recordLoginSuccess(ip) {
        this.loginLog.push({
            time: new Date().toISOString(),
            ip,
            password: null,
            success: true
        });
        setImmediate(() => this._saveLoginLog());
        delete this.loginAttempts[ip];
        console.log(chalk.green(`[Security] 登录成功: IP=${ip}`));
    }

    // 获取登录日志
    getLoginLog() {
        return this.loginLog.slice().reverse();
    }

    // 获取真实 IP
    getRealIP(req) {
        // Cloudflare 真实 IP（优先）
        return req.headers['cf-connecting-ip']
            // 其他常见 header
            || req.headers['x-forwarded-for']?.split(',')[0].trim()
            || req.headers['x-real-ip']
            || req.ip
            || req.connection?.remoteAddress
            || 'unknown';
    }

    // 检查 IP 是否在黑名单
    isBlocked(ip) {
        return this.blacklist.has(ip);
    }

    // 添加 IP 到黑名单
    blockIP(ip, reason = 'manual') {
        if (this.config.whitelist.includes(ip)) {
            return false;
        }
        this.blacklist.add(ip);
        this._saveBlacklist();
        console.log(chalk.red(`[Security] IP 已拉黑: ${ip} (原因: ${reason})`));
        return true;
    }

    // 从黑名单移除 IP
    unblockIP(ip) {
        const removed = this.blacklist.delete(ip);
        if (removed) {
            this._saveBlacklist();
            console.log(chalk.green(`[Security] IP 已解除拉黑: ${ip}`));
        }
        return removed;
    }

    // 记录访问
    logAccess(req, statusCode = 200) {
        const ip = this.getRealIP(req);
        const log = {
            time: new Date().toISOString(),
            ip,
            method: req.method,
            url: req.originalUrl,
            host: req.get('host'),
            userAgent: req.get('user-agent'),
            statusCode,
            referer: req.get('referer') || null
        };

        this.accessLog.push(log);

        // 只保留今天的日志（内存优化）
        const today = new Date().toDateString();
        this.accessLog = this.accessLog.filter(l =>
            new Date(l.time).toDateString() === today
        );

        // 异步保存
        setImmediate(() => this._saveAccessLog());

        return log;
    }

    // 记录 404 并检查是否需要自动拉黑
    recordNotFound(req) {
        const ip = this.getRealIP(req);

        if (this.config.whitelist.includes(ip)) {
            return false;
        }

        const now = Date.now();

        // 初始化或清理过期记录
        if (!this.notFoundCounter[ip]) {
            this.notFoundCounter[ip] = [];
        }
        this.notFoundCounter[ip] = this.notFoundCounter[ip].filter(
            t => now - t < this.config.timeWindow
        );

        // 添加新记录
        this.notFoundCounter[ip].push(now);

        // 检查是否超过阈值
        if (this.notFoundCounter[ip].length >= this.config.notFoundThreshold) {
            this.blockIP(ip, `扫描检测: ${this.config.timeWindow / 1000}秒内访问了${this.notFoundCounter[ip].length}个不存在的文件`);
            delete this.notFoundCounter[ip];
            return true; // 已拉黑
        }

        return false;
    }

    // 查询 IP 地理位置（使用免费 API）
    async getGeoInfo(ip) {
        // 跳过本地 IP
        if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('::ffff:127.')) {
            return { country: 'LOCAL', countryCode: 'LOCAL', flag: '🏠' };
        }

        // 检查缓存
        const cleanIP = ip.replace('::ffff:', '');
        if (this.geoCache[cleanIP]) {
            return this.geoCache[cleanIP];
        }

        try {
            const http = require('http');

            return new Promise((resolve) => {
                const req = http.get(`http://ip-api.com/json/${cleanIP}?fields=status,country,countryCode,regionName,city`, { timeout: 5000 }, (res) => {
                    let data = '';
                    res.on('data', chunk => data += chunk);
                    res.on('end', () => {
                        try {
                            const json = JSON.parse(data);
                            if (json.status === 'success') {
                                const info = {
                                    country: json.country || 'Unknown',
                                    countryCode: json.countryCode || 'XX',
                                    flag: this._countryCodeToFlag(json.countryCode),
                                    city: json.city,
                                    region: json.regionName
                                };
                                this.geoCache[cleanIP] = info;
                                resolve(info);
                            } else {
                                resolve({ country: 'Unknown', countryCode: 'XX', flag: '🌐' });
                            }
                        } catch (e) {
                            resolve({ country: 'Unknown', countryCode: 'XX', flag: '🌐' });
                        }
                    });
                });
                req.on('error', () => resolve({ country: 'Unknown', countryCode: 'XX', flag: '🌐' }));
                req.on('timeout', () => {
                    req.destroy();
                    resolve({ country: 'Unknown', countryCode: 'XX', flag: '🌐' });
                });
            });
        } catch (e) {
            return { country: 'Unknown', countryCode: 'XX', flag: '🌐' };
        }
    }

    // 国家代码转 emoji 旗帜
    _countryCodeToFlag(countryCode) {
        if (!countryCode || countryCode.length !== 2) return '🌐';
        const codePoints = countryCode
            .toUpperCase()
            .split('')
            .map(char => 127397 + char.charCodeAt(0));
        return String.fromCodePoint(...codePoints);
    }

    // 获取今日访问统计（异步版本，包含地理信息）
    async getTodayStatsAsync() {
        const stats = this.getTodayStats();

        // 并行查询所有 IP 的地理信息
        const geoPromises = stats.visitors.map(async (v) => {
            v.geo = await this.getGeoInfo(v.ip);
            return v;
        });

        await Promise.all(geoPromises);
        return stats;
    }

    // 获取今日访问统计
    getTodayStats() {
        const today = new Date().toDateString();
        const todayLogs = this.accessLog.filter(log =>
            new Date(log.time).toDateString() === today
        );

        // 按 IP 分组
        const byIP = {};
        todayLogs.forEach(log => {
            if (!byIP[log.ip]) {
                byIP[log.ip] = {
                    ip: log.ip,
                    requests: [],
                    firstSeen: log.time,
                    lastSeen: log.time,
                    userAgent: log.userAgent
                };
            }
            byIP[log.ip].requests.push({
                time: log.time,
                method: log.method,
                url: log.url,
                status: log.statusCode
            });
            byIP[log.ip].lastSeen = log.time;
        });

        return {
            date: today,
            totalRequests: todayLogs.length,
            uniqueVisitors: Object.keys(byIP).length,
            visitors: Object.values(byIP).sort((a, b) =>
                new Date(b.lastSeen) - new Date(a.lastSeen)
            ),
            blacklistCount: this.blacklist.size
        };
    }

    // 生成管理面板 HTML
    getAdminHTML(stats) {
        const logoutBtn = this.config.adminPassword
            ? '<a href="' + this.config.adminPath + '/logout" style="color:#ff4757;text-decoration:none;font-size:0.9em;">🚪 退出登录</a>'
            : '';
        return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Extic 管理面板</title>
    <script src="https://cdn.jsdelivr.net/npm/@twemoji/api@latest/dist/twemoji.min.js" crossorigin="anonymous"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee; 
            padding: 20px;
            min-height: 100vh;
        }
        img.emoji { height: 1em; width: 1em; vertical-align: -0.1em; }
        .visitor-flag { font-size: 1.2em; margin-right: 6px; }
        .visitor-flag img.emoji { height: 1.1em; width: 1.1em; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        h1 { 
            color: #00d9ff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px; 
            margin-bottom: 20px;
        }
        .stat-card {
            background: #16213e;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .stat-card .number { 
            font-size: 2.5em; 
            font-weight: bold; 
            color: #00d9ff;
        }
        .stat-card .label { color: #888; margin-top: 5px; }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #16213e;
            padding-bottom: 10px;
        }
        .tab {
            background: transparent;
            border: none;
            color: #888;
            padding: 10px 20px;
            cursor: pointer;
            font-size: 1em;
            border-radius: 8px 8px 0 0;
            transition: all 0.2s;
        }
        .tab:hover { color: #fff; background: #16213e; }
        .tab.active { 
            color: #00d9ff; 
            background: #16213e;
            border-bottom: 2px solid #00d9ff;
        }
        .tab-content { animation: fadeIn 0.2s ease; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .login-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 15px;
            background: #0f0f23;
            border-radius: 6px;
            margin-bottom: 8px;
            font-family: monospace;
            font-size: 0.85em;
        }
        .login-item.success { border-left: 3px solid #2ed573; }
        .login-item.fail { border-left: 3px solid #ff4757; }
        .failed-pwd { 
            color: #ff4757; 
            background: #2a1a1a; 
            padding: 2px 8px; 
            border-radius: 3px; 
        }
        .section { 
            background: #16213e; 
            border-radius: 10px; 
            padding: 20px;
            margin-bottom: 20px;
        }
        .section h2 { 
            color: #00d9ff; 
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #333;
        }
        .visitor {
            background: #0f0f23;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
        }
        .visitor-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .visitor-ip {
            font-family: monospace;
            font-size: 1.1em;
            color: #fff;
        }
        .visitor-ip.blocked { color: #ff4757; text-decoration: line-through; }
        .visitor-flag { font-size: 1.4em; margin-right: 8px; cursor: help; }
        .visitor-meta { color: #666; font-size: 0.85em; }
        .visitor-requests {
            max-height: 200px;
            overflow-y: auto;
            font-size: 0.9em;
        }
        .request {
            padding: 5px 10px;
            border-left: 3px solid #333;
            margin: 5px 0;
            font-family: monospace;
        }
        .request.status-200 { border-color: #2ed573; }
        .request.status-404 { border-color: #ff4757; }
        .request.status-403 { border-color: #ffa502; }
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.2s;
        }
        .btn-block { background: #ff4757; color: white; }
        .btn-block:hover { background: #ff6b7a; }
        .btn-unblock { background: #2ed573; color: white; }
        .btn-unblock:hover { background: #7bed9f; }
        .blacklist {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .blacklist-item {
            background: #0f0f23;
            padding: 8px 15px;
            border-radius: 5px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-family: monospace;
        }
        .refresh-btn {
            background: #00d9ff;
            color: #1a1a2e;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }
        .refresh-btn:hover { background: #00b8d9; }
        .empty { color: #666; font-style: italic; }
        .toggle-requests {
            background: #333;
            color: #fff;
            border: none;
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.8em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Extic 管理面板</h1>
            ${logoutBtn}
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="number">${stats.totalRequests}</div>
                <div class="label">今日请求</div>
            </div>
            <div class="stat-card">
                <div class="number">${stats.uniqueVisitors}</div>
                <div class="label">独立访客</div>
            </div>
            <div class="stat-card">
                <div class="number">${stats.blacklistCount}</div>
                <div class="label">黑名单 IP</div>
            </div>
            <div class="stat-card">
                <div class="number">${stats.loginLogs ? stats.loginLogs.filter(l => !l.success).length : 0}</div>
                <div class="label">登录失败</div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('visitors')">👥 今日访客</button>
            <button class="tab" onclick="switchTab('blacklist')">📋 黑名单</button>
            <button class="tab" onclick="switchTab('login')">🔐 登录日志</button>
        </div>
        
        <div class="tab-content" id="tab-visitors">
            <div class="section">
                <button class="refresh-btn" onclick="location.reload()">🔄 刷新</button>
                ${stats.visitors.length > 0
                    ? stats.visitors.map((v, i) => `
                        <div class="visitor">
                            <div class="visitor-header">
                                <div>
                                    <span class="visitor-flag" title="${v.geo?.country || 'Unknown'}">${v.geo?.flag || '🌐'}</span>
                                    <span class="visitor-ip ${stats.blacklist?.includes(v.ip) ? 'blocked' : ''}">${v.ip}</span>
                                    <span class="visitor-meta"> · ${v.requests.length} 次请求</span>
                                </div>
                                <div>
                                    <button class="toggle-requests" onclick="toggleRequests(${i})">展开/收起</button>
                                    ${!stats.blacklist?.includes(v.ip)
                            ? `<button class="btn btn-block" onclick="blockIP('${v.ip}')">拉黑</button>`
                            : `<button class="btn btn-unblock" onclick="unblockIP('${v.ip}')">解除</button>`
                        }
                                </div>
                            </div>
                            <div class="visitor-meta">
                                ${v.geo?.country || ''} ${v.geo?.city ? '· ' + v.geo.city : ''} · 
                                首次: ${new Date(v.firstSeen).toLocaleTimeString()} · 
                                最后: ${new Date(v.lastSeen).toLocaleTimeString()}
                            </div>
                            <div class="visitor-meta">${v.userAgent || '未知 UA'}</div>
                            <div class="visitor-requests" id="requests-${i}" style="display:none;">
                                ${v.requests.slice(-50).reverse().map(r => `
                                    <div class="request status-${r.status}">
                                        <span>${new Date(r.time).toLocaleTimeString()}</span>
                                        <span>${r.method}</span>
                                        <span>${r.url}</span>
                                        <span>[${r.status}]</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')
                    : '<p class="empty">今日暂无访客</p>'
                }
            </div>
        </div>
        
        <div class="tab-content" id="tab-blacklist" style="display:none;">
            <div class="section">
                <div class="blacklist" id="blacklist">
                    ${stats.blacklist && stats.blacklist.length > 0
                    ? stats.blacklist.map(ip => `
                            <div class="blacklist-item">
                                <span>${ip}</span>
                                <button class="btn btn-unblock" onclick="unblockIP('${ip}')">解除</button>
                            </div>
                        `).join('')
                    : '<span class="empty">暂无黑名单</span>'
                }
                </div>
            </div>
        </div>
        
        <div class="tab-content" id="tab-login" style="display:none;">
            <div class="section">
                ${stats.loginLogs && stats.loginLogs.length > 0
                ? stats.loginLogs.map(log => `
                        <div class="login-item ${log.success ? 'success' : 'fail'}">
                            <span>${new Date(log.time).toLocaleString()} · ${log.ip}</span>
                            <span>${log.success ? '<span style="color:#2ed573">✓ 成功</span>' : '<span class="failed-pwd">' + (log.password || '空') + '</span>'}</span>
                        </div>
                    `).join('')
                : '<span class="empty">暂无登录记录</span>'
            }
            </div>
        </div>
    </div>
    
    <script>
        function switchTab(name) {
            document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + name).style.display = 'block';
            event.target.classList.add('active');
        }
        
        function toggleRequests(index) {
            const el = document.getElementById('requests-' + index);
            el.style.display = el.style.display === 'none' ? 'block' : 'none';
        }
        
        async function blockIP(ip) {
            if (!confirm('确定要拉黑 ' + ip + ' 吗？')) return;
            const res = await fetch('${this.config.adminPath}/api/block', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            if (res.ok) location.reload();
            else alert('操作失败');
        }
        
        async function unblockIP(ip) {
            if (!confirm('确定要解除 ' + ip + ' 的拉黑吗？')) return;
            const res = await fetch('${this.config.adminPath}/api/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            if (res.ok) location.reload();
            else alert('操作失败');
        }
        
        // 使用 Twemoji 渲染国旗
        document.addEventListener('DOMContentLoaded', () => {
            if (typeof twemoji !== 'undefined') {
                document.querySelectorAll('.visitor-flag').forEach(el => twemoji.parse(el, { folder: 'svg', ext: '.svg' }));
            }
        });
        
        // 自动刷新（每30秒）
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>`;
    }

    // Express 中间件
    middleware() {
        return (req, res, next) => {
            const ip = this.getRealIP(req);

            // 检查是否是管理面板请求
            if (req.path.startsWith(this.config.adminPath)) {
                return this.handleAdminRequest(req, res);
            }

            // 检查黑名单
            if (this.isBlocked(ip)) {
                console.log(chalk.red(`[Security] 已拦截黑名单 IP: ${ip}`));
                res.status(403).send('Forbidden');
                return;
            }

            // 包装 res.send 以记录状态码
            const originalSend = res.send.bind(res);
            res.send = (body) => {
                this.logAccess(req, res.statusCode);

                // 检查 404 是否需要自动拉黑
                if (res.statusCode === 404) {
                    this.recordNotFound(req);
                }

                return originalSend(body);
            };

            next();
        };
    }

    // 处理管理面板请求
    handleAdminRequest(req, res) {
        const subPath = req.path.replace(this.config.adminPath, '') || '/';
        const ip = this.getRealIP(req);

        // 必须设置密码才能使用管理面板
        if (!this.config.adminPassword) {
            res.status(403).send(`
                <html>
                <head><title>Extic Admin</title></head>
                <body style="background:#1a1a2e;color:#ff4757;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
                    <div style="text-align:center;">
                        <h1>⚠️ 管理面板未启用</h1>
                        <p style="color:#888;">请在配置文件中设置 <code style="background:#333;padding:2px 8px;border-radius:4px;">security.adminPassword</code></p>
                    </div>
                </body>
                </html>
            `);
            return;
        }

        // 密码验证
        // 检查 session cookie 或 query 参数
        const cookies = this._parseCookies(req.headers.cookie || '');
        const sessionValid = cookies['extic_admin_session'] === this._getSessionToken();

        // 登录页面
        if (subPath === '/login' && req.method === 'POST') {
            // 检查是否被锁定
            if (this.isLoginLocked(ip)) {
                const remaining = this.getLockoutRemaining(ip);
                return res.status(429).json({ error: `登录尝试过多，请 ${remaining} 分钟后再试`, lockedMinutes: remaining });
            }
            
            const { password } = req.body || {};
            if (password === this.config.adminPassword) {
                this.recordLoginSuccess(ip);
                res.setHeader('Set-Cookie', `extic_admin_session=${this._getSessionToken()}; Path=${this.config.adminPath}; HttpOnly; SameSite=Strict`);
                return res.json({ success: true });
            }
            
            // 记录失败
            const locked = this.recordLoginFailure(ip, password);
            if (locked) {
                const remaining = this.getLockoutRemaining(ip);
                return res.status(429).json({ error: `登录尝试过多，已锁定 ${remaining} 分钟`, lockedMinutes: remaining });
            }
            return res.status(401).json({ error: '密码错误' });
        }

        // 登出
        if (subPath === '/logout') {
            res.setHeader('Set-Cookie', `extic_admin_session=; Path=${this.config.adminPath}; HttpOnly; Max-Age=0`);
            return res.redirect(this.config.adminPath);
        }

        // 未登录则显示登录页（检查锁定状态）
        if (!sessionValid) {
            if (this.isLoginLocked(ip)) {
                return res.send(this.getLockedHTML(this.getLockoutRemaining(ip)));
            }
            return res.send(this.getLoginHTML());
        }

        // API 路由
        if (subPath === '/api/block' && req.method === 'POST') {
            const { ip } = req.body || {};
            if (ip && this.blockIP(ip, 'admin')) {
                return res.json({ success: true });
            }
            return res.status(400).json({ error: 'Invalid IP' });
        }

        if (subPath === '/api/unblock' && req.method === 'POST') {
            const { ip } = req.body || {};
            if (ip && this.unblockIP(ip)) {
                return res.json({ success: true });
            }
            return res.status(400).json({ error: 'IP not in blacklist' });
        }

        if (subPath === '/api/stats') {
            const stats = this.getTodayStats();
            stats.blacklist = Array.from(this.blacklist);
            return res.json(stats);
        }

        // 管理面板页面
        if (subPath === '/' || subPath === '') {
            this.getTodayStatsAsync().then(stats => {
                stats.blacklist = Array.from(this.blacklist);
                stats.loginLogs = this.getLoginLog().slice(0, 100);
                res.type('html');
                res.send(this.getAdminHTML(stats));
            }).catch(err => {
                console.error('[Security] 获取统计失败:', err);
                const stats = this.getTodayStats();
                stats.blacklist = Array.from(this.blacklist);
                stats.loginLogs = this.getLoginLog().slice(0, 100);
                res.type('html');
                res.send(this.getAdminHTML(stats));
            });
            return;
        }

        res.status(404).send('Not Found');
    }

    // 解析 cookies
    _parseCookies(cookieHeader) {
        const cookies = {};
        cookieHeader.split(';').forEach(cookie => {
            const [name, value] = cookie.trim().split('=');
            if (name && value) cookies[name] = value;
        });
        return cookies;
    }

    // 生成 session token（基于密码的简单 hash，服务重启后失效）
    _getSessionToken() {
        if (!this._sessionToken) {
            const crypto = require('crypto');
            this._sessionToken = crypto
                .createHash('sha256')
                .update(this.config.adminPassword + process.pid + Date.now().toString().slice(0, -5))
                .digest('hex')
                .slice(0, 32);
        }
        return this._sessionToken;
    }

    // 锁定页面 HTML
    getLockedHTML(minutes) {
        return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Extic - 已锁定</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e; 
            color: #eee; 
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .lock-box {
            background: #16213e;
            padding: 40px;
            border-radius: 15px;
            text-align: center;
        }
        h1 { color: #ff4757; margin-bottom: 20px; font-size: 3em; }
        p { color: #888; margin-bottom: 10px; }
        .time { color: #ff4757; font-size: 2em; font-weight: bold; }
    </style>
</head>
<body>
    <div class="lock-box">
        <h1>🔒</h1>
        <p>登录尝试过多</p>
        <p>请等待</p>
        <p class="time">${minutes} 分钟</p>
        <p>后再试</p>
    </div>
    <script>setTimeout(() => location.reload(), 60000);</script>
</body>
</html>`;
    }

    // 登录页面 HTML
    getLoginHTML() {
        return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Extic 管理面板 - 登录</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e; 
            color: #eee; 
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-box {
            background: #16213e;
            padding: 40px;
            border-radius: 15px;
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        h1 { 
            color: #00d9ff; 
            margin-bottom: 30px;
            font-size: 1.5em;
        }
        input {
            width: 100%;
            padding: 15px;
            border: 2px solid #333;
            border-radius: 8px;
            background: #0f0f23;
            color: #fff;
            font-size: 1em;
            margin-bottom: 20px;
            outline: none;
            transition: border-color 0.2s;
        }
        input:focus { border-color: #00d9ff; }
        input::placeholder { color: #666; }
        button {
            width: 100%;
            padding: 15px;
            background: #00d9ff;
            color: #1a1a2e;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover { background: #00b8d9; }
        .error {
            color: #ff4757;
            margin-bottom: 20px;
            display: none;
        }
        .error.show { display: block; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>🛡️ Extic 管理面板</h1>
        <p class="error" id="error">密码错误，请重试</p>
        <form onsubmit="login(event)">
            <input type="password" id="password" placeholder="请输入管理密码" autofocus>
            <button type="submit">登录</button>
        </form>
    </div>
    <script>
        async function login(e) {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const res = await fetch('${this.config.adminPath}/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            if (res.ok) {
                location.href = '${this.config.adminPath}';
            } else {
                document.getElementById('error').classList.add('show');
                document.getElementById('password').value = '';
                document.getElementById('password').focus();
            }
        }
    </script>
</body>
</html>`;
    }
}
module.exports = SecurityManager;
