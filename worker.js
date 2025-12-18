```javascript
[...]
function getSecurityConfig(env) {
  [...]
}
[...]
class VpsBatchProcessor {
  constructor() {
    [...]
  }

  // 添加VPS上报数据到批量缓冲区
  addReport(serverId, reportData, batchInterval) {
    [...]
  }

  // 获取并清空批量数据
  getBatchData() {
    [...]
  }

  // 检查是否需要定时刷新
  shouldFlush(batchInterval) {
    const now = Math.floor(Date.now() / 1000);
    return this.batchBuffer.length > 0 && (now - this.lastBatch >= batchInterval);
  }
}
[...]
async function flushVpsBatchData(env) {
  [...]
}

// 定时刷新VPS批量数据（在主请求处理中调用）
async function scheduleVpsBatchFlush(env, ctx) {
  [...]
}
[...]
function storeRealtimeData(serverId, metrics) {
  [...]
}

// 获取实时数据
function getRealtimeData(serverId) {
  [...]
}

// 清理过期的实时数据缓存
function cleanupRealtimeCache() {
  [...]
}
[...]
class ConfigCache {
  constructor() {
    [...]
  }

  set(key, value, ttl) {
    [...]
  }

  get(key) {
    [...]
  }

  async getTelegramConfig(db) {
    [...]
  }

  async getMonitoringSettings(db) {
    [...]
  }

  async getServerList(db, isAdmin = false) {
    [...]
  }

  clear() {
    this.cache.clear();
  }

  clearKey(key) {
    this.cache.delete(key);
  }
}
[...]
async function calculateVpsUptime(env, serverId, hours = 24) {
	[...]
}

// 格式化时间duration（秒）为可读格式
function formatDuration(seconds) {
  [...]
}

// 计算网站在线率
async function calculateSiteUptime(env, siteId, hours = 24) {
	[...]
}

// SQL安全验证 - 防止注入攻击
function validateSqlIdentifier(value, type) {
  [...]
}

// 敏感信息脱敏
function maskSensitive(value, type = 'key') {
  if (!value || typeof value !== 'string') return value;
  return type === 'key' && value.length > 8 ? value.substring(0, 8) + '***' : '***';
}
[...]
function revokeToken(token) {
  [...]
}

function isTokenRevoked(token) {
  return revokedTokens.has(token);
}

// 安全的JSON解析 - 限制大小
async function parseJsonSafely(request, maxSize = 1024 * 1024) {
  [...]
}

// 增强的管理员认证 - 修复权限检查问题
async function authenticateAdmin(request, env) {
  [...]
}

// 严格的管理员权限检查装饰器
function requireAdmin(handler) {
  [...]
}

// 路径参数验证
function extractPathSegment(path, index) {
  [...]
}

// 生成随机ID
function generateId() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// 生成安全的API密钥
function generateSecureApiKey() {
  [...]
}

// 提取服务器ID的便捷函数
function extractAndValidateServerId(path) {
  return extractPathSegment(path, -1);
}

// 增强的输入验证 - 修复SSRF漏洞
function validateInput(input, type, maxLength = 255) {
  [...]
    serverName: () => {
      [...]
    },
    description: () => {
      if (cleaned.length > 500) return false;
      return !/<[^>]*>|javascript:|on\w+\s*=|<script/i.test(cleaned);
    },
    direction: () => ['up', 'down'].includes(input),
    url: () => {
      [...]
    }
  [...]
}
[...]
function createApiResponse(data, status = 200, corsHeaders = {}) {
  [...]
}

// 创建错误响应
function createErrorResponse(error, message, status = 500, corsHeaders = {}, details = null) {
  [...]
}

// 创建成功响应
function createSuccessResponse(data, corsHeaders = {}) {
  return createApiResponse({ success: true, ...data }, 200, corsHeaders);
}
[...]
async function validateServerAuth(path, request, env) {
  [...]
}
[...]
function handleDbError(error, corsHeaders, operation = 'database operation') {
  [...]
}
[...]
async function getVpsReportInterval(env) {
  [...]
}

// 清除VPS间隔缓存（当设置更新时调用）
function clearVpsIntervalCache() {
  vpsIntervalCache.value = null;
  vpsIntervalCache.timestamp = 0;
}
[...]
function validateAndFixVpsField(data, field) {
  [...]
}

// 简化的VPS数据验证
function validateAndFixVpsData(reportData) {
  [...]
}
[...]
async function hashPassword(password) {
  [...]
}

async function verifyPassword(password, hashedPassword) {
  [...]
}
[...]
function cleanupJWTCache() {
  [...]
}

async function createJWT(payload, env) {
  [...]
}

// 安全的JWT验证函数 - 修复缓存安全问题
async function verifyJWTCached(token, env) {
  [...]
}

// 原始JWT验证函数（不使用缓存）
async function verifyJWT(token, env) {
  [...]
}
[...]
function checkRateLimit(clientIP, endpoint, env) {
  [...]
}

function checkLoginAttempts(clientIP, env) {
  [...]
}

function recordLoginAttempt(clientIP) {
  [...]
}

function getClientIP(request) {
  [...]
}
[...]
async function ensureTablesExist(db, env) {
  [...]
}

async function applySchemaAlterations(db) {
  [...]
}

async function isUsingDefaultPassword(username, password) {
  return username === DEFAULT_ADMIN_CONFIG.USERNAME && password === DEFAULT_ADMIN_CONFIG.PASSWORD;
}

async function createDefaultAdmin(db, env) {
  [...]
}

async function isDefaultPasswordActive(db) {
  [...]
}
[...]
async function authenticateRequest(request, env) {
  [...]
}

// 可选认证函数 - 用于前台API，支持游客和管理员两种模式
async function authenticateRequestOptional(request, env) {
  [...]
}
[...]
function getSecureCorsHeaders(origin, env) {
  [...]
}
[...]
async function handleAuthRoutes(path, method, request, env, corsHeaders, clientIP) {
  [...]
}

// 基于服务器信息构建Ping目标地址
function resolveServerPingTarget(server) {
  [...]
}

// 确保存在对应的Ping节点（使用服务器名称对齐）
async function ensureServerPingNode(env, server, targetAddress) {
  [...]
}

// 服务器管理路由处理器
async function handleServerRoutes(path, method, request, env, corsHeaders) {
  [...]
}

// Ping节点管理路由处理器
async function handlePingNodeRoutes(path, method, request, env, corsHeaders) {
  [...]
}

// VPS监控路由处理器
async function handleVpsRoutes(path, method, request, env, corsHeaders, ctx) {
  [...]
}
[...]
async function handleApiRequest(request, env, ctx) {
  [...]
}
[...]
async function checkWebsiteStatus(site, db, ctx) { // Added ctx for waitUntil
  [...]
}
[...]
async function checkWebsiteStatusOptimized(site, db, ctx) {
  [...]
}

// 简化版VPS离线提醒检查 - 只负责持续离线提醒
async function checkVpsOfflineReminder(env, ctx) {
  [...]
}

// 简化版Telegram通知 - 直接发送
async function sendTelegramNotificationOptimized(db, message, priority = 'normal') {
  [...]
}
[...]
async function performDatabaseMaintenance(db) {
  [...]
}
[...]
  async fetch(request, env, ctx) {
    [...]
  },

  async scheduled(event, env, ctx) {
    [...]
  }
[...]
function isValidHttpUrl(string) {
  [...]
}
[...]
async function handleInstallScript(request, url, env) {
[...]
}

// 前端请求处理
function handleFrontendRequest(request, path) {
  [...]
}
[...]
function getIndexHtml() {
[...]
}

function getLoginHtml() {
[...]
}

function getAdminHtml() {
[...]
}

function getFaviconSvg() {
[...]
}

function getStyleCss() {
[...]
}

function getMainJs() {
[...]
}
function getLoginJs() {
[...]
}
[...]
function getAdminJs() {
[...]
}

```
