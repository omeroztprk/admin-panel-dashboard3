const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { getClientIP } = require('../utils/helpers');

const deepMask = (obj, keysToMask = ['password', 'confirmPassword', 'currentPassword', 'newPassword', 'token', 'accessToken', 'refreshToken', 'authorization']) => {
  if (!obj || typeof obj !== 'object') return obj;
  const lowerList = new Set(keysToMask.map(k => String(k).toLowerCase()));
  const maskKey = (k) => lowerList.has(String(k).toLowerCase());

  const recur = (value) => {
    if (!value || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map(recur);
    const cloned = {};
    for (const [k, v] of Object.entries(value)) {
      cloned[k] = maskKey(k) ? '[REDACTED]' : recur(v);
    }
    return cloned;
  };

  try { return recur(obj); } catch { return {}; }
};

const safeSlice = (str, max = 5000) => {
  if (str == null) return '';
  const s = String(str);
  return s.length > max ? `${s.slice(0, max)}...[TRUNCATED]` : s;
};

const clampObject = (obj, maxLen = 5000) => {
  try {
    const s = JSON.stringify(obj);
    if (s.length <= maxLen) return obj;
    return { _truncated: true, preview: safeSlice(s, maxLen) };
  } catch {
    return { _truncated: true, preview: '[Unserializable]' };
  }
};

const shouldLogRequest = (req, res) => {
  const url = req.originalUrl || '';
  if (url.includes('/health') || url.includes('/favicon.ico')) return false;
  if (url.includes('/audit/export')) return false;
  if (url.includes('/auth/')) return true;
  if (res.statusCode >= 400) return true;
  if (req.method !== 'GET') return true;
  if (url.includes('/admin/')) return true;
  return false;
};

const getActionFromRequest = (req) => {
  const method = req.method?.toLowerCase();
  const path = req.route?.path || req.originalUrl || '';

  if (path.includes('/auth/login')) return 'login';
  if (path.includes('/auth/logout')) return 'logout';
  if (path.includes('/auth/register')) return 'register';
  if (path.includes('/auth/refresh') || path.includes('/auth/refresh-token')) return 'token_refresh';

  switch (method) {
    case 'post': return 'create';
    case 'put':
    case 'patch': return 'update';
    case 'delete': return 'delete';
    case 'get': return 'read';
    default: return method || 'unknown';
  }
};

const getResourceFromRequest = (req) => {
  const parts = (req.originalUrl || '').split('/').filter(Boolean);
  if (parts.includes('auth')) return 'auth';
  if (parts.includes('users')) return 'user';
  if (parts.includes('roles')) return 'role';
  if (parts.includes('permissions')) return 'permission';
  if (parts.includes('audit')) return 'audit';
  return 'unknown';
};

const getSeverityLevel = (req, res) => {
  if (res.statusCode >= 500) return 'critical';
  if (res.statusCode >= 400) return 'high';
  if ((req.originalUrl || '').includes('/auth/')) return 'medium';
  if (req.method !== 'GET') return 'medium';
  return 'low';
};

const generateTags = (req, res) => {
  const tags = [];
  if (req.user) tags.push('authenticated');
  if (res.statusCode >= 400) tags.push('error');
  if ((req.originalUrl || '').includes('/auth/')) tags.push('authentication');
  if (req.method !== 'GET') tags.push('data_modification');
  return tags;
};

const logRequest = (req, res, next) => {
  const startTime = Date.now();
  let responseData = null;

  const originalJson = res.json.bind(res);
  res.json = (data) => { responseData = data; return originalJson(data); };

  const originalSend = res.send.bind(res);
  res.send = (data) => {
    try {
      if (data && typeof data === 'object') responseData = data;
      else if (typeof data === 'string' && data.startsWith('{')) responseData = JSON.parse(data);
    } catch { }
    return originalSend(data);
  };

  const onFinish = async () => {
    res.removeListener('finish', onFinish);
    res.removeListener('close', onFinish);

    const duration = Date.now() - startTime;

    try {
      if (!shouldLogRequest(req, res)) return;

      const sessionId = req.sessionID || req.headers['x-request-id'] || undefined;

      const payload = {
        user: req.user?._id,
        action: getActionFromRequest(req),
        resource: getResourceFromRequest(req),
        resourceId: req.params?.id || req.params?.userId || req.params?.roleId,
        method: req.method,
        endpoint: req.originalUrl,
        statusCode: res.statusCode,
        userAgent: req.get('User-Agent'),
        ipAddress: getClientIP(req),
        sessionId,
        requestData: clampObject(deepMask({ query: req.query, body: req.body, params: req.params })),
        responseData: clampObject(deepMask(responseData)),
        duration,
        severity: getSeverityLevel(req, res),
        tags: generateTags(req, res)
      };

      await AuditLog.createLog(payload);
    } catch (error) {
      logger.error('Failed to create audit log:', error);
    }
  };

  res.once('finish', onFinish);
  res.once('close', onFinish);

  next();
};

const logUserAction = (action, resource, resourceId, changes = null) => {
  return async (req, res, next) => {
    try {
      const logData = {
        user: req.user?._id,
        action,
        resource,
        resourceId,
        method: req.method,
        endpoint: req.originalUrl,
        statusCode: res.statusCode,
        userAgent: req.get('User-Agent'),
        ipAddress: getClientIP(req),
        severity: 'medium',
        tags: ['user_action']
      };
      if (changes) logData.changes = changes;
      await AuditLog.createLog(logData);
    } catch (error) {
      logger.error('Failed to log user action:', error);
    }
    next();
  };
};

module.exports = { logRequest, logUserAction };
