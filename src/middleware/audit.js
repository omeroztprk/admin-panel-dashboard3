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

const clampObject = (obj, maxLen = 5000) => {
  try {
    const s = JSON.stringify(obj);
    if (s.length <= maxLen) return obj;
    return { _truncated: true, preview: s.slice(0, maxLen) + '...[TRUNCATED]' };
  } catch {
    return { _truncated: true, preview: '[Unserializable]' };
  }
};

const shouldLogRequest = (req, res) => {
  const url = req.originalUrl || '';
  if (url.includes('/health') || url.includes('/favicon.ico')) return false;
  if (url.includes('/auth/')) return true;
  if (res.statusCode >= 400) return true;
  if (req.method !== 'GET') return true;
  return false;
};

const getActionFromMethod = (method) => {
  switch (method?.toLowerCase()) {
    case 'post': return 'create';
    case 'put':
    case 'patch': return 'update';
    case 'delete': return 'delete';
    case 'get': return 'read';
    default: return 'unknown';
  }
};

const getResourceFromUrl = (url) => {
  const parts = (url || '').split('/').filter(Boolean);
  if (parts.includes('auth')) return 'auth';
  if (parts.includes('users')) return 'user';
  if (parts.includes('roles')) return 'role';
  if (parts.includes('permissions')) return 'permission';
  if (parts.includes('audit')) return 'audit';
  if (parts.includes('categories')) return 'category';
  return 'unknown';
};

const getSeverityFromStatus = (statusCode, resource, action) => {
  if (statusCode >= 500) return 'critical';
  if (statusCode >= 400) return 'high';
  if (resource === 'auth' || ['create', 'update', 'delete'].includes(action)) return 'medium';
  return 'low';
};

const auditLogger = (customAction = null, customResource = null, customSeverity = null) => {
  return async (req, res, next) => {
    const startTime = Date.now();
    let responseData = null;

    const originalJson = res.json.bind(res);
    res.json = (data) => { 
      try {
        const dataStr = JSON.stringify(data);
        if (dataStr.length < 5000) {
          responseData = data;
        } else {
          responseData = { _truncated: true, preview: dataStr.slice(0, 200) + '...' };
        }
      } catch {
        responseData = { _error: 'Unserializable response' };
      }
      return originalJson(data); 
    };

    const cleanup = () => {
      responseData = null;
      if (res.json !== originalJson) {
        res.json = originalJson;
      }
    };

    res.once('finish', async () => {
      try {
        if (!customAction && !shouldLogRequest(req, res)) return cleanup();

        const action = customAction || getActionFromMethod(req.method);
        const resource = customResource || getResourceFromUrl(req.originalUrl);
        const severity = customSeverity || getSeverityFromStatus(res.statusCode, resource, action);

        const payload = {
          user: req.user?._id,
          action,
          resource,
          resourceId: req.params?.id || req.params?.userId || req.params?.roleId || req.params?.permissionId || req.params?.categoryId,
          method: req.method,
          endpoint: req.originalUrl,
          statusCode: res.statusCode,
          userAgent: req.get('User-Agent'),
          ipAddress: getClientIP(req),
          sessionId: req.sessionID || req.headers['x-request-id'],
          requestData: clampObject(deepMask({ query: req.query, body: req.body, params: req.params })),
          responseData: clampObject(deepMask(responseData)),
          duration: Date.now() - startTime,
          severity
        };

        await AuditLog.createLog(payload);
      } catch (error) {
        logger.error('Failed to create audit log:', error);
      } finally {
        cleanup();
      }
    });

    next();
  };
};

const logRequest = auditLogger();
const logUserAction = (action, resource, severity) => auditLogger(action, resource, severity);

module.exports = { logRequest, logUserAction };