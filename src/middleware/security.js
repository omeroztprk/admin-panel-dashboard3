const rateLimit = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');
const config = require('../config');
const { t: globalT, detectLanguage } = require('../config/i18n');
const { getRedis, prefixKey } = require('../config/redis');
const { ERRORS } = require('../utils/constants');
const { getClientIP } = require('../utils/helpers');
const { applyLangHeaders } = require('../utils/response');
const AuditLog = require('../models/AuditLog');

const sendRateLimited = (req, res, messageKey) => {
  applyLangHeaders(res);

  const lng =
    (req.getLanguage && req.getLanguage()) ||
    detectLanguage(req) ||
    config.i18n.defaultLanguage;

  const rt = req.rateLimit?.resetTime;
  let retryAfterSec;
  if (rt instanceof Date) retryAfterSec = Math.max(1, Math.ceil((rt.getTime() - Date.now()) / 1000));
  else if (typeof rt === 'number' && Number.isFinite(rt)) retryAfterSec = Math.max(1, Math.ceil((rt - Date.now()) / 1000));
  if (retryAfterSec) res.set('Retry-After', String(retryAfterSec));

  const resolvedKey = (req.originalUrl || '').includes('/auth/login')
    ? (messageKey || ERRORS.AUTH.TOO_MANY_ATTEMPTS_DYNAMIC)
    : (messageKey || ERRORS.GENERAL.RATE_LIMIT_DYNAMIC);

  const sec = retryAfterSec ?? 60;
  const minute = Math.floor(sec / 60);
  const remain = sec % 60;

  let message;
  try {
    message = (req.t
      ? req.t(resolvedKey, { minute, seconds: remain })
      : globalT(resolvedKey, { lng, minute, seconds: remain })
    );
  } catch {
    message = resolvedKey;
  }

  try {
    const url = req.originalUrl || '';
    const ip = getClientIP(req);
    const resource =
      url.includes('/auth/') ? 'auth' :
        url.includes('/users') ? 'user' :
          url.includes('/roles') ? 'role' :
            url.includes('/permissions') ? 'permission' :
              url.includes('/audit') ? 'audit' :
                url.includes('/categories') ? 'category' :
                  'unknown';

    const action =
      url.includes('/auth/login') ? 'login_rate_limited' :
        (url.includes('/auth/refresh') || url.includes('/auth/refresh-token')) ? 'refresh_rate_limited' :
          'rate_limited';

    AuditLog.createLog({
      user: req.user?._id,
      action,
      resource,
      method: req.method,
      endpoint: url,
      statusCode: 429,
      userAgent: req.get('User-Agent'),
      ipAddress: ip,
      severity: url.includes('/auth/') ? 'high' : 'medium',
      tags: ['rate_limit', ...(url.includes('/auth/') ? ['authentication'] : [])],
      requestData: { query: req.query, params: req.params }
    });
  } catch { }

  return res.status(429).json({
    status: 'error',
    message,
    timestamp: new Date().toISOString()
  });
};

const getRateLimitStore = (customPrefix) => {
  const redis = getRedis();
  if (redis?.isOpen) {
    return new RedisStore({
      sendCommand: (...args) => {
        const command = Array.isArray(args[0]) ? args[0] : args;
        return redis.sendCommand(command);
      },
      prefix: customPrefix === undefined ? prefixKey('rl:') : customPrefix
    });
  }
  return undefined;
};

const createRateLimiter = (options = {}) => {
  const {
    windowMs = config.security.rateLimit.windowMs,
    max = config.security.rateLimit.max,
    messageKey = ERRORS.GENERAL.RATE_LIMIT_DYNAMIC,
    skipSuccessfulRequests = false,
    keyGenerator,
    store,
    skip,
  } = options;

  return rateLimit({
    windowMs,
    max,
    skipSuccessfulRequests,
    standardHeaders: true,
    legacyHeaders: false,
    store: store || getRateLimitStore(),
    handler: (req, res) => sendRateLimited(req, res, messageKey),
    ...(keyGenerator ? { keyGenerator } : {}),
    ...(typeof skip === 'function' ? { skip } : {}),
  });
};

const buildGlobalRateLimiter = () =>
  createRateLimiter({
    keyGenerator: (req) => getClientIP(req),
    skip: (req) => {
      const u = req.originalUrl || '';
      return u.includes('/health') || u.includes('/favicon.ico');
    },
    messageKey: ERRORS.GENERAL.RATE_LIMIT_DYNAMIC
  });

const buildAuthRateLimiter = () =>
  createRateLimiter({
    windowMs: config.security.authRateLimit.windowMs,
    max: config.security.authRateLimit.max,
    messageKey: ERRORS.GENERAL.RATE_LIMIT_DYNAMIC,
    skipSuccessfulRequests: config.security.authRateLimit.skipSuccessfulRequests === true,
    keyGenerator: (req) => `auth:${getClientIP(req)}`
  });

const buildAuthLoginIpLimiter = () =>
  createRateLimiter({
    windowMs: config.security.authLoginIpRateLimit.windowMs,
    max: config.security.authLoginIpRateLimit.max,
    messageKey: ERRORS.AUTH.TOO_MANY_FAILED_DYNAMIC,
    keyGenerator: (req) => `authip:${getClientIP(req)}`
  });

const createCustomRateLimit = (windowMs, max, messageKey, keyGen) =>
  createRateLimiter({ windowMs, max, messageKey, keyGenerator: keyGen });

const _limiterCache = new Map();

const limiter = (name) => {
  if (_limiterCache.has(name)) return _limiterCache.get(name);

  let inst;
  switch (name) {
    case 'auth:register':
      inst = buildAuthRateLimiter();
      break;
    case 'auth:login:ip':
      inst = buildAuthLoginIpLimiter();
      break;
    case 'auth:refresh':
      inst = createCustomRateLimit(60 * 1000, 30, ERRORS.GENERAL.RATE_LIMIT_DYNAMIC, (req) => getClientIP(req));
      break;
    case 'audit:export':
      inst = createCustomRateLimit(
        config.audit.exportRate.windowMs,
        config.audit.exportRate.max,
        ERRORS.GENERAL.RATE_LIMIT_DYNAMIC,
        (req) => (req.user?._id?.toString() || getClientIP(req))
      );
      break;
    default:
      throw new Error(`Unknown limiter name: ${name}`);
  }

  _limiterCache.set(name, inst);
  return inst;
};

module.exports = {
  buildGlobalRateLimiter,
  limiter
};
