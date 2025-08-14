const logger = require('../utils/logger');
const response = require('../utils/response');
const { ERRORS } = require('../utils/constants');
const AuditLog = require('../models/AuditLog');
const { getClientIP } = require('../utils/helpers');

const maskSensitive = (obj = {}) => {
  try {
    const clone = JSON.parse(JSON.stringify(obj));
    const SENSITIVE_KEYS = ['password', 'newpassword', 'confirmpassword', 'token', 'refreshtoken', 'accesstoken', 'authorization'];
    const mask = (o) => {
      Object.keys(o || {}).forEach((k) => {
        if (SENSITIVE_KEYS.includes(k.toLowerCase())) o[k] = '***';
        else if (o[k] && typeof o[k] === 'object') mask(o[k]);
      });
    };
    mask(clone);
    return clone;
  } catch {
    return {};
  }
};

const globalErrorHandler = async (err, req, res, _next) => {
  logger.error('Error', {
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: getClientIP(req),
    user: req.user?._id
  });

  try {
    await AuditLog.createLog({
      user: req.user?._id,
      action: 'error',
      resource: 'system',
      method: req.method,
      endpoint: req.originalUrl,
      statusCode: err.statusCode || 500,
      userAgent: req.get('User-Agent'),
      ipAddress: getClientIP(req),
      errorMessage: err.message,
      severity: (err.statusCode || 500) >= 500 ? 'critical' : 'medium',
      requestData: {
        query: maskSensitive(req.query),
        body: maskSensitive(req.body),
        params: maskSensitive(req.params)
      }
    });
  } catch (auditError) {
    logger.error('Failed to create audit log', auditError);
  }

  if (err.name === 'CastError') {
    const message = req.t ? req.t(ERRORS.VALIDATION.INVALID_ID) : 'Invalid ID format';
    return response.error(res, message, 400);
  }

  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || 'field';
    const message = req.t ? req.t(ERRORS.VALIDATION.DUPLICATE_VALUE, { field }) : `Duplicate value for ${field}`;
    return response.error(res, message, 400);
  }

  if (err.name === 'ValidationError') {
    const validationErrors = Object.values(err.errors || {}).map((v) => v.message).join(', ');
    const message = req.t ? req.t(ERRORS.VALIDATION.INVALID_INPUT) : validationErrors || 'Validation error';
    return response.error(res, message, 400);
  }

  if (err.name === 'JsonWebTokenError') {
    const message = req.t ? req.t(ERRORS.AUTH.INVALID_TOKEN) : 'Invalid token';
    return response.error(res, message, 401);
  }

  if (err.name === 'TokenExpiredError') {
    const message = req.t ? req.t(ERRORS.AUTH.TOKEN_EXPIRED) : 'Token expired';
    return response.error(res, message, 401);
  }

  const statusCode = err.statusCode || 500;
  const message = req.t ? req.t(err.message || ERRORS.GENERAL.INTERNAL_ERROR) : (err.message || 'Internal Server Error');
  return response.error(res, message, statusCode);
};

const notFound = (req, _res, next) => {
  const message = req.t ? req.t(ERRORS.GENERAL.NOT_FOUND) : 'Resource not found';
  const error = new Error(message);
  error.statusCode = 404;
  next(error);
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  globalErrorHandler,
  notFound,
  asyncHandler
};
