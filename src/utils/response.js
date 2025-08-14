const logger = require('./logger');
const { t: globalT, resolveLanguage, i18next } = require('../config/i18n');
const { getClientIP } = require('../utils/helpers');

const applyLangHeaders = (res) => {
  try {
    const req = res.req;
    let lng =
      (req?.getLanguage && req.getLanguage()) ||
      req?.user?.profile?.language ||
      req?.headers?.['accept-language'];
    lng = resolveLanguage(lng);

    if (!res.get('Content-Language')) res.set('Content-Language', lng);

    const vary = res.get('Vary');
    if (!vary || !vary.split(',').map((s) => s.trim().toLowerCase()).includes('accept-language')) {
      res.set('Vary', vary ? `${vary}, Accept-Language` : 'Accept-Language');
    }
  } catch (_) { }
};

const translateMessage = (req, message) => {
  if (!message || typeof message !== 'string') return message;

  try {
    const lngForCheck = resolveLanguage(
      (req?.getLanguage && req.getLanguage()) || req?.headers?.['accept-language']
    );

    const primary = req?.t
      ? req.t(message, { lng: lngForCheck })
      : globalT(message, { lng: lngForCheck });

    if (primary && primary !== message) return primary;

    const fallbackEn = globalT(message, { lng: 'en' });
    if (fallbackEn && fallbackEn !== message) return fallbackEn;
  } catch (error) {
    logger.error('Translation error in response:', {
      message,
      error: error.message,
      req: { url: req?.originalUrl, method: req?.method, userLanguage: req?.user?.profile?.language },
    });
  }

  return message;
};

const success = (res, message, data = null, statusCode = 200) => {
  applyLangHeaders(res);
  const translatedMessage = translateMessage(res.req, message);
  const body = { status: 'success', message: translatedMessage, timestamp: new Date().toISOString() };
  if (data !== null) body.data = data;
  return res.status(statusCode).json(body);
};

const error = (res, message, statusCode = 500, errors = null) => {
  applyLangHeaders(res);
  const translatedMessage = translateMessage(res.req, message);
  const body = { status: 'error', message: translatedMessage, timestamp: new Date().toISOString() };
  if (errors) body.errors = errors;

  if (statusCode >= 500) {
    logger.error('Response Error:', {
      message: translatedMessage,
      originalMessage: message,
      statusCode,
      errors,
      req: { url: res.req?.originalUrl, method: res.req?.method, userId: res.req?.user?._id, ip: getClientIP(res.req) },
    });
  }

  return res.status(statusCode).json(body);
};

const validationError = (res, message, errors = [], statusCode = 400) => {
  applyLangHeaders(res);
  const translatedMessage = translateMessage(res.req, message);
  const body = { status: 'error', message: translatedMessage, errors, timestamp: new Date().toISOString() };
  return res.status(statusCode).json(body);
};

const paginated = (res, message, data, pagination, statusCode = 200) => {
  applyLangHeaders(res);
  const translatedMessage = translateMessage(res.req, message);
  const validatedPagination = {
    currentPage: pagination.currentPage || 1,
    totalPages: pagination.totalPages || 1,
    totalItems: pagination.totalItems || 0,
    itemsPerPage: pagination.itemsPerPage || 10,
    hasNextPage: pagination.hasNextPage || false,
    hasPrevPage: pagination.hasPrevPage || false,
  };

  const body = {
    status: 'success',
    message: translatedMessage,
    data,
    pagination: validatedPagination,
    timestamp: new Date().toISOString(),
  };

  return res.status(statusCode).json(body);
};

const created = (res, message, data = null) => success(res, message, data, 201);
const noContent = (res) => {
  applyLangHeaders(res);
  return res.status(204).send();
};

const tooManyRequests = (res, arg2) => {
  if (typeof arg2 === 'number' && Number.isFinite(arg2) && arg2 > 0) {
    const secs = Math.ceil(arg2);
    try { res.set('Retry-After', String(secs)); } catch (_) { }

    const minute = Math.floor(secs / 60);
    const remain = secs % 60;

    const lngGuess =
      (res.req?.getLanguage && res.req.getLanguage()) ||
      res.req?.user?.profile?.language ||
      res.req?.headers?.['accept-language'];
    const lng = resolveLanguage(lngGuess);

    const msg = res.req?.t
      ? res.req.t('errors.general.rate_limit_dynamic', { minute, seconds: remain })
      : globalT('errors.general.rate_limit_dynamic', { lng, minute, seconds: remain });

    return error(res, msg, 429, null);
  }
  if (typeof arg2 === 'string' && arg2) {
    return error(res, arg2, 429);
  }
  return error(res, 'errors.general.rate_limit', 429);
};

const unauthorized = (res, message = 'errors.general.unauthorized') => error(res, message, 401);
const forbidden = (res, message = 'errors.general.forbidden') => error(res, message, 403);
const notFound = (res, message = 'errors.general.not_found') => error(res, message, 404);

module.exports = {
  applyLangHeaders,
  success,
  error,
  validationError,
  paginated,
  created,
  noContent,
  unauthorized,
  forbidden,
  notFound,
  tooManyRequests,
  translateMessage,
};
