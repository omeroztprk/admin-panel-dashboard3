const logger = require('../utils/logger');
const response = require('../utils/response');
const { applyLangHeaders } = require('../utils/response');
const { ERRORS } = require('../utils/constants');
const { verifyAccessToken, verifyRefreshToken } = require('../config/jwt');
const { getClientIP } = require('../utils/helpers');
const RefreshToken = require('../models/RefreshToken');
const User = require('../models/User');
const auditService = require('../services/auditService');
const crypto = require('crypto');

const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      logger.warn('Authentication attempt without token', {
        endpoint: req.originalUrl, method: req.method, ip: getClientIP(req), userAgent: req.get('User-Agent')
      });
      return response.error(res, req.t(ERRORS.AUTH.TOKEN_MISSING), 401);
    }

    const decoded = verifyAccessToken(token);
    const user = await User.findById(decoded.userId).populate('roles').populate('permissions.permission');

    if (!user || !user.isActive) {
      logger.warn('Authentication with invalid/inactive user', {
        userId: decoded.userId, endpoint: req.originalUrl, ip: getClientIP(req)
      });
      return response.error(res, req.t(ERRORS.AUTH.USER_NOT_FOUND), 401);
    }

    req.user = user;
    req.token = token;

    if (user.isLocked) {
      logger.warn('Authentication with locked account', {
        userId: user._id, lockoutUntil: user.lockoutUntil, endpoint: req.originalUrl, ip: getClientIP(req)
      });

      const retrySec = Math.max(1, Math.ceil(((user.lockoutUntil?.getTime?.() || Date.now()) - Date.now()) / 1000));
      const minute = Math.floor(retrySec / 60);
      const remain = retrySec % 60;

      try { res.set('Retry-After', String(retrySec)); } catch (_) { }

      return response.error(res, req.t(ERRORS.AUTH.ACCOUNT_LOCKED_DYNAMIC, { minute, seconds: remain }), 423);
    }

    next();
  } catch (error) {
    logger.error('Authentication error', {
      error: error.message, stack: error.stack, endpoint: req.originalUrl, method: req.method, ip: getClientIP(req), userAgent: req.get('User-Agent')
    });
    if (error.name === 'JsonWebTokenError') return response.error(res, req.t(ERRORS.AUTH.INVALID_TOKEN), 401);
    if (error.name === 'TokenExpiredError') return response.error(res, req.t(ERRORS.AUTH.TOKEN_EXPIRED), 401);
    return response.error(res, req.t(ERRORS.GENERAL.INTERNAL_ERROR), 500);
  }
};

const refreshTokenAuth = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      logger.warn('Refresh token attempt without token', {
        endpoint: req.originalUrl, ip: getClientIP(req)
      });
      return response.error(res, req.t(ERRORS.AUTH.REFRESH_TOKEN_MISSING), 400);
    }

    try {
      verifyRefreshToken(refreshToken);
    } catch {
      return response.error(res, req.t(ERRORS.AUTH.INVALID_REFRESH_TOKEN), 401);
    }

    const tokenHash = crypto.createHash('sha256').update(String(refreshToken)).digest('hex');
    const tokenDoc = await RefreshToken.findOne({ tokenHash, isBlacklisted: false }).populate('user');
    if (!tokenDoc || tokenDoc.isExpired) {
      logger.warn('Invalid refresh token attempt', {
        tokenExists: !!tokenDoc, isExpired: tokenDoc?.isExpired, endpoint: req.originalUrl, ip: getClientIP(req)
      });
      return response.error(res, req.t(ERRORS.AUTH.INVALID_REFRESH_TOKEN), 401);
    }
    if (!tokenDoc.user || !tokenDoc.user.isActive) {
      logger.warn('Refresh token for inactive user', {
        userId: tokenDoc.user?._id, userActive: tokenDoc.user?.isActive, endpoint: req.originalUrl, ip: getClientIP(req)
      });
      return response.error(res, req.t(ERRORS.AUTH.USER_NOT_FOUND), 401);
    }

    const u = tokenDoc.user;
    const locked = !!(u.isLocked && u.lockoutUntil && u.lockoutUntil.getTime() > Date.now());
    if (locked) {
      const retrySec = Math.max(1, Math.ceil((u.lockoutUntil.getTime() - Date.now()) / 1000));
      try { res.set('Retry-After', String(retrySec)); } catch (_) { }

      const minute = Math.floor(retrySec / 60);
      const remain = retrySec % 60;

      applyLangHeaders(res);

      const msg = req.t(ERRORS.AUTH.ACCOUNT_LOCKED_DYNAMIC, { minute, seconds: remain });

      try {
        await auditService.logUserAction({
          user: u._id,
          action: 'refresh_denied_locked',
          resource: 'auth',
          method: req.method,
          endpoint: req.originalUrl,
          statusCode: 423,
          ipAddress: getClientIP(req),
          userAgent: req.get('User-Agent') || 'Unknown',
          errorMessage: 'Refresh denied due to account lock',
          severity: 'high'
        });
      } catch (_) { }

      return res.status(423).json({
        status: 'error',
        message: msg,
        timestamp: new Date().toISOString(),
        unlockAt: u.lockoutUntil.toISOString()
      });
    }

    req.user = tokenDoc.user;
    req.refreshTokenDoc = tokenDoc;
    req.refreshTokenPlain = refreshToken;
    next();
  } catch (error) {
    logger.error('Refresh token authentication error', error);
    return response.error(res, req.t(ERRORS.GENERAL.INTERNAL_ERROR), 500);
  }
};

const precheckAccountLock = async (req, res, next) => {
  try {
    const email = typeof req.body?.email === 'string' ? req.body.email.toLowerCase().trim() : '';
    if (!email) return next();

    const user = await User.findOne({ email }).select('lockoutUntil');
    const locked = !!(user?.lockoutUntil && user.lockoutUntil.getTime() > Date.now());
    if (!locked) return next();

    const retrySec = Math.max(1, Math.ceil((user.lockoutUntil.getTime() - Date.now()) / 1000));
    res.set('Retry-After', String(retrySec));

    const minute = Math.floor(retrySec / 60);
    const remain = retrySec % 60;

    try {
      await auditService.logUserAction({
        user: user?._id || null,
        action: 'login_failed',
        resource: 'auth',
        method: req.method,
        endpoint: req.originalUrl,
        statusCode: 423,
        ipAddress: getClientIP(req),
        userAgent: req.get('User-Agent') || 'Unknown',
        errorMessage: `Attempt on locked account for ${email}`,
        severity: 'medium'
      });
    } catch (_) { }

    applyLangHeaders(res);

    const msg = req.t(ERRORS.AUTH.ACCOUNT_LOCKED_DYNAMIC, { minute, seconds: remain });
    return res.status(423).json({
      status: 'error',
      message: msg,
      timestamp: new Date().toISOString(),
      unlockAt: user.lockoutUntil.toISOString()
    });
  } catch (_) {
    return next();
  }
};

module.exports = {
  authenticate,
  refreshTokenAuth,
  precheckAccountLock
};
