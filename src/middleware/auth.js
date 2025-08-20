const logger = require('../utils/logger');
const response = require('../utils/response');
const { ERRORS } = require('../utils/constants');
const { verifyAccessToken, verifyRefreshToken } = require('../config/jwt');
const { getClientIP } = require('../utils/helpers');
const RefreshToken = require('../models/RefreshToken');
const User = require('../models/User');
const crypto = require('crypto');

const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return response.error(res, req.t(ERRORS.AUTH.TOKEN_MISSING), 401);
    }

    const decoded = verifyAccessToken(token);
    
    if (!decoded?.userId) {
      return response.error(res, req.t(ERRORS.AUTH.INVALID_TOKEN), 401);
    }
    
    const user = await User.findById(decoded.userId)
      .select('isActive lockoutUntil firstName lastName email roles permissions profile')
      .populate([
        {
          path: 'roles',
          select: 'name displayName description priority permissions isActive',
          populate: {
            path: 'permissions',
            select: 'name displayName resource action description category isActive',
            match: { isActive: true }
          }
        },
        {
          path: 'permissions.permission',
          select: 'name displayName resource action description category isActive',
          match: { isActive: true }
        }
      ]);

    if (!user || !user.isActive || user.isLocked) {
      if (user?.isLocked) {
        const retrySec = Math.max(1, Math.ceil(((user.lockoutUntil?.getTime?.() || Date.now()) - Date.now()) / 1000));
        const minute = Math.floor(retrySec / 60);
        const remain = retrySec % 60;
        
        res.set('Retry-After', String(retrySec));
        
        const message = req.t 
          ? req.t(ERRORS.AUTH.ACCOUNT_LOCKED_DYNAMIC, { minute, seconds: remain })
          : `Account locked. Try again in ${minute}m ${remain}s`;
          
        return response.error(res, message, 423);
      }
      return response.error(res, req.t(ERRORS.AUTH.USER_NOT_FOUND), 401);
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    logger.error('Authentication error', { 
      error: error.message, 
      endpoint: req.originalUrl, 
      ip: getClientIP(req) 
    });
    
    if (error.name === 'JsonWebTokenError') {
      return response.error(res, req.t(ERRORS.AUTH.INVALID_TOKEN), 401);
    }
    if (error.name === 'TokenExpiredError') {
      return response.error(res, req.t(ERRORS.AUTH.TOKEN_EXPIRED), 401);
    }
    return response.error(res, req.t(ERRORS.GENERAL.INTERNAL_ERROR), 500);
  }
};

const refreshTokenAuth = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return response.error(res, req.t(ERRORS.AUTH.REFRESH_TOKEN_MISSING), 400);
    }

    verifyRefreshToken(refreshToken);
    
    const tokenHash = crypto.createHash('sha256').update(String(refreshToken)).digest('hex');
    const tokenDoc = await RefreshToken.findOne({ tokenHash, isBlacklisted: false }).populate('user');
    
    if (!tokenDoc || tokenDoc.isExpired || !tokenDoc.user?.isActive) {
      return response.error(res, req.t(ERRORS.AUTH.INVALID_REFRESH_TOKEN), 401);
    }

    if (tokenDoc.user.isLocked) {
      const retrySec = Math.max(1, Math.ceil((tokenDoc.user.lockoutUntil.getTime() - Date.now()) / 1000));
      const minute = Math.floor(retrySec / 60);
      const remain = retrySec % 60;
      
      res.set('Retry-After', String(retrySec));
      return response.error(res, req.t(ERRORS.AUTH.ACCOUNT_LOCKED_DYNAMIC, { minute, seconds: remain }), 423);
    }

    req.user = tokenDoc.user;
    req.refreshTokenDoc = tokenDoc;
    req.refreshTokenPlain = refreshToken;
    next();
  } catch (error) {
    logger.error('Refresh token authentication error', error);
    return response.error(res, req.t(ERRORS.AUTH.INVALID_REFRESH_TOKEN), 401);
  }
};

const precheckAccountLock = async (req, res, next) => {
  try {
    const email = req.body?.email?.toLowerCase?.()?.trim?.();
    if (!email) return next();

    const user = await User.findOne({ email }).select('lockoutUntil isActive');
    
    if (!user?.isActive) {
      return response.error(res, req.t(ERRORS.AUTH.ACCOUNT_INACTIVE), 401);
    }
    
    if (!user?.lockoutUntil || user.lockoutUntil.getTime() <= Date.now()) {
      return next();
    }

    const retrySec = Math.max(1, Math.ceil((user.lockoutUntil.getTime() - Date.now()) / 1000));
    const minute = Math.floor(retrySec / 60);
    const remain = retrySec % 60;
    
    res.set('Retry-After', String(retrySec));
    return response.error(res, req.t(ERRORS.AUTH.ACCOUNT_LOCKED_DYNAMIC, { minute, seconds: remain }), 423);
  } catch (error) {
    return next();
  }
};

module.exports = { authenticate, refreshTokenAuth, precheckAccountLock };
