const logger = require('../utils/logger');
const response = require('../utils/response');
const { ERRORS } = require('../utils/constants');
const { getClientIP } = require('../utils/helpers');

const hasPermission = (requiredPermission) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return response.error(res, req.t(ERRORS.AUTH.AUTHENTICATION_REQUIRED), 401);
      }

      let userPermissions;
      try {
        userPermissions = await req.user.getAllPermissions();
      } catch (error) {
        logger.error('Failed to get user permissions', error);
        return response.error(res, req.t(ERRORS.GENERAL.INTERNAL_ERROR), 500);
      }

      const permissionNames = userPermissions.map((p) => p.name || `${p.resource}:${p.action}`);
      if (permissionNames.includes(requiredPermission)) return next();

      const [resource, action] = requiredPermission.split(':');
      if (resource && action) {
        const wildcardPermissions = [`${resource}:*`, `*:${action}`, '*:*', `${resource}:manage`];
        const hasWildcard = wildcardPermissions.some((perm) => permissionNames.includes(perm));
        if (hasWildcard) return next();
      }

      logger.warn('Permission denied', {
        userId: req.user._id,
        requiredPermission,
        userPermissions: permissionNames,
        endpoint: req.originalUrl,
        method: req.method,
        ip: getClientIP(req)
      });

      return response.error(res, req.t(ERRORS.AUTH.INSUFFICIENT_PERMISSIONS), 403);
    } catch (error) {
      logger.error('RBAC permission check error', error);
      return response.error(res, req.t(ERRORS.GENERAL.INTERNAL_ERROR), 500);
    }
  };
};

const isSelfOrHasPermission = (permission) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return response.error(res, req.t(ERRORS.AUTH.AUTHENTICATION_REQUIRED), 401);
      }

      const targetUserId = req.params.id || req.params.userId;

      if (targetUserId) {
        if (!/^[0-9a-fA-F]{24}$/.test(targetUserId)) {
          return response.error(res, req.t(ERRORS.VALIDATION.INVALID_ID), 400);
        }
        if (req.user._id.toString() === targetUserId) {
          return next();
        }
      }

      return hasPermission(permission)(req, res, next);
    } catch (error) {
      logger.error('RBAC self-or-permission check error', error);
      return response.error(res, req.t(ERRORS.GENERAL.INTERNAL_ERROR), 500);
    }
  };
};

module.exports = { hasPermission, isSelfOrHasPermission };
