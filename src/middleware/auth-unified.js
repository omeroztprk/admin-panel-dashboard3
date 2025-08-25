const config = require('../config');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const KeycloakService = require('../services/keycloakService');
const { mapKeycloakRolesToLocal } = require('../utils/sso');
const Role = require('../models/Role');
const logger = require('../utils/logger');
const tokenService = require('../services/tokenService');
const { getRedis, prefixKey } = require('../config/redis');

async function getKcStatusCached(keycloakId) {
  if (!keycloakId) return { exists: null, enabled: null };
  const ttlSec = Number(process.env.KEYCLOAK_ENABLED_CACHE_TTL || 30);
  const key = prefixKey(`kc:user:status:${keycloakId}`);

  try {
    const redis = getRedis();
    if (redis?.isOpen) {
      const cached = await redis.get(key);
      if (cached !== null && cached !== undefined) {
        try { return JSON.parse(cached); } catch { }
      }
    }

    let exists = null, enabled = null;
    try {
      const kc = await KeycloakService.kcGetUser(keycloakId);
      exists = true;
      enabled = !!kc?.enabled;
    } catch (e) {
      if (e && (e.statusCode === 404 || e.status === 404)) {
        exists = false;
        enabled = null;
      } else {
        exists = null;
        enabled = null;
      }
    }

    const payload = JSON.stringify({ exists, enabled });
    if (redis?.isOpen) await redis.set(key, payload, { EX: Math.max(5, ttlSec) });
    return { exists, enabled };
  } catch (e) {
    logger.warn('getKcStatusCached failed', { error: e?.message });
    return { exists: null, enabled: null };
  }
}

async function ensureAuthUnified(req, res, next) {
  let user = null;
  let authMethod = 'none';

  if (['DEFAULT', 'HYBRID'].includes(config.auth.mode)) {
    const auth = req.headers['authorization'] || '';
    const match = auth.match(/^Bearer\s+(.+)$/i);
    if (match) {
      try {
        const decoded = jwt.verify(match[1], config.jwt.access.secret, {
          issuer: config.jwt.issuer,
          audience: config.jwt.audience
        });

        if (decoded?.jti && await tokenService.isAccessTokenRevoked(decoded.jti)) {
          return res.status(401).json({ message: 'Token revoked' });
        }

        user = await processJwtUser(decoded);
        authMethod = 'jwt';
      } catch (e) {
      }
    }
  }

  if (!user && ['SSO', 'HYBRID'].includes(config.auth.mode) && req.isAuthenticated && req.isAuthenticated()) {
    try {
      user = await processKeycloakUser(req.user, req);
      if (user && user.sso?.keycloakId) {
        if (user.isActive === false || !user._id || user.__kcDeleted === true) {
          try { await KeycloakService.kcRevokeAllUserSessions(user.sso.keycloakId); } catch (err) {
            logger.warn('ensureAuthUnified: kcRevokeAllUserSessions failed', { error: err?.message });
          }
          try {
            if (typeof req.logout === 'function') await new Promise(resolve => req.logout(resolve));
            req.session?.destroy?.(() => {});
          } catch (err) {
            logger.warn('ensureAuthUnified: local session destroy failed', { error: err?.message });
          }
          return res.status(401).json({ message: 'Account inactive', code: 'ACCOUNT_INACTIVE' });
        }
        authMethod = 'sso';
      } else {
        logger.error('ensureAuthUnified: Invalid SSO user data', { user: user?.id });
        user = null;
      }
    } catch (err) {
      logger.error('ensureAuthUnified: Error processing SSO user', { error: err?.message });
    }
  }

  if (!user) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  req.user = standardizeUser(user, authMethod);
  req.authMethod = authMethod;
  return next();
}

function standardizeUser(user, authMethod) {
  let sso = user.sso || {};
  
  if (authMethod === 'sso' && user.profile?.id && !sso.keycloakId) {
    sso.keycloakId = user.profile.id;
    sso.provider = 'keycloak';
  }
  
  if (authMethod === 'jwt') {
    sso = {};
  }

  const standardRoles = (user.roles || []).map(role => {
    if (typeof role === 'string') {
      return {
        _id: null,
        name: role,
        displayName: String(role).replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
        description: null,
        priority: 0,
        isActive: true
      };
    }
    return {
      _id: role._id || null,
      name: role.name,
      displayName: role.displayName || String(role.name).replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      description: role.description || null,
      priority: role.priority || 0,
      isActive: role.isActive !== false
    };
  });

  const standardPermissions = (user.permissions || []).map(permission => ({
    _id: permission._id || null,
    name: permission.name || `${permission.resource}:${permission.action}`,
    displayName: permission.displayName || permission.name,
    resource: permission.resource,
    action: permission.action,
    description: permission.description || null,
    category: permission.category || null,
    isActive: permission.isActive !== false,
    granted: permission.granted !== false
  }));

  return {
    _id: user._id,
    id: user.id || user._id || (authMethod === 'sso' ? user.profile?.id : null),
    firstName: user.firstName || user.profile?.firstName || user.profile?._json?.given_name || 'Unknown',
    lastName: user.lastName || user.profile?.lastName || user.profile?._json?.family_name || 'User',
    email: user.email || user.profile?.email || user.profile?._json?.email,
    roles: standardRoles,
    permissions: standardPermissions,
    isActive: user.isActive !== false,
    profile: user.profile || {},
    lastLogin: user.lastLogin,
    createdAt: user.createdAt,
    authMethod: authMethod,
    sso: sso,
    getAllPermissions() {
      return standardPermissions;
    }
  };
}

async function processKeycloakUser(kcUser, reqOrOptions) {
  try {
    if (!kcUser) throw new Error('Invalid Keycloak user data');

    const kcRoles = kcUser.kcRoles || [];
    const localRoles = mapKeycloakRolesToLocal(kcRoles);
    const keycloakId = kcUser.profile?.id || kcUser.profile?._json?.sub;

    if (!keycloakId) {
      logger.warn('processKeycloakUser: No Keycloak ID found in profile');
    }

    let dbUser = kcUser.user;

    const forceSync = !!(reqOrOptions && reqOrOptions.forceSync === true);
    const shouldSync = forceSync && !!keycloakId;

    if (shouldSync) {
      try {
        dbUser = await KeycloakService.updateUserKeycloakInfo(
          keycloakId, kcRoles, kcUser.profile._json || kcUser.profile, { updateLastLogin: true }
        );
      } catch (syncErr) {
        logger.error('processKeycloakUser: Sync error', { error: syncErr.message });
      }
    }

    let freshUser = null;
    try {
      if (keycloakId) {
        freshUser = await User.findOne({ 'sso.keycloakId': keycloakId })
          .populate({
            path: 'roles',
            match: { isActive: true },
            select: 'name displayName description priority isActive permissions',
            populate: { path: 'permissions', match: { isActive: true } }
          })
          .populate({
            path: 'permissions.permission',
            select: 'name displayName resource action description category isActive'
          });
      } else if (dbUser?._id) {
        freshUser = await User.findById(dbUser._id)
          .populate({
            path: 'roles',
            match: { isActive: true },
            select: 'name displayName description priority isActive permissions',
            populate: { path: 'permissions', match: { isActive: true } }
          })
          .populate({
            path: 'permissions.permission',
            select: 'name displayName resource action description category isActive'
          });
      }
    } catch (e) {
      logger.error('processKeycloakUser: fresh load error', { error: e.message });
    }

    const dbFound = !!freshUser;
    dbUser = freshUser || dbUser;

    const kcStatus = keycloakId ? await getKcStatusCached(keycloakId) : { exists: null, enabled: null };

    if (kcStatus.enabled !== null && dbFound && freshUser.isActive !== kcStatus.enabled) {
      try {
        await User.updateOne({ _id: freshUser._id }, { $set: { isActive: kcStatus.enabled } });
        freshUser.isActive = kcStatus.enabled;
      } catch (e) {
        logger.warn('processKeycloakUser: failed to sync isActive from Keycloak', { error: e?.message });
      }
    }

    let kcDeleted = false;
    if (kcStatus.exists === false) {
      kcDeleted = true;
      if (dbFound) {
        try {
          await tokenService.blacklistAllUserTokens(freshUser._id);
        } catch (e) {
          logger.warn('processKeycloakUser: token blacklist failed', { userId: freshUser._id?.toString(), error: e?.message });
        }
        try {
          await User.deleteOne({ _id: freshUser._id });
          dbUser = null;
        } catch (e) {
          logger.warn('processKeycloakUser: delete user failed', { userId: freshUser._id?.toString(), error: e?.message });
        }
      }
    }

    let resolvedPermissions = [];
    try {
      if (freshUser && typeof freshUser.getAllPermissions === 'function') {
        resolvedPermissions = await freshUser.getAllPermissions();
      } else {
        resolvedPermissions = await KeycloakService.mapKeycloakRolesToPermissions(kcRoles);
      }
    } catch (e) {
      logger.error('processKeycloakUser: permission resolve error', { error: e.message });
    }

    let roleDocs = Array.isArray(freshUser?.roles) && freshUser.roles.length
      ? freshUser.roles
      : [];
    if (!roleDocs.length && localRoles?.length) {
      roleDocs = await Role.find({
        name: { $in: localRoles },
        isActive: true
      }).select('name displayName description priority isActive permissions');
    }

    const finalIsActive =
      kcStatus.exists === false ? false
      : (kcStatus.enabled !== null ? kcStatus.enabled
         : (dbFound ? (freshUser.isActive !== false) : false));

    return {
      _id: dbUser?._id,
      id: keycloakId || dbUser?._id,
      email: dbUser?.email || kcUser.profile?._json?.email || kcUser.profile?.email,
      firstName: dbUser?.firstName || kcUser.profile?._json?.given_name || kcUser.profile?.firstName,
      lastName: dbUser?.lastName || kcUser.profile?._json?.family_name || kcUser.profile?.lastName,
      roles: roleDocs.length ? roleDocs : localRoles,
      permissions: resolvedPermissions,
      isActive: finalIsActive,
      profile: dbUser?.profile || kcUser.profile || {},
      lastLogin: dbUser?.lastLogin,
      createdAt: dbUser?.createdAt,
      authMethod: 'sso',
      sso: { provider: 'keycloak', keycloakId },
      __kcDeleted: kcDeleted
    };
  } catch (error) {
    logger.error('Error processing Keycloak user:', { error: error.message });
    throw error;
  }
}

async function processJwtUser(decoded) {
  try {
    const userId = decoded.user?._id || decoded._id || decoded.userId;
    if (!userId) throw new Error('Invalid token payload');

    const user = await User.findById(userId)
      .populate({
        path: 'roles',
        match: { isActive: true },
        populate: {
          path: 'permissions',
          match: { isActive: true }
        }
      });

    if (!user || !user.isActive) {
      throw new Error('User not found or inactive');
    }

    const allPermissions = await user.getAllPermissions();

    return {
      _id: user._id,
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      roles: user.roles || [],
      permissions: allPermissions,
      isActive: user.isActive,
      profile: user.profile || {},
      lastLogin: user.lastLogin,
      createdAt: user.createdAt,
      authMethod: 'jwt'
    };
  } catch (error) {
    logger.error('Error processing JWT user:', { error: error.message });
    throw error;
  }
}

module.exports = { ensureAuthUnified, processKeycloakUser, processJwtUser, standardizeUser };
