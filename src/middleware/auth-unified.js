const config = require('../config');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const KeycloakRoleService = require('../services/keycloakRoleService');
const { mapKeycloakRolesToLocal } = require('../utils/sso');
const Role = require('../models/Role');

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
        user = await processJwtUser(decoded);
        authMethod = 'jwt';
      } catch (e) {
        // JWT verification failed - debug log kaldırıldı
      }
    }
  }

  if (!user && ['SSO', 'HYBRID'].includes(config.auth.mode) && req.isAuthenticated && req.isAuthenticated()) {
    try {
      user = await processKeycloakUser(req.user, req);
      if (user && user.sso?.keycloakId) {
        authMethod = 'sso';
      } else {
        console.error('ensureAuthUnified: Invalid SSO user data', user); // Bu error log'u koru
        user = null;
      }
    } catch (err) {
      console.error('ensureAuthUnified: Error processing SSO user', err); // Bu error log'u koru
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

  // İzinleri standart formata çevir
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
      console.warn('processKeycloakUser: No Keycloak ID found in profile'); // Bu warn'ı koru
    }

    const permissions = Array.isArray(kcUser.permissions) && kcUser.permissions.length
      ? kcUser.permissions
      : await KeycloakRoleService.mapKeycloakRolesToPermissions(kcRoles);
    
    const now = Date.now();
    const req = reqOrOptions && reqOrOptions.session !== undefined ? reqOrOptions : null;
    const throttleMs = 5 * 60 * 1000;
    const lastSynced = req?.session?.kcProfileSyncedAt || 0;
    const shouldSync = now - lastSynced > throttleMs;

    let dbUser = kcUser.user;

    if ((!dbUser || shouldSync) && keycloakId) {
      try {
        dbUser = await KeycloakRoleService.updateUserKeycloakInfo(
          keycloakId, kcRoles, kcUser.profile._json || kcUser.profile, { updateLastLogin: false }
        );
        if (req?.session) req.session.kcProfileSyncedAt = now;
      } catch (syncErr) {
        console.error('processKeycloakUser: Sync error', syncErr); // Bu error log'u koru
      }
    }

    let roleDocs = [];
    if (localRoles?.length) {
      roleDocs = await Role.find({
        name: { $in: localRoles },
        isActive: true
      }).select('name displayName description priority isActive permissions');
    }

    return {
      _id: dbUser?._id,
      id: keycloakId || dbUser?._id,
      email: kcUser.profile?._json?.email || kcUser.profile?.email || dbUser?.email,
      firstName: kcUser.profile?._json?.given_name || kcUser.profile?.firstName || dbUser?.firstName,
      lastName: kcUser.profile?._json?.family_name || kcUser.profile?.lastName || dbUser?.lastName,
      roles: roleDocs.length ? roleDocs : localRoles,
      permissions: permissions,
      isActive: dbUser?.isActive !== false,
      profile: kcUser.profile || dbUser?.profile || {},
      lastLogin: dbUser?.lastLogin,
      createdAt: dbUser?.createdAt,
      authMethod: 'sso',
      sso: { 
        provider: 'keycloak', 
        keycloakId: keycloakId
      }
    };
  } catch (error) {
    console.error('Error processing Keycloak user:', error); // Bu error log'u koru
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
    console.error('Error processing JWT user:', error); // Bu error log'u koru
    throw error;
  }
}

module.exports = { ensureAuthUnified, processKeycloakUser, processJwtUser, standardizeUser };
