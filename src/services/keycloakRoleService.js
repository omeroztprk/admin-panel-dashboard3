const User = require('../models/User');
const Role = require('../models/Role');
const Permission = require('../models/Permission');
const { mapKeycloakRolesToLocal } = require('../utils/sso');
const { filterKeycloakRoles } = require('../utils/sso'); // NEW import
const config = require('../config');
const fetch = global.fetch || require('node-fetch');

class KeycloakRoleService {
  static async mapKeycloakRolesToPermissions(kcRoles = []) {
    try {
      const localRoleNames = mapKeycloakRolesToLocal(kcRoles);
      if (!localRoleNames?.length) return [];

      const roles = await Role.find({
        name: { $in: localRoleNames },
        isActive: true
      }).populate({
        path: 'permissions',
        match: { isActive: true }
      });

      const permissionMap = new Map();
      roles.forEach(role => {
        role.permissions?.forEach(permission => {
          if (!permissionMap.has(permission._id.toString())) {
            permissionMap.set(permission._id.toString(), {
              _id: permission._id,
              name: permission.name,
              displayName: permission.displayName,
              resource: permission.resource,
              action: permission.action,
              description: permission.description,
              category: permission.category,
              isActive: permission.isActive
            });
          }
        });
      });

      return Array.from(permissionMap.values());
    } catch (error) {
      console.error('Error mapping Keycloak roles to permissions:', error);
      return [];
    }
  }

  static async updateUserKeycloakInfo(keycloakUserId, kcRoles = [], profile = {}, options = {}) {
    try {
      const localRoleNames = mapKeycloakRolesToLocal(kcRoles || []);
      const profileEmail = (profile?.email || '').toLowerCase().trim();

      // 1) Locate user by KC ID or fallback to email
      let user = await User.findOne({ 'sso.keycloakId': keycloakUserId });
      if (!user && profileEmail) {
        user = await User.findOne({ email: profileEmail });
        if (user) {
          user.sso = { keycloakId: keycloakUserId, provider: 'keycloak' };
        }
      }

      // 2) Create if missing
      if (!user) {
        user = new User({
          firstName: profile?.given_name || profile?.firstName || 'Unknown',
          lastName: profile?.family_name || profile?.lastName || 'User',
          email: profileEmail || `keycloak_${keycloakUserId}@unknown.com`,
          isActive: true,
          sso: { provider: 'keycloak', keycloakId: keycloakUserId }
        });
        user.$__skipValidation = true;
      }

      // 3) Map roles -> ids
      let roleIds = [];
      if (localRoleNames?.length) {
        const roles = await Role.find({ name: { $in: localRoleNames }, isActive: true }).select('_id name');
        roleIds = roles.map(r => r._id);
        const currentIds = (user.roles || []).map(r => r.toString()).sort().join(',');
        const desiredIds = roleIds.map(r => r.toString()).sort().join(',');
        if (currentIds !== desiredIds) {
          user.roles = roleIds;
        }
      }

      // 4) Sync profile basics (firstName, lastName, email, locale)
      const nextFirst = profile?.given_name ?? profile?.firstName;
      const nextLast = profile?.family_name ?? profile?.lastName;
      const nextEmail = profileEmail || undefined;

      if (nextFirst && nextFirst !== user.firstName) user.firstName = nextFirst;
      if (nextLast && nextLast !== user.lastName) user.lastName = nextLast;

      if (nextEmail && nextEmail !== user.email) {
        const exists = await User.findOne({ email: nextEmail, _id: { $ne: user._id } }).select('_id');
        if (!exists) {
          user.email = nextEmail;
        } else {
          console.warn(`updateUserKeycloakInfo: Email conflict for KC user ${keycloakUserId} -> ${nextEmail}, keeping local email ${user.email}`);
        }
      }

      const kcLocale = profile?.locale || profile?.attributes?.locale;
      if (kcLocale) {
        user.profile = user.profile || {};
        if (user.profile.language !== kcLocale) {
          user.profile.language = kcLocale;
        }
      }

      // 5) Audit-ish timestamp update (optional)
      if (options.updateLastLogin !== false) {
        user.lastLogin = new Date();
      }

      await user.save({ validateBeforeSave: false });
      return user;
    } catch (error) {
      console.error('Error updating user Keycloak info:', error);
      return null;
    }
  }
}

let _kcAdminToken = { token: null, exp: 0 };

async function getAdminAccessToken() {
  const now = Date.now();
  if (_kcAdminToken.token && now < _kcAdminToken.exp) return _kcAdminToken.token;

  const url = `${config.auth.keycloak.url}/realms/${config.auth.keycloak.realm}/protocol/openid-connect/token`;
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: config.auth.keycloak.adminClientId,
    client_secret: config.auth.keycloak.adminClientSecret
  });

  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`Keycloak token error: ${resp.status} ${text}`);
    err.statusCode = 502;
    throw err;
  }
  const data = await resp.json();
  _kcAdminToken = {
    token: data.access_token,
    exp: now + Math.max(0, (data.expires_in - 5)) * 1000
  };
  return _kcAdminToken.token;
}

function kcAdminBase() {
  return `${config.auth.keycloak.url}/admin/realms/${config.auth.keycloak.realm}`;
}

async function kcUpdateUserProfile(keycloakId, { firstName, lastName, email, enabled }) {
  const token = await getAdminAccessToken();
  const payload = {};
  if (firstName !== undefined) payload.firstName = firstName;
  if (lastName !== undefined) payload.lastName = lastName;
  if (email !== undefined) payload.email = email;
  if (enabled !== undefined) payload.enabled = !!enabled;

  const resp = await fetch(`${kcAdminBase()}/users/${keycloakId}`, {
    method: 'PUT',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`Keycloak update user failed: ${resp.status} ${text}`);
    err.statusCode = resp.status === 404 ? 404 : 502;
    throw err;
  }
  return true;
}

async function kcSetUserEnabled(keycloakId, enabled) {
  return kcUpdateUserProfile(keycloakId, { enabled });
}

async function kcResetPassword(keycloakId, newPassword, temporary = false) {
  const token = await getAdminAccessToken();
  const resp = await fetch(`${kcAdminBase()}/users/${keycloakId}/reset-password`, {
    method: 'PUT',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'password', value: newPassword, temporary: !!temporary })
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`Keycloak reset password failed: ${resp.status} ${text}`);
    err.statusCode = 502;
    throw err;
  }
  return true;
}

async function kcAssignRealmRoles(keycloakId, kcRoleNames = []) {
  const token = await getAdminAccessToken();

  // 1) Tüm realm rollerini çek
  const rolesResp = await fetch(`${kcAdminBase()}/roles`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!rolesResp.ok) {
    const text = await rolesResp.text().catch(() => '');
    const err = new Error(`Keycloak fetch roles failed: ${rolesResp.status} ${text}`);
    err.statusCode = 502;
    throw err;
  }
  const allRoles = await rolesResp.json(); // [{id,name}]

  const desired = allRoles.filter(r => kcRoleNames.includes(r.name));

  // 2) Kullanıcının mevcut realm rol atamalarını çek
  const currentResp = await fetch(`${kcAdminBase()}/users/${keycloakId}/role-mappings/realm`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!currentResp.ok) {
    const text = await currentResp.text().catch(() => '');
    const err = new Error(`Keycloak user role-mappings fetch failed (userId=${keycloakId}): ${currentResp.status} ${text}`);
    // 404'ü doğrudan öne çıkar, controller bunu status olarak dönecek
    err.statusCode = currentResp.status || 502;
    throw err;
  }
  const current = await currentResp.json();

  const currentNames = new Set(current.map(r => r.name));
  const desiredNames = new Set(desired.map(r => r.name));

  const toAdd = desired.filter(r => !currentNames.has(r.name));
  const toRemove = current.filter(r => !desiredNames.has(r.name));

  // 3) Ekle
  if (toAdd.length) {
    const respAdd = await fetch(`${kcAdminBase()}/users/${keycloakId}/role-mappings/realm`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(toAdd.map(r => ({ id: r.id, name: r.name })))
    });
    if (!respAdd.ok) {
      const text = await respAdd.text().catch(() => '');
      const err = new Error(`Keycloak add roles failed: ${respAdd.status} ${text}`);
      err.statusCode = 502;
      throw err;
    }
  }
  // 4) Kaldır
  if (toRemove.length) {
    const respDel = await fetch(`${kcAdminBase()}/users/${keycloakId}/role-mappings/realm`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(toRemove.map(r => ({ id: r.id, name: r.name })))
    });
    if (!respDel.ok) {
      const text = await respDel.text().catch(() => '');
      const err = new Error(`Keycloak remove roles failed: ${respDel.status} ${text}`);
      err.statusCode = 502;
      throw err;
    }
  }

  return true;
}

async function kcDeleteUser(keycloakId) {
  const token = await getAdminAccessToken();
  const resp = await fetch(`${kcAdminBase()}/users/${keycloakId}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${token}` }
  });
  // 204 = deleted, 404 = zaten yok → idempotent kabul et
  if (resp.status !== 204 && resp.status !== 404) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`Keycloak delete user failed: ${resp.status} ${text}`);
    err.statusCode = 502;
    throw err;
  }
  return true;
}

async function kcGetUserSessions(keycloakId) {
  const token = await getAdminAccessToken();
  const resp = await fetch(`${kcAdminBase()}/users/${keycloakId}/sessions`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    console.error(`kcGetUserSessions: Failed with status ${resp.status}: ${text}`); // Bu error log'u koru
    
    const err = new Error(`Keycloak get user sessions failed: ${resp.status} ${text}`);
    err.statusCode = resp.status === 404 ? 404 : 502;
    throw err;
  }
  
  const sessions = await resp.json();
  return sessions;
}

async function kcRevokeUserSession(sessionId) {
  const token = await getAdminAccessToken();
  const resp = await fetch(`${kcAdminBase()}/sessions/${sessionId}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!resp.ok && resp.status !== 404) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`Keycloak revoke session failed: ${resp.status} ${text}`);
    err.statusCode = 502;
    throw err;
  }
  return true;
}

async function kcRevokeAllUserSessions(keycloakId) {
  const token = await getAdminAccessToken();
  const resp = await fetch(`${kcAdminBase()}/users/${keycloakId}/logout`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`Keycloak logout user failed: ${resp.status} ${text}`);
    err.statusCode = 502;
    throw err;
  }
  return true;
}

async function kcGetUser(keycloakId) { // NEW
  const token = await getAdminAccessToken();
  const resp = await fetch(`${kcAdminBase()}/users/${keycloakId}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`Keycloak get user failed: ${resp.status} ${text}`);
    err.statusCode = resp.status === 404 ? 404 : 502;
    throw err;
  }
  return await resp.json();
}

async function kcGetUserRealmRoles(keycloakId) { // NEW
  const token = await getAdminAccessToken();
  const resp = await fetch(`${kcAdminBase()}/users/${keycloakId}/role-mappings/realm`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`Keycloak get user realm roles failed: ${resp.status} ${text}`);
    err.statusCode = resp.status === 404 ? 404 : 502;
    throw err;
  }
  const roles = await resp.json(); // [{name, id, ...}]
  const names = roles.map(r => r.name);
  // Filter built-in roles using realm name
  const realm = config.auth.keycloak.realm;
  const filtered = filterKeycloakRoles(names, realm);
  return filtered;
}

module.exports = {
  mapKeycloakRolesToPermissions: KeycloakRoleService.mapKeycloakRolesToPermissions,
  updateUserKeycloakInfo: KeycloakRoleService.updateUserKeycloakInfo,
  getAdminAccessToken,
  kcUpdateUserProfile,
  kcSetUserEnabled,
  kcResetPassword,
  kcAssignRealmRoles,
  kcDeleteUser,
  kcGetUserSessions,
  kcRevokeUserSession,
  kcRevokeAllUserSessions,
  kcGetUser,                 // NEW export
  kcGetUserRealmRoles        // NEW export
};