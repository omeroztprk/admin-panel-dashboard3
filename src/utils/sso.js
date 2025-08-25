const config = require('../config');
const jwt = require('jsonwebtoken');

const builtinRolePrefixes = ['default-roles-'];
const builtinRoles = new Set(['offline_access', 'uma_authorization']);

function isBuiltinRole(role, realm) {
  if (builtinRoles.has(role)) return true;
  return builtinRolePrefixes.some(p => role.startsWith(`${p}${realm}`));
}

function filterKeycloakRoles(kcRoles = [], realm) {
  return kcRoles.filter(r => !isBuiltinRole(r, realm));
} 

function mapKeycloakRolesToLocal(kcRoles = []) {
  const mapping = config.auth.keycloak.roleMapping || {};
  return kcRoles.map(r => mapping[`realm:${r}`]).filter(Boolean);
}

function extractRolesFromToken(token, clientId) {
  try {
    const dec = jwt.decode(token) || {};
    const realmRoles = dec?.realm_access?.roles || [];
    const clientRoles = dec?.resource_access?.[clientId]?.roles || [];
    return Array.from(new Set([...realmRoles, ...clientRoles]));
  } catch {
    return [];
  }
}

function mapLocalRolesToKeycloak(localRoleNames = []) {
  const mapping = config.auth.keycloak.roleMapping || {};
  const reverse = {};
  for (const [k, v] of Object.entries(mapping)) {
    if (k.startsWith('realm:') && v) {
      reverse[v] = k.slice('realm:'.length); // 'realm:kcRole' -> 'kcRole'
    }
  }
  return localRoleNames.map(l => reverse[l]).filter(Boolean);
}

module.exports = { filterKeycloakRoles, mapKeycloakRolesToLocal, extractRolesFromToken, mapLocalRolesToKeycloak };
