const User = require('../models/User');
const config = require('../config');
const {
  kcGetUser,
  kcGetUserRealmRoles,
  updateUserKeycloakInfo
} = require('./keycloakRoleService');

let _timer = null;

function isEnabled() {
  const modeOk = ['SSO', 'HYBRID'].includes(config.auth.mode);
  const flag = String(process.env.KEYCLOAK_SYNC_ENABLED || '').toLowerCase() === 'true';
  return modeOk && flag;
}

function getIntervalMs() {
  const dflt = 5 * 60 * 1000;
  const val = parseInt(process.env.KEYCLOAK_SYNC_INTERVAL_MS || '', 10);
  return Number.isFinite(val) && val > 10_000 ? val : dflt;
}

function getBatchSize() {
  const val = parseInt(process.env.KEYCLOAK_SYNC_BATCH || '', 10);
  return Number.isFinite(val) && val > 0 && val <= 500 ? val : 100;
}

async function tick() {
  try {
    const batch = getBatchSize();
    const users = await User.find({
      'sso.provider': 'keycloak',
      'sso.keycloakId': { $exists: true, $ne: null }
    })
      .select('_id email firstName lastName sso updatedAt')
      .limit(batch)
      .lean();

    if (!users.length) return;

    for (const u of users) {
      try {
        const kcUser = await kcGetUser(u.sso.keycloakId);
        const kcRoles = await kcGetUserRealmRoles(u.sso.keycloakId);
        await updateUserKeycloakInfo(u.sso.keycloakId, kcRoles, kcUser, { updateLastLogin: false });
      } catch (e) {
        console.error('keycloakSyncService: Failed to sync user', u.sso?.keycloakId, e?.message || e);
      }
    }
  } catch (e) {
    console.error('keycloakSyncService: Tick error', e?.message || e);
  }
}

function startKeycloakPeriodicSync() {
  if (!isEnabled()) return;
  if (_timer) return;

  const intervalMs = getIntervalMs();
  console.log(`Keycloak periodic sync enabled. Interval=${intervalMs}ms, batch=${getBatchSize()}`); // Bu servis başlatma log'u koru
  _timer = setInterval(tick, intervalMs);
  _timer.unref?.();
}

function stopKeycloakPeriodicSync() {
  if (_timer) {
    clearInterval(_timer);
    _timer = null;
  }
}

module.exports = { startKeycloakPeriodicSync, stopKeycloakPeriodicSync };