const config = require('../config');
const logger = require('../utils/logger');
const { getRedis } = require('../config/redis');
const User = require('../models/User');
const { filterKeycloakRoles } = require('../utils/sso');
const KeycloakService = require('./keycloakService');
const mongoose = require('mongoose');
const tokenService = require('./tokenService');

let _timer = null;

function isEnabled() {
  return !!config.auth?.keycloak?.sync?.enabled;
}

function getIntervalMs() {
  return Number(config.auth.keycloak.sync.intervalMs) || 300000;
}

function getBatchSize() {
  return Number(config.auth.keycloak.sync.batchSize) || 100;
}

function lockKey() {
  return String(config.auth.keycloak.sync.lockKey);
}

function cursorKey() {
  return String(config.auth.keycloak.sync.cursorKey);
}

async function acquireLock(ttlMs) {
  try {
    const redis = getRedis();
    if (!redis?.isOpen) return true;
    const res = await redis.set(lockKey(), '1', { NX: true, PX: ttlMs });
    return res === 'OK';
  } catch {
    return true;
  }
}

async function runLocalFollow(batchSize) {
  const redis = getRedis();
  let lastId = null;
  try {
    lastId = (await redis?.get(cursorKey())) || null;
  } catch { }

  const query = { 'sso.provider': 'keycloak' };
  if (lastId) {
    try {
      query._id = { $gt: new mongoose.Types.ObjectId(lastId) };
    } catch {
      try { await redis?.del(cursorKey()); } catch { }
    }
  }

  const users = await User.find(query).select('_id sso.keycloakId email').sort({ _id: 1 }).limit(batchSize);
  if (!users.length) {
    try { await redis?.del(cursorKey()); } catch { }
    return { processed: 0, finished: true };
  }

  let processed = 0;
  for (const u of users) {
    const kcId = u?.sso?.keycloakId;
    if (!kcId) continue;

    try {
      const kcUser = await KeycloakService.kcGetUser(kcId);
      const kcRoles = await KeycloakService.kcGetUserRealmRoles(kcId);
      const roleNames = (kcRoles || []).map(r => r.name);
      const filtered = filterKeycloakRoles(roleNames, config.auth.keycloak.realm);

      await KeycloakService.updateUserKeycloakInfo(kcId, filtered, kcUser || {}, { updateLastLogin: false });
      processed += 1;
    } catch (e) {
      if (e && (e.statusCode === 404 || e.status === 404)) {
        try {
          await tokenService.blacklistAllUserTokens(u._id);
        } catch (err) {
          logger.warn('keycloakSync: blacklist failed', { userId: u._id?.toString(), error: err?.message });
        }
        try {
          await User.deleteOne({ _id: u._id });
          processed += 1;
        } catch (err) {
          logger.warn('keycloakSync: delete user failed', { userId: u._id?.toString(), error: err?.message });
        }
      } else {
        logger.warn('keycloakSync: user sync failed', { userId: u._id?.toString(), kcId, error: e?.message });
      }
    }

    try { await redis?.set(cursorKey(), String(u._id)); } catch { }
  }

  return { processed, finished: false };
}

async function runRealmScan(batchSize) {
  let first = 0;
  let processed = 0;
  while (true) {
    const list = await KeycloakService.kcListUsers({ first, max: batchSize });
    if (!Array.isArray(list) || list.length === 0) break;

    for (const kc of list) {
      const kcId = kc?.id;
      if (!kcId) continue;

      try {
        const kcRoles = await KeycloakService.kcGetUserRealmRoles(kcId);
        const roleNames = (kcRoles || []).map(r => r.name);
        const filtered = filterKeycloakRoles(roleNames, config.auth.keycloak.realm);

        await KeycloakService.updateUserKeycloakInfo(kcId, filtered, kc || {}, { updateLastLogin: false });
        processed += 1;
      } catch (e) {
        logger.warn('keycloakSync: realm user sync failed', { kcId, error: e?.message });
      }
    }

    if (list.length < batchSize) break;
    first += batchSize;
  }
  return { processed, finished: true };
}

async function tick() {
  const intervalMs = getIntervalMs();
  const gotLock = await acquireLock(Math.max(5000, intervalMs - 1000));
  if (!gotLock) return;

  const mode = (config.auth.keycloak.sync.mode || 'local-follow').toLowerCase();
  const batchSize = getBatchSize();

  try {
    if (mode === 'realm-scan') {
      const res = await runRealmScan(batchSize);
      logger.info('keycloakSync: realm-scan run completed', res);
    } else {
      const res = await runLocalFollow(batchSize);
      logger.info('keycloakSync: local-follow batch run', res);
    }
  } catch (e) {
    logger.error('keycloakSync: tick error', { error: e?.message });
  }
}

function startKeycloakPeriodicSync() {
  if (!isEnabled()) return;
  if (_timer) return;
  const intervalMs = getIntervalMs();
  logger.info('Keycloak periodic sync enabled', { intervalMs, batchSize: getBatchSize(), mode: config.auth.keycloak.sync.mode });
  tick().catch(() => { });
  _timer = setInterval(() => tick().catch(() => { }), intervalMs);
  _timer.unref?.();
}

function stopKeycloakPeriodicSync() {
  if (_timer) {
    clearInterval(_timer);
    _timer = null;
  }
}

module.exports = { startKeycloakPeriodicSync, stopKeycloakPeriodicSync };