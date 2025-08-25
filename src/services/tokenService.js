const crypto = require('crypto');
const RefreshToken = require('../models/RefreshToken');
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require('../config/jwt');
const { ERRORS } = require('../utils/constants');
const { parseUserAgent } = require('../utils/helpers');
const { getRedis, prefixKey } = require('../config/redis');
const jwt = require('jsonwebtoken');

const ACCESS_REVOKE_PREFIX = (jti) => prefixKey(`jwt:access:revoked:${jti}`);

async function blacklistAccessJti(jti, expiresAt) {
  if (!jti) return false;
  try {
    const redis = getRedis();
    if (!redis?.isOpen) return false;
    const ttlMs = Math.max(1000, (expiresAt ? (new Date(expiresAt).getTime() - Date.now()) : 15 * 60 * 1000));
    await redis.set(ACCESS_REVOKE_PREFIX(jti), '1', { PX: ttlMs });
    return true;
  } catch {
    return false;
  }
}

async function isAccessTokenRevoked(jti) {
  if (!jti) return false;
  try {
    const redis = getRedis();
    if (!redis?.isOpen) return false;
    const val = await redis.get(ACCESS_REVOKE_PREFIX(jti));
    return !!val;
  } catch {
    return false;
  }
}

const saveRefreshToken = async (tokenData) => {
  const { token, userId, userAgent, ipAddress, deviceId, accessJti, accessExp } = tokenData;

  const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');

  let decoded;
  try {
    decoded = await verifyRefreshToken(token);
  } catch {
    throw new Error(ERRORS.AUTH.INVALID_REFRESH_TOKEN);
  }

  const expiresAt = decoded?.exp ? new Date(decoded.exp * 1000) : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const jti = decoded?.jti || (crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'));

  const parsed = parseUserAgent(userAgent);

  const doc = new RefreshToken({
    tokenHash,
    jti,
    user: userId,
    expiresAt,
    isBlacklisted: false,
    deviceInfo: {
      userAgent: userAgent || 'Unknown',
      ipAddress: ipAddress || 'Unknown',
      deviceId: deviceId || undefined,
      ...parseUserAgent(userAgent || '')
    },
    lastAccessJti: accessJti || undefined,
    lastAccessExpiresAt: accessExp ? new Date(accessExp) : undefined
  });

  await doc.save();
  return doc;
};

const refreshAccessToken = async (refreshTokenDoc, refreshTokenPlain) => {
  try {
    const decoded = await verifyRefreshToken(refreshTokenPlain);
    if (!refreshTokenDoc.isValid) {
      throw new Error(ERRORS.AUTH.INVALID_REFRESH_TOKEN);
    }

    const atJti = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
    const accessToken = await generateAccessToken({ userId: decoded.userId, jti: atJti });
    const atDecoded = jwt.decode(accessToken);

    const newRefreshTokenValue = await generateRefreshToken({ userId: decoded.userId });

    await refreshTokenDoc.blacklist();

    await saveRefreshToken({
      token: newRefreshTokenValue,
      userId: decoded.userId,
      userAgent: refreshTokenDoc.deviceInfo?.userAgent,
      ipAddress: refreshTokenDoc.deviceInfo?.ipAddress,
      deviceId: refreshTokenDoc.deviceInfo?.deviceId,
      accessJti: atJti,
      accessExp: atDecoded?.exp ? atDecoded.exp * 1000 : undefined
    });

    return { accessToken, refreshToken: newRefreshTokenValue };
  } catch (error) {
    throw new Error(ERRORS.AUTH.INVALID_REFRESH_TOKEN);
  }
};

const blacklistRefreshToken = async (plainToken) => {
  const tokenHash = crypto.createHash('sha256').update(String(plainToken)).digest('hex');
  const doc = await RefreshToken.findOneAndUpdate(
    { tokenHash, isBlacklisted: false },
    { isBlacklisted: true },
    { new: true }
  );

  if (doc?.lastAccessJti) {
    await blacklistAccessJti(doc.lastAccessJti, doc.lastAccessExpiresAt);
  }

  if (!doc) throw new Error(ERRORS.AUTH.REFRESH_TOKEN_INVALID);
  return true;
};

const blacklistAllUserTokens = async (userId) => {
  const tokens = await RefreshToken.find({ user: userId, isBlacklisted: false }).select('lastAccessJti lastAccessExpiresAt');
  await RefreshToken.updateMany(
    { user: userId, isBlacklisted: false },
    { isBlacklisted: true }
  );

  for (const t of tokens) {
    if (t.lastAccessJti) {
      await blacklistAccessJti(t.lastAccessJti, t.lastAccessExpiresAt);
    }
  }
  return true;
};

module.exports = {
  saveRefreshToken,
  refreshAccessToken,
  blacklistRefreshToken,
  blacklistAllUserTokens,
  blacklistAccessJti,
  isAccessTokenRevoked
};
