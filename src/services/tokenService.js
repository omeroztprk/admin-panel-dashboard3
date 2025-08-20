const crypto = require('crypto');
const RefreshToken = require('../models/RefreshToken');
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require('../config/jwt');
const { ERRORS } = require('../utils/constants');
const { parseUserAgent } = require('../utils/helpers');

const saveRefreshToken = async (tokenData) => {
  const { token, userId, userAgent, ipAddress, deviceId } = tokenData;

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

  try {
    const doc = await RefreshToken.create({
      tokenHash,
      jti,
      user: userId,
      expiresAt,
      isBlacklisted: false,
      deviceInfo: {
        userAgent,
        ipAddress,
        deviceId,
        platform: parsed.platform,
        browser: parsed.browser
      }
    });
    return doc;
  } catch (e) {
    if (e && e.code === 11000) {
      const existing = await RefreshToken.findOne({ tokenHash });
      if (existing) return existing;
    }
    throw e;
  }
};

const refreshAccessToken = async (refreshTokenDoc, refreshTokenPlain) => {
  try {
    const decoded = await verifyRefreshToken(refreshTokenPlain);
    if (!refreshTokenDoc.isValid) {
      throw new Error(ERRORS.AUTH.INVALID_REFRESH_TOKEN);
    }

    refreshTokenDoc.lastUsed = new Date();
    await refreshTokenDoc.save();

    const accessToken = await generateAccessToken({ userId: decoded.userId });
    const newRefreshTokenValue = await generateRefreshToken({ userId: decoded.userId });

    await refreshTokenDoc.blacklist();

    await saveRefreshToken({
      token: newRefreshTokenValue,
      userId: decoded.userId,
      userAgent: refreshTokenDoc.deviceInfo?.userAgent,
      ipAddress: refreshTokenDoc.deviceInfo?.ipAddress,
      deviceId: refreshTokenDoc.deviceInfo?.deviceId
    });

    return { accessToken, refreshToken: newRefreshTokenValue };
  } catch (error) {
    throw new Error(ERRORS.AUTH.INVALID_REFRESH_TOKEN);
  }
};

const blacklistRefreshToken = async (plainToken) => {
  const tokenHash = crypto.createHash('sha256').update(String(plainToken)).digest('hex');
  const refreshToken = await RefreshToken.findOne({ tokenHash });
  if (refreshToken) await refreshToken.blacklist();
  return true;
};

const blacklistAllUserTokens = async (userId) => {
  await RefreshToken.updateMany(
    { user: userId, isBlacklisted: false },
    { isBlacklisted: true }
  );
  return true;
};

module.exports = {
  saveRefreshToken,
  refreshAccessToken,
  blacklistRefreshToken,
  blacklistAllUserTokens
};
