const User = require('../models/User');
const { generateAccessToken, generateRefreshToken } = require('../config/jwt');
const { resolveLanguage } = require('../config/i18n');
const tokenService = require('./tokenService');
const { ERRORS } = require('../utils/constants');
const { normalizeEmail } = require('../utils/helpers');

const register = async (userData) => {
  const { firstName, lastName, email, password, profile, ipAddress, userAgent } = userData;

  const normalizedEmail = normalizeEmail(email);
  const existingUser = await User.findOne({ email: normalizedEmail });
  if (existingUser) {
    throw new Error(ERRORS.AUTH.EMAIL_EXISTS);
  }

  const language = resolveLanguage(profile?.language);

  const user = new User({
    firstName,
    lastName,
    email: normalizedEmail,
    password,
    profile: { ...(profile || {}), language },
    metadata: { ipAddress, userAgent }
  });

  await user.save();

  const accessToken = await generateAccessToken({ userId: user._id });
  const refreshTokenValue = await generateRefreshToken({ userId: user._id });

  await tokenService.saveRefreshToken({
    token: refreshTokenValue,
    userId: user._id,
    userAgent,
    ipAddress
  });

  await user.populate([
    {
      path: 'roles',
      populate: {
        path: 'permissions',
        select: 'name displayName resource action description category'
      }
    },
    {
      path: 'permissions.permission',
      select: 'name displayName resource action description category'
    }
  ]);

  user.password = undefined;

  return {
    user,
    accessToken,
    refreshToken: refreshTokenValue
  };
};

const login = async (credentials) => {
  const { email, password, ipAddress, userAgent } = credentials;
  const normalizedEmail = normalizeEmail(email);

  const user = await User.findOne({ email: normalizedEmail }).select('+password');
  if (!user) throw new Error(ERRORS.AUTH.INVALID_CREDENTIALS);

  if (user.isLocked) {
    const ms = Math.max(0, (user.lockoutUntil?.getTime?.() || 0) - Date.now());
    const retryAfterSec = Math.max(1, Math.ceil(ms / 1000));
    const err = new Error(ERRORS.AUTH.ACCOUNT_LOCKED);
    err.code = 'ACCOUNT_LOCKED';
    err.status = 423;
    err.retryAfterSec = retryAfterSec;
    err.lockoutUntil = user.lockoutUntil;
    throw err;
  }

  if (!user.isActive) throw new Error(ERRORS.AUTH.ACCOUNT_INACTIVE);

  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    await user.incLoginAttempts();
    throw new Error(ERRORS.AUTH.INVALID_CREDENTIALS);
  }

  if (user.loginAttempts > 0) {
    await user.resetLoginAttempts();
  }

  user.lastLogin = new Date();
  await user.save();

  const accessToken = await generateAccessToken({ userId: user._id });
  const refreshTokenValue = await generateRefreshToken({ userId: user._id });

  await tokenService.saveRefreshToken({
    token: refreshTokenValue,
    userId: user._id,
    userAgent,
    ipAddress
  });

  await user.populate([
    {
      path: 'roles',
      select: 'name displayName description priority permissions',
      populate: {
        path: 'permissions',
        select: 'name displayName resource action description category isActive'
      }
    },
    {
      path: 'permissions.permission',
      select: 'name displayName resource action description category isActive'
    }
  ]);

  user.password = undefined;

  return {
    user,
    accessToken,
    refreshToken: refreshTokenValue
  };
};

const logout = async (_userId, refreshToken) => {
  if (refreshToken) {
    await tokenService.blacklistRefreshToken(refreshToken);
  }
  return true;
};

const logoutAll = async (userId) => {
  await tokenService.blacklistAllUserTokens(userId);
  return true;
};

const getMe = async (userId) => {
  const user = await User.findById(userId).populate([
    {
      path: 'roles',
      select: 'name displayName description priority permissions',
      populate: {
        path: 'permissions',
        select: 'name displayName resource action description category isActive'
      }
    },
    {
      path: 'permissions.permission',
      select: 'name displayName resource action description category isActive'
    }
  ]);

  if (!user) throw new Error(ERRORS.USER.NOT_FOUND);
  return user;
};

const updateProfile = async (userId, updates) => {
  const allowedFields = ['firstName', 'lastName', 'profile'];
  const filteredUpdates = {};
  allowedFields.forEach((f) => {
    if (updates[f] !== undefined) filteredUpdates[f] = updates[f];
  });

  if (filteredUpdates.profile?.language) {
    filteredUpdates.profile.language = resolveLanguage(filteredUpdates.profile.language);
  }

  const user = await User.findByIdAndUpdate(
    userId,
    filteredUpdates,
    { new: true, runValidators: true }
  ).populate([
    {
      path: 'roles',
      select: 'name displayName description priority permissions',
      populate: {
        path: 'permissions',
        select: 'name displayName resource action description category isActive'
      }
    },
    {
      path: 'permissions.permission',
      select: 'name displayName resource action description category isActive'
    }
  ]);

  if (!user) throw new Error(ERRORS.USER.NOT_FOUND);
  return user;
};

const changePassword = async (userId, currentPassword, newPassword) => {
  const user = await User.findById(userId).select('+password');
  if (!user) {
    const err = new Error(ERRORS.USER.NOT_FOUND);
    err.statusCode = 404;
    throw err;
  }

  const isCurrentPasswordValid = await user.comparePassword(currentPassword);
  if (!isCurrentPasswordValid) {
    const err = new Error(ERRORS.AUTH.INVALID_CURRENT_PASSWORD);
    err.statusCode = 400;
    throw err;
  }

  const isSameAsCurrent = await user.comparePassword(newPassword);
  if (isSameAsCurrent) {
    const err = new Error(ERRORS.VALIDATION.PASSWORDS_SAME);
    err.statusCode = 400;
    throw err;
  }

  user.password = newPassword;
  await user.save();

  await tokenService.blacklistAllUserTokens(userId);

  return true;
};

const getActiveSessions = async (userId) => {
  const sessions = await tokenService.getUserActiveSessions(userId);
  return sessions.map((s) => ({
    id: s._id,
    deviceInfo: s.deviceInfo,
    lastUsed: s.lastUsed,
    createdAt: s.createdAt,
    expiresAt: s.expiresAt
  }));
};

const revokeSession = async (userId, tokenId) => {
  await tokenService.revokeSession(userId, tokenId);
  return true;
};

module.exports = {
  register,
  login,
  logout,
  logoutAll,
  getMe,
  updateProfile,
  changePassword,
  getActiveSessions,
  revokeSession
};
