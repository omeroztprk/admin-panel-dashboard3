const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { generateAccessToken, generateRefreshToken } = require('../config/jwt');
const { resolveLanguage } = require('../config/i18n');
const tokenService = require('./tokenService');
const { ERRORS } = require('../utils/constants');
const { normalizeEmail, hashPassword, sleep } = require('../utils/helpers');
const { generateTfaCode, storeTfaCode, verifyTfaCode } = require('./tfaService');
const { sendTfaCode } = require('./emailService');
const { detectLanguage } = require('../config/i18n');
const config = require('../config');

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

  return { user };
};

const login = async (credentials) => {
  const { email, password, ipAddress, userAgent } = credentials;
  const normalizedEmail = normalizeEmail(email);

  const user = await User.findOne({ email: normalizedEmail }).select('+password');
  if (!user) {
    await sleep(100 + Math.floor(Math.random() * 200));
    throw new Error(ERRORS.AUTH.INVALID_CREDENTIALS);
  }

  if (user.isLocked) {
    const retryAfterSec = Math.max(1, Math.ceil(((user.lockoutUntil?.getTime?.() || 0) - Date.now()) / 1000));
    const err = new Error(ERRORS.AUTH.ACCOUNT_LOCKED);
    err.code = 'ACCOUNT_LOCKED';
    err.status = 423;
    err.retryAfterSec = retryAfterSec;
    err.lockoutUntil = user.lockoutUntil;
    throw err;
  }

  if (!user.isActive) {
    throw new Error(ERRORS.AUTH.ACCOUNT_INACTIVE);
  }

  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    await user.incLoginAttempts();
    await sleep(100 + Math.floor(Math.random() * 200));
    throw new Error(ERRORS.AUTH.INVALID_CREDENTIALS);
  }

  if (user.loginAttempts > 0) {
    await user.resetLoginAttempts();
  }

  if (config.tfa.enabled) {
    const tfaCode = generateTfaCode();
    const stored = await storeTfaCode(normalizedEmail, tfaCode);
    
    if (!stored) {
      throw new Error(ERRORS.AUTH.TFA_EMAIL_FAILED);
    }

    const language = user.profile?.language || 'en';
    const emailSent = await sendTfaCode(normalizedEmail, tfaCode, language);
    
    if (!emailSent) {
      throw new Error(ERRORS.AUTH.TFA_EMAIL_FAILED);
    }

    const error = new Error(ERRORS.AUTH.TFA_CODE_REQUIRED);
    error.requiresTfa = true;
    error.email = normalizedEmail;
    throw error;
  }

  return await completeLogin(user, ipAddress, userAgent);
};

const verifyTfaAndLogin = async (email, tfaCode, ipAddress, userAgent) => {
  const normalizedEmail = normalizeEmail(email);
  
  await verifyTfaCode(normalizedEmail, tfaCode);
  
  const user = await User.findOne({ email: normalizedEmail }).select('+password');
  if (!user || !user.isActive || user.isLocked) {
    throw new Error(ERRORS.AUTH.INVALID_CREDENTIALS);
  }

  return await completeLogin(user, ipAddress, userAgent);
};

const completeLogin = async (user, ipAddress, userAgent) => {
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

  if (!user) {
    throw new Error(ERRORS.USER.NOT_FOUND);
  }
  return user;
};

const updateProfile = async (userId, updates) => {
  const allowedFields = ['firstName', 'lastName', 'profile'];
  const filteredUpdates = {};
  
  allowedFields.forEach((field) => {
    if (updates[field] !== undefined) {
      filteredUpdates[field] = updates[field];
    }
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

  if (!user) {
    throw new Error(ERRORS.USER.NOT_FOUND);
  }
  return user;
};

const changePassword = async (userId, currentPassword, newPassword) => {
  const user = await User.findById(userId).select('+password');
  if (!user) {
    throw new Error(ERRORS.USER.NOT_FOUND);
  }

  const isCurrentPasswordValid = await user.comparePassword(currentPassword);
  if (!isCurrentPasswordValid) {
    throw new Error(ERRORS.AUTH.INVALID_CURRENT_PASSWORD);
  }

  const isSameAsCurrent = await user.comparePassword(newPassword);
  if (isSameAsCurrent) {
    throw new Error(ERRORS.VALIDATION.PASSWORDS_SAME);
  }

  user.password = newPassword;
  await user.save();

  await tokenService.blacklistAllUserTokens(userId);

  return true;
};

const getActiveSessions = async (userId) => {
  const sessions = await RefreshToken.find({
    user: userId,
    isBlacklisted: false,
    expiresAt: { $gt: new Date() }
  }).sort({ createdAt: -1 });

  return sessions.map((session) => ({
    id: session._id,
    deviceInfo: session.deviceInfo,
    lastUsed: session.lastUsed,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt
  }));
};

const revokeSession = async (userId, tokenId) => {
  const token = await RefreshToken.findOne({ _id: tokenId, user: userId });
  if (!token) throw new Error(ERRORS.AUTH.INVALID_SESSION);
  await token.blacklist();
  return true;
};

module.exports = {
  register,
  login,
  verifyTfaAndLogin,
  logout,
  logoutAll,
  getMe,
  updateProfile,
  changePassword,
  getActiveSessions,
  revokeSession
};
