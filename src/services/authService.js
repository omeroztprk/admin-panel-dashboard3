const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { generateAccessToken, generateRefreshToken } = require('../config/jwt');
const { resolveLanguage } = require('../config/i18n');
const tokenService = require('./tokenService');
const { ERRORS } = require('../utils/constants');
const { normalizeEmail, hashPassword, sleep, isValidObjectId } = require('../utils/helpers');
const { generateTfaCode, storeTfaCode, verifyTfaCode } = require('./tfaService');
const { sendTfaCode } = require('./emailService');
const config = require('../config');
const crypto = require('crypto');
const KeycloakRoleService = require('./keycloakRoleService');

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

  // Frontend'in beklediği format için permissions'ı flatten et
  const allPermissions = await user.getAllPermissions();

  // Frontend için standart format
  return {
    _id: user._id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    roles: user.roles,
    permissions: allPermissions,
    isActive: user.isActive,
    profile: user.profile,
    lastLogin: user.lastLogin,
    createdAt: user.createdAt,
    authMethod: 'jwt' // DEFAULT/HYBRID modda JWT kullanıldığı için
  };
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

const getActiveSessions = async (userId, currentRefreshTokenPlain = '', options = {}) => {
  const source = (options && options.source) || 'auto';
  try {
    if (!userId) {
      throw new Error('Invalid user ID');
    }
    
    const { Types } = require('mongoose');
    let objectId;
    try {
      objectId = typeof userId === 'string' ? new Types.ObjectId(userId) : userId;
    } catch (e) {
      throw new Error('Invalid user ID format');
    }

    const user = await User.findById(objectId);
    if (!user) {
      throw new Error('User not found');
    }

    // Keycloak oturumları
    if ((source === 'keycloak' || (source === 'auto' && user.sso?.provider === 'keycloak')) && user.sso?.keycloakId) {
      try {
        let keycloakSessions = await KeycloakRoleService.kcGetUserSessions(user.sso.keycloakId);
        
        if (!keycloakSessions || !Array.isArray(keycloakSessions)) {
          keycloakSessions = [];
        }
        
        // Sadece Keycloak oturumları isteniyorsa
        if (source === 'keycloak') {
          return keycloakSessions.map(session => ({
            id: `kc-session-${session.id}`,
            isCurrent: false,
            createdAt: new Date(session.start * 1000).toISOString(),
            lastActivity: new Date(session.lastAccess * 1000).toISOString(),
            expiresAt: session.expires ? new Date(session.expires * 1000).toISOString() : null,
            ip: session.ipAddress || 'Unknown',
            device: {
              name: session.clients?.[0] || 'Keycloak',
              type: 'desktop',
              browser: session.browser || 'Unknown',
              os: session.os || 'Unknown'
            },
            location: { city: 'Unknown', country: 'Turkey' },
            source: 'keycloak'
          }));
        }
        
        const kcSessions = keycloakSessions.map(session => ({
          id: `kc-session-${session.id}`,
          isCurrent: false,
          createdAt: new Date(session.start * 1000).toISOString(),
          lastActivity: new Date(session.lastAccess * 1000).toISOString(),
          expiresAt: session.expires ? new Date(session.expires * 1000).toISOString() : null,
          ip: session.ipAddress || 'Unknown',
          device: {
            name: session.clients?.[0] || 'Keycloak Session',
            type: 'desktop',
            browser: session.browser || 'Unknown',
            os: session.os || 'Unknown'
          },
          location: { city: 'Unknown', country: 'Turkey' },
          source: 'keycloak'
        }));
        
        const jwtSessions = await getJwtSessions(objectId, currentRefreshTokenPlain);
        return [...kcSessions, ...jwtSessions];
      } catch (error) {
        console.error('Failed to fetch Keycloak sessions:', error); // Bu error log'u koru
        
        if (source === 'keycloak') {
          return [];
        }
      }
    }

    const jwtSessions = await getJwtSessions(objectId, currentRefreshTokenPlain);
    return jwtSessions;
  } catch (error) {
    console.error('Error getting active sessions:', error); // Bu error log'u koru
    throw new Error('Failed to fetch active sessions');
  }
};

const getJwtSessions = async (userId, currentRefreshTokenPlain) => {
  const refreshTokens = await RefreshToken.find({
    user: userId,
    isBlacklisted: false,
    expiresAt: { $gt: new Date() }
  })
  .populate('user', 'email')
  .sort({ createdAt: -1 })
  .lean();

  let currentHash = '';
  if (currentRefreshTokenPlain && typeof currentRefreshTokenPlain === 'string') {
    const crypto = require('crypto');
    currentHash = crypto.createHash('sha256').update(currentRefreshTokenPlain).digest('hex');
  }

  return refreshTokens.map(token => ({
    id: token._id.toString(),
    isCurrent: currentHash && token.tokenHash === currentHash,
    createdAt: token.createdAt,
    lastActivity: token.lastUsed || token.createdAt,
    expiresAt: token.expiresAt,
    ip: token.deviceInfo?.ipAddress || 'Unknown',
    device: {
      name: token.deviceInfo?.userAgent?.split(' ')[0] || 'Unknown Device',
      type: token.deviceInfo?.platform?.toLowerCase().includes('mobile') ? 'mobile' :
            token.deviceInfo?.platform?.toLowerCase().includes('tablet') ? 'tablet' : 'desktop',
      browser: token.deviceInfo?.browser || 'Unknown',
      os: token.deviceInfo?.platform || 'Unknown'
    },
    location: { city: 'Unknown', country: 'Turkey' },
    source: 'jwt'
  }));
};

const revokeSession = async (userId, sessionId) => {
  try {
    if (!userId) {
      throw new Error('Invalid user ID');
    }

    const { Types } = require('mongoose');
    let objectId;
    try {
      objectId = typeof userId === 'string' ? new Types.ObjectId(userId) : userId;
    } catch (e) {
      throw new Error('Invalid user ID format');
    }

    const user = await User.findById(objectId);
    if (!user) throw new Error('User not found');

    // Keycloak session ID kontrolü
    if (sessionId.startsWith('kc-session-') && user.sso?.keycloakId) {
      const realSessionId = sessionId.replace('kc-session-', '');
      return await KeycloakRoleService.kcRevokeUserSession(realSessionId);
    }

    // JWT refresh token
    const result = await RefreshToken.findOneAndUpdate(
      { _id: sessionId, user: objectId, isBlacklisted: false },
      { isBlacklisted: true },
      { new: true }
    );
    
    if (!result) {
      throw new Error('Session not found or already revoked');
    }
    
    return true;
  } catch (error) {
    console.error('Error revoking session:', error);
    throw error;
  }
};

const revokeAllSessions = async (userId) => {
  try {
   if (!userId) {
      throw new Error('Invalid user ID');
    }

   const { Types } = require('mongoose');
   let objectId;
   try {
     objectId = typeof userId === 'string' ? new Types.ObjectId(userId) : userId;
   } catch (e) {
     throw new Error('Invalid user ID format');
   }

   const user = await User.findById(objectId);
    if (!user) throw new Error('User not found');

    // SSO kullanıcı: Keycloak'taki tüm session'ları sonlandır
    if (user.sso?.provider === 'keycloak') {
      await KeycloakRoleService.kcRevokeAllUserSessions(user.sso.keycloakId);
    }

    // JWT token'larını da iptal et (HYBRID modda her iki tip session da olabilir)
    await RefreshToken.updateMany(
     { user: objectId, isBlacklisted: false },
      { isBlacklisted: true }
    );
    
    return true;
  } catch (error) {
    console.error('Error revoking all sessions:', error);
    throw new Error('Failed to revoke all sessions');
  }
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
  revokeSession,
  revokeAllSessions
};
