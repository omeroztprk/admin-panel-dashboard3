const authService = require('../services/authService');
const tokenService = require('../services/tokenService');
const { MESSAGES } = require('../utils/constants');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { getClientIP, sanitizeObject, maskEmail } = require('../utils/helpers');
const { resolveLanguage } = require('../config/i18n');
const config = require('../config');
const User = require('../models/User');
const { isValidObjectId } = require('../utils/helpers');

const register = asyncHandler(async (req, res) => {
  const userData = {
    ...req.body,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown'
  };

  const result = await authService.register(userData);

  const lng = resolveLanguage(result.user?.profile?.language);
  res.set('Content-Language', lng);

  return response.created(res, req.t(MESSAGES.AUTH.REGISTER_SUCCESS), {
    user: sanitizeObject(result.user),
    message: req.t('messages.auth.registration_completed')
  });
});

const login = asyncHandler(async (req, res) => {
  const credentials = {
    email: req.body.email,
    password: req.body.password,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown'
  };

  try {
    const result = await authService.login(credentials);

    const lng = resolveLanguage(result.user?.profile?.language);
    res.set('Content-Language', lng);

    return response.success(res, req.t(MESSAGES.AUTH.LOGIN_SUCCESS), {
      user: sanitizeObject(result.user),
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    });
  } catch (error) {
    if (error.requiresTfa) {
      return response.success(res, req.t(MESSAGES.AUTH.TFA_CODE_SENT), {
        requiresTfa: true,
        email: maskEmail(error.email),
        expiresIn: 300,
        maxAttempts: 3
      }, 202);
    }
    throw error;
  }
});

const verifyTfa = asyncHandler(async (req, res) => {
  const { email, tfaCode } = req.body;
  const ipAddress = getClientIP(req);
  const userAgent = req.get('User-Agent') || 'Unknown';

  const result = await authService.verifyTfaAndLogin(email, tfaCode, ipAddress, userAgent);

  const lng = resolveLanguage(result.user?.profile?.language);
  res.set('Content-Language', lng);

  return response.success(res, req.t(MESSAGES.AUTH.TFA_VERIFIED), {
    user: sanitizeObject(result.user),
    accessToken: result.accessToken,
    refreshToken: result.refreshToken
  });
});

const refreshToken = asyncHandler(async (req, res) => {
  const result = await tokenService.refreshAccessToken(
    req.refreshTokenDoc,
    req.refreshTokenPlain
  );

  return response.success(res, req.t(MESSAGES.AUTH.TOKEN_REFRESHED), {
    accessToken: result.accessToken,
    refreshToken: result.refreshToken
  });
});

const logout = asyncHandler(async (req, res) => {
  await authService.logout(req.user._id, req.body.refreshToken);
  return response.success(res, req.t(MESSAGES.AUTH.LOGOUT_SUCCESS));
});

const logoutAll = asyncHandler(async (req, res) => {
  const user = req.user;

  await authService.revokeAllSessions(user._id);

  if (user?.authMethod === 'sso' || user?.sso?.provider === 'keycloak') {
    req.logout(() => {
      req.session?.destroy(() => {
        return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS));
      });
    });
    return;
  }

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS));
});

const getMe = asyncHandler(async (req, res) => {
  const user = await authService.getMe(req.user._id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { user: sanitizeObject(user) });
});

const updateProfile = asyncHandler(async (req, res) => {
  const user = await authService.updateProfile(req.user._id, req.body);

  const lng = resolveLanguage(user?.profile?.language);
  res.set('Content-Language', lng);

  return response.success(res, req.t(MESSAGES.AUTH.PROFILE_UPDATED), { user: sanitizeObject(user) });
});

const changePassword = asyncHandler(async (req, res) => {
  await authService.changePassword(req.user._id, req.body.currentPassword, req.body.newPassword);
  return response.success(res, req.t(MESSAGES.AUTH.PASSWORD_CHANGED));
});

const getActiveSessions = asyncHandler(async (req, res) => {
  const user = req.user;
  const currentRt = req.get('x-refresh-token') || req.get('X-Refresh-Token') || '';

  let effectiveUserId = null;

  if (user?._id && isValidObjectId(user._id)) {
    effectiveUserId = user._id;
  } else if (user?.id && isValidObjectId(user.id)) {
    effectiveUserId = user.id;
  } else if (user?.sso?.keycloakId) {
    const bySso = await User.findOne({ 'sso.keycloakId': user.sso.keycloakId }).select('_id');
    if (bySso?._id) {
      effectiveUserId = bySso._id;
    }
  } else if (user?.email) {
    const byEmail = await User.findOne({ email: String(user.email).toLowerCase() }).select('_id');
    if (byEmail?._id) {
      effectiveUserId = byEmail._id;
    }
  }

  if (!effectiveUserId) {
    return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { sessions: [] });
  }

  try {
    let sessions = [];
    const authMethod = req.authMethod || user?.authMethod;

    if (config.auth?.mode === 'HYBRID' || authMethod === 'sso' || user?.sso?.provider === 'keycloak') {
      sessions = await authService.getActiveSessions(effectiveUserId, currentRt, { source: 'auto' });
    } else {
      sessions = await authService.getActiveSessions(effectiveUserId, currentRt, { source: 'jwt' });
    }

    if (sessions.length && req.sessionID) {
      const index = sessions.findIndex(s => s.source === 'keycloak' && !s.isCurrent);
      if (index >= 0) {
        sessions[index].isCurrent = true;
      }
    }

    return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { sessions });
  } catch (error) {
    console.error('Error fetching sessions:', error);
    return response.error(res, req.t(MESSAGES.GENERAL.ERROR), 500);
  }
});

const revokeSession = asyncHandler(async (req, res) => {
  await authService.revokeSession(req.user._id, req.params.tokenId);
  return response.success(res, req.t(MESSAGES.AUTH.SESSION_REVOKED));
});

module.exports = {
  register,
  login,
  verifyTfa,
  refreshToken,
  logout,
  logoutAll,
  getMe,
  updateProfile,
  changePassword,
  getActiveSessions,
  revokeSession
};
