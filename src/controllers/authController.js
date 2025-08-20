const authService = require('../services/authService');
const tokenService = require('../services/tokenService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { MESSAGES } = require('../utils/constants');
const { getClientIP, sanitizeObject, maskEmail } = require('../utils/helpers');
const { resolveLanguage } = require('../config/i18n');

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
  await authService.logoutAll(req.user._id);
  return response.success(res, req.t(MESSAGES.AUTH.LOGOUT_ALL_SUCCESS));
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
  const sessions = await authService.getActiveSessions(req.user._id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { sessions });
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
