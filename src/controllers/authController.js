const auditService = require('../services/auditService');
const authService = require('../services/authService');
const tokenService = require('../services/tokenService');
const response = require('../utils/response');
const { applyLangHeaders } = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { getClientIP, sleep } = require('../utils/helpers');
const config = require('../config');
const { detectLanguage, resolveLanguage } = require('../config/i18n');

const register = asyncHandler(async (req, res) => {
  const { firstName, lastName, email, password, profile } = req.body || {};
  const requestedLng =
    profile?.language ||
    req.query?.lng ||
    req.headers['accept-language'] ||
    config.i18n.defaultLanguage;
  const selectedLng = resolveLanguage(requestedLng);

  let result;
  try {
    result = await authService.register({
      firstName,
      lastName,
      email,
      password,
      profile: { ...(profile || {}), language: selectedLng },
      ipAddress: getClientIP(req),
      userAgent: req.get('User-Agent') || 'Unknown'
    });
  } catch (err) {
    if (err?.message === ERRORS.AUTH.EMAIL_EXISTS || err?.code === 11000) {
      return response.error(res, req.t(ERRORS.AUTH.EMAIL_EXISTS), 409);
    }
    throw err;
  }

  await auditService.logUserAction({
    user: result.user._id,
    action: 'register',
    resource: 'user',
    resourceId: result.user._id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 201,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    severity: 'medium'
  });

  res.set('Content-Language', selectedLng);

  return response.created(
    res,
    req.t(MESSAGES.AUTH.REGISTER_SUCCESS, { lng: selectedLng }),
    {
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    }
  );
});

const login = asyncHandler(async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body.password;
  const clientIP = getClientIP(req);

  try {
    const result = await authService.login({
      email,
      password,
      ipAddress: clientIP,
      userAgent: req.get('User-Agent') || 'Unknown'
    });

    await auditService.logUserAction({
      user: result.user._id,
      action: 'login',
      resource: 'auth',
      method: req.method,
      endpoint: req.originalUrl,
      statusCode: 200,
      ipAddress: clientIP,
      userAgent: req.get('User-Agent') || 'Unknown',
      severity: 'medium'
    });

    const lng = resolveLanguage(
      result.user?.profile?.language || detectLanguage(req, result.user)
    );
    res.set('Content-Language', lng);

    return response.success(res, req.t(MESSAGES.AUTH.LOGIN_SUCCESS, { lng }), {
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    });
  } catch (error) {
    const errKey = error?.message;

    await auditService.logUserAction({
      user: null,
      action: 'login_failed',
      resource: 'auth',
      method: req.method,
      endpoint: req.originalUrl,
      statusCode: 401,
      ipAddress: clientIP,
      userAgent: req.get('User-Agent') || 'Unknown',
      errorMessage: `Failed login attempt for ${email}`,
      severity: 'medium'
    });

    await sleep(100 + Math.floor(Math.random() * 200));

    if (errKey === ERRORS.AUTH.ACCOUNT_LOCKED || error?.code === 'ACCOUNT_LOCKED') {
      const seconds = Number.isFinite(error?.retryAfterSec)
        ? error.retryAfterSec
        : Math.ceil((config.security.lockout.lockoutTime || 60000) / 1000);

      res.set('Retry-After', String(seconds));

      const minute = Math.floor(seconds / 60);
      const remain = seconds % 60;

      const msg = req.t(ERRORS.AUTH.ACCOUNT_LOCKED_DYNAMIC, { minute, seconds: remain });

      applyLangHeaders(res);

      const body = {
        status: 'error',
        message: msg,
        timestamp: new Date().toISOString()
      };
      if (error?.lockoutUntil) body.unlockAt = new Date(error.lockoutUntil).toISOString();

      return res.status(423).json(body);
    }

    switch (errKey) {
      case ERRORS.AUTH.INVALID_CREDENTIALS:
        return response.error(res, req.t(ERRORS.AUTH.INVALID_CREDENTIALS), 401);
      case ERRORS.AUTH.ACCOUNT_INACTIVE:
        return response.error(res, req.t(ERRORS.AUTH.ACCOUNT_INACTIVE), 403);
      default:
        throw error;
    }
  }
});

const refreshToken = asyncHandler(async (req, res) => {
  const result = await tokenService.refreshAccessToken(
    req.refreshTokenDoc,
    req.refreshTokenPlain
  );

  await auditService.logUserAction({
    user: req.user._id,
    action: 'refresh_token',
    resource: 'auth',
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    severity: 'low'
  });

  return response.success(res, req.t(MESSAGES.AUTH.TOKEN_REFRESHED), {
    accessToken: result.accessToken,
    refreshToken: result.refreshToken
  });
});

const logout = asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  await authService.logout(req.user._id, refreshToken);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'logout',
    resource: 'auth',
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    severity: 'low'
  });

  return response.success(res, req.t(MESSAGES.AUTH.LOGOUT_SUCCESS));
});

const logoutAll = asyncHandler(async (req, res) => {
  await authService.logoutAll(req.user._id);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'logout_all',
    resource: 'auth',
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    severity: 'medium'
  });

  return response.success(res, req.t(MESSAGES.AUTH.LOGOUT_ALL_SUCCESS));
});

const getMe = asyncHandler(async (req, res) => {
  const user = await authService.getMe(req.user._id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { user });
});

const updateProfile = asyncHandler(async (req, res) => {
  const allowedFields = ['firstName', 'lastName', 'profile'];
  const updates = {};
  allowedFields.forEach((field) => {
    if (req.body[field] !== undefined) updates[field] = req.body[field];
  });

  if (updates.profile?.language) {
    updates.profile.language = resolveLanguage(updates.profile.language);
  }

  const user = await authService.updateProfile(req.user._id, updates);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'update_profile',
    resource: 'user',
    resourceId: req.user._id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { after: updates },
    severity: 'low'
  });

  const lng = resolveLanguage(user?.profile?.language || detectLanguage(req, user));
  res.set('Content-Language', lng);

  return response.success(res, req.t(MESSAGES.AUTH.PROFILE_UPDATED, { lng }), { user });
});

const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return response.error(res, req.t(ERRORS.VALIDATION.REQUIRED_FIELDS), 400);
  }

  await authService.changePassword(req.user._id, currentPassword, newPassword);
  await authService.logoutAll(req.user._id);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'change_password',
    resource: 'user',
    resourceId: req.user._id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    severity: 'high'
  });

  return response.success(res, req.t(MESSAGES.AUTH.PASSWORD_CHANGED));
});

const getActiveSessions = asyncHandler(async (req, res) => {
  const sessions = await authService.getActiveSessions(req.user._id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { sessions });
});

const revokeSession = asyncHandler(async (req, res) => {
  const { tokenId } = req.params;

  await authService.revokeSession(req.user._id, tokenId);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'revoke_session',
    resource: 'auth',
    resourceId: tokenId,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    severity: 'medium'
  });

  return response.success(res, req.t(MESSAGES.AUTH.SESSION_REVOKED));
});

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  logoutAll,
  getMe,
  updateProfile,
  changePassword,
  getActiveSessions,
  revokeSession
};
