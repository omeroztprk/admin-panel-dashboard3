const auditService = require('../services/auditService');
const tokenService = require('../services/tokenService');
const userService = require('../services/userService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { getClientIP, sanitizeObject, toInt, escapeRegex, isValidObjectId, toBool } = require('../utils/helpers');

const getUsers = asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 10,
    sort = '-createdAt',
    search,
    role,
    isActive,
    startDate,
    endDate
  } = req.query;

  const sanitizedQuery = {
    page: Math.max(1, toInt(page, 1)),
    limit: Math.min(100, Math.max(1, toInt(limit, 10))),
    sort: sort || '-createdAt'
  };

  const filters = {};
  if (typeof search === 'string' && search.trim()) {
    const re = new RegExp(escapeRegex(search.trim()), 'i');
    filters.$or = [
      { firstName: { $regex: re } },
      { lastName: { $regex: re } },
      { email: { $regex: re } }
    ];
  }

  if (role && isValidObjectId(role)) {
    filters.roles = role;
  }

  if (isActive !== undefined) {
    filters.isActive = toBool(isActive, undefined);
  }

  if (startDate || endDate) {
    const createdAt = {};
    if (startDate) {
      const d = new Date(startDate);
      if (!Number.isNaN(d.getTime())) createdAt.$gte = d;
    }
    if (endDate) {
      const d = new Date(endDate);
      if (!Number.isNaN(d.getTime())) createdAt.$lte = d;
    }
    if (Object.keys(createdAt).length) filters.createdAt = createdAt;
  }

  const result = await userService.getUsers(filters, sanitizedQuery);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const getUserById = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const user = await userService.getUserById(id);
  if (!user) return response.notFound(res, req.t(ERRORS.USER.NOT_FOUND));
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { user });
});

const createUser = asyncHandler(async (req, res) => {
  const userData = {
    ...req.body,
    metadata: {
      createdBy: req.user._id,
      ipAddress: getClientIP(req),
      userAgent: req.get('User-Agent') || 'Unknown'
    }
  };

  const user = await userService.createUser(userData);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'create',
    resource: 'user',
    resourceId: user._id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 201,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { after: sanitizeObject(userData, ['password', '__v', 'metadata.userAgent']) },
    severity: 'medium'
  });

  const sanitizedUser = sanitizeObject(user.toObject(), ['password', '__v']);
  return response.created(res, req.t(MESSAGES.USER.CREATED), { user: sanitizedUser });
});

const updateUser = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const updates = {
    ...req.body,
    metadata: {
      ...(req.body?.metadata || {}),
      updatedBy: req.user._id,
      updatedAt: new Date()
    }
  };

  if (updates.metadata) delete updates.metadata.createdBy;
  delete updates.password;
  delete updates._id;
  delete updates.__v;

  const originalUser = await userService.getUserById(id);
  if (!originalUser) return response.notFound(res, req.t(ERRORS.USER.NOT_FOUND));

  const user = await userService.updateUser(id, updates);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'update',
    resource: 'user',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: {
      before: sanitizeObject(originalUser.toObject(), ['password', '__v']),
      after: sanitizeObject(updates, ['password', '__v'])
    },
    severity: 'medium'
  });

  const sanitizedUser = sanitizeObject(user.toObject(), ['password', '__v']);
  return response.success(res, req.t(MESSAGES.USER.UPDATED), { user: sanitizedUser });
});

const deleteUser = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const user = await userService.getUserById(id);
  if (!user) return response.notFound(res, req.t(ERRORS.USER.NOT_FOUND));

  await userService.deleteUser(id);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'delete',
    resource: 'user',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: sanitizeObject(user.toObject(), ['password', '__v']) },
    severity: 'high'
  });

  return response.success(res, req.t(MESSAGES.USER.DELETED));
});

const toggleUserStatus = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { isActive } = req.body;

  if (typeof isActive !== 'boolean') {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const originalUser = await userService.getUserById(id);
  if (!originalUser) return response.notFound(res, req.t(ERRORS.USER.NOT_FOUND));

  const user = await userService.toggleUserStatus(id, isActive, req.user._id);

  await auditService.logUserAction({
    user: req.user._id,
    action: isActive ? 'activate' : 'deactivate',
    resource: 'user',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: { isActive: originalUser.isActive }, after: { isActive } },
    severity: 'medium'
  });

  const sanitizedUser = sanitizeObject(user.toObject(), ['password', '__v']);
  return response.success(res, req.t(MESSAGES.USER.STATUS_UPDATED), { user: sanitizedUser });
});

const assignRoles = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { roles } = req.body;

  if (!Array.isArray(roles) || roles.length === 0) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const originalUser = await userService.getUserById(id);
  if (!originalUser) return response.notFound(res, req.t(ERRORS.USER.NOT_FOUND));

  const user = await userService.assignRoles(id, roles);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'assign_roles',
    resource: 'user',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: { roles: originalUser.roles }, after: { roles } },
    severity: 'high'
  });

  const sanitizedUser = sanitizeObject(user.toObject(), ['password', '__v']);
  return response.success(res, req.t(MESSAGES.USER.ROLES_ASSIGNED), { user: sanitizedUser });
});

const assignPermissions = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { permissions } = req.body;

  if (!Array.isArray(permissions) || permissions.length === 0) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const originalUser = await userService.getUserById(id);
  if (!originalUser) return response.notFound(res, req.t(ERRORS.USER.NOT_FOUND));

  const user = await userService.assignPermissions(id, permissions);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'assign_permissions',
    resource: 'user',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: { permissions: originalUser.permissions }, after: { permissions } },
    severity: 'high'
  });

  const sanitizedUser = sanitizeObject(user.toObject(), ['password', '__v']);
  return response.success(res, req.t(MESSAGES.USER.PERMISSIONS_ASSIGNED), { user: sanitizedUser });
});

const getUserPermissions = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const permissions = await userService.getUserPermissions(id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { permissions });
});

const resetPassword = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;

  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    return response.error(res, req.t(ERRORS.VALIDATION.PASSWORD_MIN_LENGTH), 400);
  }

  await userService.resetPassword(id, newPassword);
  await tokenService.blacklistAllUserTokens(id);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'reset_password',
    resource: 'user',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    severity: 'high'
  });

  return response.success(res, req.t(MESSAGES.USER.PASSWORD_RESET));
});

const unlockUser = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const found = await userService.getUserById(id);
  if (!found) return response.notFound(res, req.t(ERRORS.USER.NOT_FOUND));

  const { wasLocked, unlocked } = await userService.unlockUser(id);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'unlock',
    resource: 'user',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: unlocked
      ? { before: { isLocked: true }, after: { isLocked: false } }
      : { before: { isLocked: false }, after: { isLocked: false }, noop: true },
    severity: unlocked ? 'medium' : 'low'
  });

  const msgKey = unlocked ? MESSAGES.USER.UNLOCKED : MESSAGES.USER.ALREADY_UNLOCKED;
  return response.success(res, req.t(msgKey), { wasLocked, unlocked });
});

module.exports = {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  deleteUser,
  toggleUserStatus,
  assignRoles,
  assignPermissions,
  getUserPermissions,
  resetPassword,
  unlockUser
};
