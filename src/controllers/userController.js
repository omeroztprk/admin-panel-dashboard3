const userService = require('../services/userService');
const tokenService = require('../services/tokenService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { sanitizeObject, toInt, escapeRegex, isValidObjectId, toBool } = require('../utils/helpers');

const getUsers = asyncHandler(async (req, res) => {
  const filters = {};
  const options = {
    page: Math.max(1, toInt(req.query.page, 1)),
    limit: Math.min(100, Math.max(1, toInt(req.query.limit, 10))),
    sort: req.query.sort || '-createdAt'
  };

  if (req.query.search?.trim()) {
    const re = new RegExp(escapeRegex(req.query.search.trim()), 'i');
    filters.$or = [
      { firstName: { $regex: re } },
      { lastName: { $regex: re } },
      { email: { $regex: re } }
    ];
  }
  if (req.query.role && isValidObjectId(req.query.role)) filters.roles = req.query.role;
  if (req.query.isActive !== undefined) filters.isActive = toBool(req.query.isActive);
  if (req.query.startDate || req.query.endDate) {
    const createdAt = {};
    if (req.query.startDate) createdAt.$gte = new Date(req.query.startDate);
    if (req.query.endDate) createdAt.$lte = new Date(req.query.endDate);
    if (Object.keys(createdAt).length) filters.createdAt = createdAt;
  }

  const result = await userService.getUsers(filters, options);
  const users = (result.users || []).map(sanitizeObject);

  return response.paginated(res, req.t(MESSAGES.GENERAL.SUCCESS), { users }, result.pagination);
});

const getUserById = asyncHandler(async (req, res) => {
  const user = await userService.getUserById(req.params.id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { user: sanitizeObject(user) });
});

const createUser = asyncHandler(async (req, res) => {
  const userData = {
    ...req.body,
    metadata: { createdBy: req.user._id }
  };

  const user = await userService.createUser(userData);
  return response.created(res, req.t(MESSAGES.USER.CREATED), { user: sanitizeObject(user) });
});

const updateUser = asyncHandler(async (req, res) => {
  const result = await userService.updateUser(req.params.id, req.body);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const deleteUser = asyncHandler(async (req, res) => {
  await userService.deleteUser(req.params.id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { deleted: true });
});

const toggleUserStatus = asyncHandler(async (req, res) => {
  const result = await userService.toggleUserStatus(req.params.id, req.body.isActive, req.user?._id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const assignRoles = asyncHandler(async (req, res) => {
  const result = await userService.assignRoles(req.params.id, req.body.roles || [], req.user?._id);
  return response.success(res, result);
});

const assignPermissions = asyncHandler(async (req, res) => {
  const user = await userService.assignPermissions(req.params.id, req.body.permissions, req.user._id);
  return response.success(res, req.t(MESSAGES.USER.PERMISSIONS_ASSIGNED), { user: sanitizeObject(user) });
});

const getUserPermissions = asyncHandler(async (req, res) => {
  const permissions = await userService.getUserPermissions(req.params.id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { permissions });
});

const resetPassword = asyncHandler(async (req, res) => {
  await userService.resetPassword(req.params.id, req.body.newPassword);
  await tokenService.blacklistAllUserTokens(req.params.id);
  return response.success(res, req.t(MESSAGES.USER.PASSWORD_RESET));
});

const unlockUser = asyncHandler(async (req, res) => {
  const result = await userService.unlockUser(req.params.id);
  const messageKey = result.unlocked ? MESSAGES.USER.UNLOCKED : MESSAGES.USER.ALREADY_UNLOCKED;
  return response.success(res, req.t(messageKey), result);
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
