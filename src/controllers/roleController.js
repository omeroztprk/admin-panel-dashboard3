const roleService = require('../services/roleService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { sanitizeObject, toInt, escapeRegex, isValidObjectId, toBool } = require('../utils/helpers');

const getRoles = asyncHandler(async (req, res) => {
  const filters = {};
  const options = {
    page: Math.max(1, toInt(req.query.page, 1)),
    limit: Math.min(100, Math.max(1, toInt(req.query.limit, 10))),
    sort: req.query.sort || 'priority',
    includePermissions: toBool(req.query.includePermissions, true)
  };

  if (req.query.search?.trim()) {
    const re = new RegExp(escapeRegex(req.query.search.trim()), 'i');
    filters.$or = [{ name: { $regex: re } }, { displayName: { $regex: re } }];
  }
  if (req.query.isActive !== undefined) filters.isActive = toBool(req.query.isActive);

  const result = await roleService.getRoles(filters, options);
  const roles = (result.roles || []).map(sanitizeObject);
  return response.paginated(res, req.t(MESSAGES.GENERAL.SUCCESS), { roles }, result.pagination);
});

const getRoleById = asyncHandler(async (req, res) => {
  const includePermissions = toBool(req.query.includePermissions, true);
  const role = await roleService.getRoleById(req.params.id, includePermissions);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { role: sanitizeObject(role) });
});

const createRole = asyncHandler(async (req, res) => {
  const roleData = {
    ...req.body,
    metadata: { createdBy: req.user._id }
  };

  const role = await roleService.createRole(roleData);
  return response.created(res, req.t(MESSAGES.ROLE.CREATED), { role: sanitizeObject(role) });
});

const updateRole = asyncHandler(async (req, res) => {
  const updates = {
    ...req.body,
    metadata: { updatedBy: req.user._id }
  };

  const role = await roleService.updateRole(req.params.id, updates);
  return response.success(res, req.t(MESSAGES.ROLE.UPDATED), { role: sanitizeObject(role) });
});

const deleteRole = asyncHandler(async (req, res) => {
  await roleService.deleteRole(req.params.id);
  return response.success(res, req.t(MESSAGES.ROLE.DELETED));
});

const toggleRoleStatus = asyncHandler(async (req, res) => {
  const role = await roleService.toggleRoleStatus(req.params.id, req.body.isActive, req.user._id);
  return response.success(res, req.t(MESSAGES.ROLE.STATUS_UPDATED), { role: sanitizeObject(role) });
});

const assignPermissions = asyncHandler(async (req, res) => {
  const role = await roleService.assignPermissions(req.params.id, req.body.permissions);
  return response.success(res, req.t(MESSAGES.ROLE.PERMISSIONS_ASSIGNED), { role: sanitizeObject(role) });
});

const removePermissions = asyncHandler(async (req, res) => {
  const role = await roleService.removePermissions(req.params.id, req.body.permissions);
  return response.success(res, req.t(MESSAGES.ROLE.PERMISSIONS_REMOVED), { role: sanitizeObject(role) });
});

const getRoleUsers = asyncHandler(async (req, res) => {
  const options = {
    page: Math.max(1, toInt(req.query.page, 1)),
    limit: Math.min(100, Math.max(1, toInt(req.query.limit, 10))),
    sort: req.query.sort || '-createdAt'
  };

  const result = await roleService.getRoleUsers(req.params.id, options);
  const users = (result.users || []).map(sanitizeObject);
  return response.paginated(res, req.t(MESSAGES.GENERAL.SUCCESS), { users }, result.pagination);
});

module.exports = {
  getRoles,
  getRoleById,
  createRole,
  updateRole,
  deleteRole,
  toggleRoleStatus,
  assignPermissions,
  removePermissions,
  getRoleUsers
};
