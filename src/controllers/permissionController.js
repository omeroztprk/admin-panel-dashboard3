const permissionService = require('../services/permissionService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { sanitizeObject, toInt, escapeRegex, toBool } = require('../utils/helpers');

const getAvailableResources = asyncHandler(async (req, res) => {
  const resources = await permissionService.getAvailableResources();
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { resources });
});

const getAvailableActions = asyncHandler(async (req, res) => {
  const actions = await permissionService.getAvailableActions();
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { actions });
});

const getPermissionCategories = asyncHandler(async (req, res) => {
  const categories = await permissionService.getPermissionCategories();
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { categories });
});

const getPermissionsByResource = asyncHandler(async (req, res) => {
  const permissions = await permissionService.getPermissionsByResource(req.params.resource);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { permissions });
});

const getPermissions = asyncHandler(async (req, res) => {
  const filters = {};
  const options = {
    page: Math.max(1, toInt(req.query.page, 1)),
    limit: Math.min(100, Math.max(1, toInt(req.query.limit, 50))),
    sort: req.query.sort || 'resource'
  };

  if (req.query.search?.trim()) {
    const re = new RegExp(escapeRegex(req.query.search.trim()), 'i');
    filters.$or = [
      { name: { $regex: re } },
      { displayName: { $regex: re } },
      { description: { $regex: re } }
    ];
  }
  if (req.query.resource) filters.resource = req.query.resource;
  if (req.query.action) filters.action = req.query.action;
  if (req.query.category) filters.category = req.query.category;
  if (req.query.isActive !== undefined) filters.isActive = toBool(req.query.isActive);

  const result = await permissionService.getPermissions(filters, options);
  const permissions = (result.permissions || []).map(sanitizeObject);
  return response.paginated(res, req.t(MESSAGES.GENERAL.SUCCESS), { permissions }, result.pagination);
});

const getPermissionById = asyncHandler(async (req, res) => {
  const permission = await permissionService.getPermissionById(req.params.id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { permission: sanitizeObject(permission) });
});

const createPermission = asyncHandler(async (req, res) => {
  const permissionData = {
    ...req.body,
    metadata: { createdBy: req.user._id }
  };

  const permission = await permissionService.createPermission(permissionData);
  return response.created(res, req.t(MESSAGES.PERMISSION.CREATED), { permission: sanitizeObject(permission) });
});

const updatePermission = asyncHandler(async (req, res) => {
  const updates = {
    ...req.body,
    metadata: { updatedBy: req.user._id }
  };

  const permission = await permissionService.updatePermission(req.params.id, updates);
  return response.success(res, req.t(MESSAGES.PERMISSION.UPDATED), { permission: sanitizeObject(permission) });
});

const deletePermission = asyncHandler(async (req, res) => {
  await permissionService.deletePermission(req.params.id);
  return response.success(res, req.t(MESSAGES.PERMISSION.DELETED));
});

const togglePermissionStatus = asyncHandler(async (req, res) => {
  const permission = await permissionService.togglePermissionStatus(req.params.id, req.body.isActive, req.user._id);
  return response.success(res, req.t(MESSAGES.PERMISSION.STATUS_UPDATED), { permission: sanitizeObject(permission) });
});

module.exports = {
  getAvailableResources,
  getAvailableActions,
  getPermissionCategories,
  getPermissionsByResource,
  getPermissions,
  getPermissionById,
  createPermission,
  updatePermission,
  deletePermission,
  togglePermissionStatus
};
