const auditService = require('../services/auditService');
const permissionService = require('../services/permissionService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { getClientIP, sanitizeObject, toInt, escapeRegex, toBool } = require('../utils/helpers');

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
  const { resource } = req.params;
  if (!resource || typeof resource !== 'string') {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }
  const permissions = await permissionService.getPermissionsByResource(resource);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { permissions });
});

const getPermissions = asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 50,
    sort = 'resource',
    search,
    resource,
    action,
    category,
    isActive
  } = req.query;

  const sanitizedQuery = {
    page: Math.max(1, toInt(page, 1)),
    limit: Math.min(100, Math.max(1, toInt(limit, 50))),
    sort: sort || 'resource'
  };

  const filters = {};
  if (typeof search === 'string' && search.trim()) {
    const re = new RegExp(escapeRegex(search.trim()), 'i');
    filters.$or = [
      { name: { $regex: re } },
      { displayName: { $regex: re } },
      { description: { $regex: re } }
    ];
  }
  if (typeof resource === 'string' && resource) filters.resource = resource;
  if (typeof action === 'string' && action) filters.action = action;
  if (typeof category === 'string' && category) filters.category = category;
  if (isActive !== undefined) filters.isActive = toBool(isActive, undefined);

  const result = await permissionService.getPermissions(filters, sanitizedQuery);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const getPermissionById = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const permission = await permissionService.getPermissionById(id);
  if (!permission) return response.notFound(res, req.t(ERRORS.PERMISSION.NOT_FOUND));
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { permission });
});

const createPermission = asyncHandler(async (req, res) => {
  const { name, resource, action } = req.body || {};
  if (!(typeof name === 'string' && name.trim()) && !(resource && action)) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const permissionData = {
    ...req.body,
    metadata: {
      createdBy: req.user._id,
      ipAddress: getClientIP(req),
      userAgent: req.get('User-Agent') || 'Unknown'
    }
  };

  const permission = await permissionService.createPermission(permissionData);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'create',
    resource: 'permission',
    resourceId: permission._id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 201,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { after: sanitizeObject(permissionData, ['metadata.userAgent', 'metadata.ipAddress']) },
    severity: 'high'
  });

  const sanitizedPermission = sanitizeObject(permission.toObject(), ['__v']);
  return response.created(res, req.t(MESSAGES.PERMISSION.CREATED), { permission: sanitizedPermission });
});

const updatePermission = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const updates = {
    ...req.body,
    metadata: {
      updatedBy: req.user._id,
      updatedAt: new Date(),
      ipAddress: getClientIP(req),
      userAgent: req.get('User-Agent') || 'Unknown'
    }
  };

  delete updates._id;
  delete updates.__v;

  const originalPermission = await permissionService.getPermissionById(id);
  if (!originalPermission) {
    return response.notFound(res, req.t(ERRORS.PERMISSION.NOT_FOUND));
  }

  const permission = await permissionService.updatePermission(id, updates);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'update',
    resource: 'permission',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: {
      before: sanitizeObject(originalPermission.toObject(), ['__v']),
      after: sanitizeObject(updates, ['metadata.userAgent', 'metadata.ipAddress'])
    },
    severity: 'high'
  });

  const sanitizedPermission = sanitizeObject(permission.toObject(), ['__v']);
  return response.success(res, req.t(MESSAGES.PERMISSION.UPDATED), { permission: sanitizedPermission });
});

const deletePermission = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const permission = await permissionService.getPermissionById(id);
  if (!permission) {
    return response.notFound(res, req.t(ERRORS.PERMISSION.NOT_FOUND));
  }

  await permissionService.deletePermission(id);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'delete',
    resource: 'permission',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: sanitizeObject(permission.toObject(), ['__v']) },
    severity: 'high'
  });

  return response.success(res, req.t(MESSAGES.PERMISSION.DELETED));
});

const togglePermissionStatus = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { isActive } = req.body;

  if (typeof isActive !== 'boolean') {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const original = await permissionService.getPermissionById(id);
  if (!original) {
    return response.notFound(res, req.t(ERRORS.PERMISSION.NOT_FOUND));
  }

  const permission = await permissionService.togglePermissionStatus(id, isActive, { updatedBy: req.user._id });

  await auditService.logUserAction({
    user: req.user._id,
    action: isActive ? 'activate' : 'deactivate',
    resource: 'permission',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: { isActive: original.isActive }, after: { isActive } },
    severity: 'medium'
  });

  const sanitizedPermission = sanitizeObject(permission.toObject(), ['__v']);
  return response.success(res, req.t(MESSAGES.PERMISSION.STATUS_UPDATED), { permission: sanitizedPermission });
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
