const auditService = require('../services/auditService');
const roleService = require('../services/roleService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { getClientIP, toInt, sanitizeObject, escapeRegex, toBool } = require('../utils/helpers');

const getRoles = asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 10,
    sort = 'priority',
    search,
    isActive,
    includePermissions = true
  } = req.query;

  const filters = {};
  if (typeof search === 'string' && search.trim()) {
    const re = new RegExp(escapeRegex(search.trim()), 'i');
    filters.$or = [
      { name: { $regex: re } },
      { displayName: { $regex: re } }
    ];
  }
  if (isActive !== undefined) filters.isActive = toBool(isActive, undefined);

  const result = await roleService.getRoles(filters, {
    page: toInt(page, 1),
    limit: toInt(limit, 10),
    sort: sort || 'priority',
    includePermissions: toBool(includePermissions, true)
  });

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const getRoleById = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { includePermissions = true } = req.query;

  const role = await roleService.getRoleById(id, toBool(includePermissions, true));
  if (!role) return response.notFound(res, req.t(ERRORS.ROLE.NOT_FOUND));

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { role });
});

const createRole = asyncHandler(async (req, res) => {
  const roleData = {
    ...req.body,
    metadata: {
      createdBy: req.user._id,
      ipAddress: getClientIP(req),
      userAgent: req.get('User-Agent') || 'Unknown'
    }
  };

  const role = await roleService.createRole(roleData);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'create',
    resource: 'role',
    resourceId: role._id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 201,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { after: sanitizeObject(roleData, ['metadata.userAgent', 'metadata.ipAddress']) },
    severity: 'high'
  });

  return response.created(res, req.t(MESSAGES.ROLE.CREATED), { role });
});

const updateRole = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const updates = {
    ...req.body,
    metadata: {
      ...(req.body?.metadata || {}),
      updatedBy: req.user._id,
      updatedAt: new Date(),
      ipAddress: getClientIP(req),
      userAgent: req.get('User-Agent') || 'Unknown'
    }
  };
  delete updates._id;
  delete updates.__v;
  if (updates.metadata) delete updates.metadata.createdBy;

  const originalRole = await roleService.getRoleById(id, false);
  if (!originalRole) return response.notFound(res, req.t(ERRORS.ROLE.NOT_FOUND));

  const role = await roleService.updateRole(id, updates);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'update',
    resource: 'role',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: {
      before: sanitizeObject(originalRole.toObject(), ['__v']),
      after: sanitizeObject(updates, ['metadata.userAgent', 'metadata.ipAddress'])
    },
    severity: 'high'
  });

  return response.success(res, req.t(MESSAGES.ROLE.UPDATED), { role });
});

const deleteRole = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const role = await roleService.getRoleById(id, false);
  if (!role) return response.notFound(res, req.t(ERRORS.ROLE.NOT_FOUND));

  await roleService.deleteRole(id);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'delete',
    resource: 'role',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: sanitizeObject(role.toObject(), ['__v']) },
    severity: 'high'
  });

  return response.success(res, req.t(MESSAGES.ROLE.DELETED));
});

const toggleRoleStatus = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { isActive } = req.body;
  if (typeof isActive !== 'boolean') {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const original = await roleService.getRoleById(id, false);
  if (!original) return response.notFound(res, req.t(ERRORS.ROLE.NOT_FOUND));

  const role = await roleService.toggleRoleStatus(id, isActive, { updatedBy: req.user._id });

  await auditService.logUserAction({
    user: req.user._id,
    action: isActive ? 'activate' : 'deactivate',
    resource: 'role',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: { isActive: original.isActive }, after: { isActive } },
    severity: 'medium'
  });

  return response.success(res, req.t(MESSAGES.ROLE.STATUS_UPDATED), { role });
});

const assignPermissions = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { permissions } = req.body;

  if (!Array.isArray(permissions) || permissions.length === 0) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const role = await roleService.assignPermissions(id, permissions);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'assign_permissions',
    resource: 'role',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { after: { permissions } },
    severity: 'high'
  });

  return response.success(res, req.t(MESSAGES.ROLE.PERMISSIONS_ASSIGNED), { role });
});

const removePermissions = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { permissions } = req.body;

  if (!Array.isArray(permissions) || permissions.length === 0) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const role = await roleService.removePermissions(id, permissions);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'remove_permissions',
    resource: 'role',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { after: { removedPermissions: permissions } },
    severity: 'high'
  });

  return response.success(res, req.t(MESSAGES.ROLE.PERMISSIONS_REMOVED), { role });
});

const getRoleUsers = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { page = 1, limit = 10, sort = '-createdAt' } = req.query;

  const result = await roleService.getRoleUsers(id, {
    page: toInt(page, 1),
    limit: toInt(limit, 10),
    sort: sort || '-createdAt'
  });

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
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
