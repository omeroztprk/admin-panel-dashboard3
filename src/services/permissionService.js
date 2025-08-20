const Permission = require('../models/Permission');
const Role = require('../models/Role');
const User = require('../models/User');
const { ERRORS } = require('../utils/constants');

const getAvailableResources = async () => {
  const resources = await Permission.distinct('resource', { isActive: true });
  return resources.sort();
};

const getAvailableActions = async () => {
  const actions = await Permission.distinct('action', { isActive: true });
  return actions.sort();
};

const getPermissionCategories = async () => {
  const categories = await Permission.distinct('category', { isActive: true });
  return categories.sort();
};

const getPermissionsByResource = async (resource) => {
  return Permission.find({ resource, isActive: true }).sort('action');
};

const getPermissions = async (filters = {}, options = {}) => {
  const { page = 1, limit = 50, sort = 'resource' } = options;
  const skip = (page - 1) * limit;

  const permissions = await Permission.find(filters)
    .populate('metadata.createdBy', 'firstName lastName')
    .populate('metadata.updatedBy', 'firstName lastName')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await Permission.countDocuments(filters);

  return {
    permissions,
    pagination: {
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      totalItems: total,
      itemsPerPage: limit,
      hasNextPage: page < Math.ceil(total / limit),
      hasPrevPage: page > 1
    }
  };
};

const getPermissionById = async (permissionId) => {
  const permission = await Permission.findById(permissionId)
    .populate('metadata.createdBy', 'firstName lastName')
    .populate('metadata.updatedBy', 'firstName lastName');

  if (!permission) {
    throw new Error(ERRORS.PERMISSION.NOT_FOUND);
  }

  return permission;
};

const createPermission = async (permissionData) => {
  const { name, resource, action, ...otherData } = permissionData;

  const permissionName = (typeof name === 'string' && name.trim())
    ? name.trim()
    : `${resource}:${action}`;

  const existingPermission = await Permission.findOne({ name: permissionName });
  if (existingPermission) {
    throw new Error(ERRORS.PERMISSION.NAME_EXISTS);
  }

  const permission = new Permission({
    ...otherData,
    name: permissionName,
    resource,
    action
  });

  await permission.save();
  return getPermissionById(permission._id);
};

const updatePermission = async (permissionId, updates) => {
  const existingPermission = await Permission.findById(permissionId);
  if (!existingPermission) {
    throw new Error(ERRORS.PERMISSION.NOT_FOUND);
  }

  if (existingPermission.isSystem) {
    throw new Error(ERRORS.PERMISSION.SYSTEM_PERMISSION_MODIFICATION);
  }

  if (updates.resource || updates.action || updates.name) {
    const nextResource = updates.resource || existingPermission.resource;
    const nextAction = updates.action || existingPermission.action;
    const nextName = (typeof updates.name === 'string' && updates.name.trim())
      ? updates.name.trim()
      : `${nextResource}:${nextAction}`;

    const nameExists = await Permission.findOne({ 
      name: nextName, 
      _id: { $ne: permissionId } 
    });
    if (nameExists) {
      throw new Error(ERRORS.PERMISSION.NAME_EXISTS);
    }

    updates.name = nextName;
  }

  const finalUpdates = {
    ...updates,
    metadata: {
      ...existingPermission.metadata,
      ...updates.metadata,
      updatedAt: new Date()
    }
  };

  await Permission.findByIdAndUpdate(permissionId, finalUpdates, { 
    new: true, 
    runValidators: true 
  });

  return getPermissionById(permissionId);
};

const deletePermission = async (permissionId) => {
  const permission = await Permission.findById(permissionId);
  if (!permission) {
    throw new Error(ERRORS.PERMISSION.NOT_FOUND);
  }

  if (permission.isSystem) {
    throw new Error(ERRORS.PERMISSION.SYSTEM_PERMISSION_DELETE);
  }

  const roleCount = await Role.countDocuments({ permissions: permissionId });
  if (roleCount > 0) {
    throw new Error(ERRORS.PERMISSION.ASSIGNED_TO_ROLES);
  }

  const userCount = await User.countDocuments({ 'permissions.permission': permissionId });
  if (userCount > 0) {
    throw new Error(ERRORS.PERMISSION.ASSIGNED_TO_USERS);
  }

  await Permission.findByIdAndDelete(permissionId);
  return true;
};

const togglePermissionStatus = async (permissionId, isActive, actorId) => {
  const permission = await Permission.findById(permissionId);
  if (!permission) {
    throw new Error(ERRORS.PERMISSION.NOT_FOUND);
  }

  if (permission.isSystem) {
    throw new Error(ERRORS.PERMISSION.SYSTEM_PERMISSION_MODIFICATION);
  }

  const updates = {
    isActive: !!isActive,
    metadata: {
      ...permission.metadata,
      updatedBy: actorId,
      updatedAt: new Date()
    }
  };

  await Permission.findByIdAndUpdate(permissionId, updates, { 
    new: true, 
    runValidators: true 
  });

  return getPermissionById(permissionId);
};

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
