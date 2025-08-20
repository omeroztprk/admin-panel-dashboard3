const Role = require('../models/Role');
const Permission = require('../models/Permission');
const User = require('../models/User');
const { ERRORS } = require('../utils/constants');

const getRoles = async (filters = {}, options = {}) => {
  const { page = 1, limit = 10, sort = 'priority', includePermissions = true } = options;
  const skip = (page - 1) * limit;

  let query = Role.find(filters);

  if (includePermissions) {
    query = query.populate({
      path: 'permissions',
      select: 'name displayName resource action description category isActive',
      match: { isActive: true }
    });
  }

  const roles = await query
    .populate('metadata.createdBy', 'firstName lastName')
    .populate('metadata.updatedBy', 'firstName lastName')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await Role.countDocuments(filters);

  return {
    roles,
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

const getRoleById = async (roleId, includePermissions = true) => {
  let query = Role.findById(roleId);

  if (includePermissions) {
    query = query.populate({
      path: 'permissions',
      select: 'name displayName resource action description category isActive',
      match: { isActive: true }
    });
  }

  const role = await query
    .populate('metadata.createdBy', 'firstName lastName')
    .populate('metadata.updatedBy', 'firstName lastName');

  if (!role) {
    throw new Error(ERRORS.ROLE.NOT_FOUND);
  }

  return role;
};

const createRole = async (roleData) => {
  const { name, permissions = [], ...otherData } = roleData;

  const existingRole = await Role.findOne({ name });
  if (existingRole) {
    throw new Error(ERRORS.ROLE.NAME_EXISTS);
  }

  if (permissions.length) {
    const validPermissions = await Permission.find({ _id: { $in: permissions }, isActive: true });
    if (validPermissions.length !== permissions.length) {
      throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);
    }
  }

  const role = new Role({
    ...otherData,
    name,
    permissions
  });

  await role.save();
  return getRoleById(role._id);
};

const updateRole = async (roleId, updates) => {
  const existingRole = await Role.findById(roleId);
  if (!existingRole) {
    throw new Error(ERRORS.ROLE.NOT_FOUND);
  }

  if (existingRole.isSystem && (updates.name !== undefined || updates.permissions !== undefined)) {
    throw new Error(ERRORS.ROLE.SYSTEM_ROLE_MODIFICATION);
  }

  if (updates.name && updates.name !== existingRole.name) {
    const nameExists = await Role.findOne({ name: updates.name, _id: { $ne: roleId } });
    if (nameExists) {
      throw new Error(ERRORS.ROLE.NAME_EXISTS);
    }
  }

  if (updates.permissions !== undefined && updates.permissions.length > 0) {
    const validPermissions = await Permission.find({ _id: { $in: updates.permissions }, isActive: true });
    if (validPermissions.length !== updates.permissions.length) {
      throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);
    }
  }

  const finalUpdates = {
    ...updates,
    metadata: {
      ...existingRole.metadata,
      ...updates.metadata,
      updatedAt: new Date()
    }
  };

  await Role.findByIdAndUpdate(roleId, finalUpdates, { new: true, runValidators: true });
  return getRoleById(roleId);
};

const deleteRole = async (roleId) => {
  const role = await Role.findById(roleId);
  if (!role) {
    throw new Error(ERRORS.ROLE.NOT_FOUND);
  }

  if (role.isSystem) {
    throw new Error(ERRORS.ROLE.SYSTEM_ROLE_DELETE);
  }

  const userCount = await User.countDocuments({ roles: roleId });
  if (userCount > 0) {
    throw new Error(ERRORS.ROLE.ASSIGNED_TO_USERS);
  }

  await Role.findByIdAndDelete(roleId);
  return true;
};

const toggleRoleStatus = async (roleId, isActive, actorId) => {
  const role = await Role.findById(roleId);
  if (!role) {
    throw new Error(ERRORS.ROLE.NOT_FOUND);
  }

  if (role.isSystem) {
    throw new Error(ERRORS.ROLE.SYSTEM_ROLE_MODIFICATION);
  }

  const updates = {
    isActive: !!isActive,
    metadata: {
      ...role.metadata,
      updatedBy: actorId,
      updatedAt: new Date()
    }
  };

  await Role.findByIdAndUpdate(roleId, updates, { new: true, runValidators: true });
  return getRoleById(roleId);
};

const assignPermissions = async (roleId, permissionIds) => {
  const role = await Role.findById(roleId);
  if (!role) {
    throw new Error(ERRORS.ROLE.NOT_FOUND);
  }

  if (role.isSystem) {
    throw new Error(ERRORS.ROLE.SYSTEM_ROLE_MODIFICATION);
  }

  if (permissionIds?.length) {
    const validPermissions = await Permission.find({ _id: { $in: permissionIds }, isActive: true });
    if (validPermissions.length !== permissionIds.length) {
      throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);
    }
  }

  const updates = {
    permissions: permissionIds || [],
    metadata: {
      ...role.metadata,
      updatedAt: new Date()
    }
  };

  await Role.findByIdAndUpdate(roleId, updates, { new: true, runValidators: true });
  return getRoleById(roleId);
};

const removePermissions = async (roleId, permissionIds) => {
  const role = await Role.findById(roleId);
  if (!role) throw new Error(ERRORS.ROLE.NOT_FOUND);
  if (role.isSystem) throw new Error(ERRORS.ROLE.SYSTEM_ROLE_MODIFICATION);

  const toStr = (x) => (x ? x.toString() : '');
  const removeSet = new Set((permissionIds || []).map(toStr));

  const updatedPermissions = (role.permissions || []).filter(
    (permId) => !removeSet.has(toStr(permId))
  );

  const updates = {
    permissions: updatedPermissions,
    metadata: {
      ...role.metadata,
      updatedAt: new Date()
    }
  };

  await Role.findByIdAndUpdate(roleId, updates, { new: true, runValidators: true });
  return getRoleById(roleId);
};

const getRoleUsers = async (roleId, options = {}) => {
  const { page = 1, limit = 10, sort = '-createdAt' } = options;
  const skip = (page - 1) * limit;

  const role = await Role.findById(roleId);
  if (!role) {
    throw new Error(ERRORS.ROLE.NOT_FOUND);
  }

  const users = await User.find({ roles: roleId })
    .select('firstName lastName email isActive lastLogin createdAt')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await User.countDocuments({ roles: roleId });

  return {
    users,
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
