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

  query = query
    .populate('metadata.createdBy', 'firstName lastName')
    .populate('metadata.updatedBy', 'firstName lastName')
    .sort(sort)
    .skip(skip)
    .limit(limit);

  const roles = await query.lean();
  const total = await Role.countDocuments(filters);

  return {
    roles,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
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

  return query
    .populate('metadata.createdBy', 'firstName lastName')
    .populate('metadata.updatedBy', 'firstName lastName');
};

const createRole = async (roleData) => {
  const { name, permissions, ...otherData } = roleData;

  const existingRole = await Role.findOne({ name });
  if (existingRole) throw new Error(ERRORS.ROLE.NAME_EXISTS);

  if (permissions?.length) {
    const validPermissions = await Permission.find({ _id: { $in: permissions }, isActive: true });
    if (validPermissions.length !== permissions.length) {
      throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);
    }
  }

  const role = new Role({ ...otherData, name, permissions: permissions || [] });
  await role.save();
  return getRoleById(role._id);
};

const updateRole = async (roleId, updates) => {
  const { name, permissions, ...otherUpdates } = updates;
  const existingRole = await Role.findById(roleId);
  if (!existingRole) throw new Error(ERRORS.ROLE.NOT_FOUND);

  if (existingRole.isSystem && (name !== undefined || permissions !== undefined)) {
    throw new Error(ERRORS.ROLE.SYSTEM_ROLE_MODIFICATION);
  }

  if (name && name !== existingRole.name) {
    const nameExists = await Role.findOne({ name, _id: { $ne: roleId } });
    if (nameExists) throw new Error(ERRORS.ROLE.NAME_EXISTS);
    otherUpdates.name = name;
  }

  if (permissions !== undefined) {
    if (permissions.length > 0) {
      const valid = await Permission.find({ _id: { $in: permissions }, isActive: true });
      if (valid.length !== permissions.length) {
        throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);
      }
    }
    otherUpdates.permissions = permissions;
  }

  await Role.findByIdAndUpdate(roleId, otherUpdates, { new: true, runValidators: true });
  return getRoleById(roleId);
};

const deleteRole = async (roleId) => {
  const role = await Role.findById(roleId);
  if (!role) throw new Error(ERRORS.ROLE.NOT_FOUND);
  if (role.isSystem) throw new Error(ERRORS.ROLE.SYSTEM_ROLE_DELETE);

  const userCount = await User.countDocuments({ roles: roleId });
  if (userCount > 0) throw new Error(ERRORS.ROLE.ASSIGNED_TO_USERS);

  await Role.findByIdAndDelete(roleId);
  return true;
};

const toggleRoleStatus = async (roleId, isActive, { updatedBy } = {}) => {
  const role = await Role.findById(roleId);
  if (!role) throw new Error(ERRORS.ROLE.NOT_FOUND);
  if (role.isSystem) throw new Error(ERRORS.ROLE.SYSTEM_ROLE_MODIFICATION);

  role.isActive = !!isActive;
  role.metadata = {
    ...(role.metadata || {}),
    updatedBy,
    updatedAt: new Date()
  };

  await role.save();
  return getRoleById(roleId, true);
};

const assignPermissions = async (roleId, permissionIds) => {
  const role = await Role.findById(roleId);
  if (!role) throw new Error(ERRORS.ROLE.NOT_FOUND);
  if (role.isSystem) throw new Error(ERRORS.ROLE.SYSTEM_ROLE_MODIFICATION);

  const valid = await Permission.find({ _id: { $in: permissionIds }, isActive: true });
  if (valid.length !== permissionIds.length) {
    throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);
  }

  role.permissions = permissionIds;
  await role.save();
  return getRoleById(roleId);
};

const removePermissions = async (roleId, permissionIds) => {
  const role = await Role.findById(roleId);
  if (!role) throw new Error(ERRORS.ROLE.NOT_FOUND);
  if (role.isSystem) throw new Error(ERRORS.ROLE.SYSTEM_ROLE_MODIFICATION);

  role.permissions = role.permissions.filter(
    (permId) => !permissionIds.includes(permId.toString())
  );

  await role.save();
  return getRoleById(roleId);
};

const getRoleUsers = async (roleId, options = {}) => {
  const { page = 1, limit = 10, sort = '-createdAt' } = options;
  const skip = (page - 1) * limit;

  const users = await User.find({ roles: roleId })
    .select('firstName lastName email isActive lastLogin createdAt')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await User.countDocuments({ roles: roleId });

  return {
    users,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
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
