const mongoose = require('mongoose');
const User = require('../models/User');
const Role = require('../models/Role');
const Permission = require('../models/Permission');
const { ERRORS } = require('../utils/constants');
const { isValidObjectId, normalizeEmail } = require('../utils/helpers');

const getUsers = async (filters = {}, options = {}) => {
  const { page = 1, limit = 10, sort = '-createdAt' } = options;
  const skip = (page - 1) * limit;

  const users = await User.find(filters)
    .populate([
      {
        path: 'roles',
        select: 'name displayName description priority isActive permissions createdAt updatedAt',
        populate: {
          path: 'permissions',
          select: 'name displayName resource action description category isActive'
        }
      },
      {
        path: 'permissions.permission',
        select: 'name displayName resource action description category isActive'
      },
      { path: 'metadata.createdBy', select: 'firstName lastName' },
      { path: 'metadata.updatedBy', select: 'firstName lastName' }
    ])
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await User.countDocuments(filters);

  return {
    users,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  };
};

const getUserById = async (userId) => {
  if (!isValidObjectId(userId)) return null;

  return User.findById(userId).populate([
    {
      path: 'roles',
      select: 'name displayName description priority isActive permissions createdAt updatedAt',
      populate: {
        path: 'permissions',
        select: 'name displayName resource action description category isActive'
      }
    },
    {
      path: 'permissions.permission',
      select: 'name displayName resource action description category isActive'
    },
    { path: 'metadata.createdBy', select: 'firstName lastName' },
    { path: 'metadata.updatedBy', select: 'firstName lastName' }
  ]);
};

const createUser = async (userData) => {
  const { email, roles, permissions, ...otherData } = userData;

  const normalizedEmail = normalizeEmail(email);
  const existingUser = await User.findOne({ email: normalizedEmail });
  if (existingUser) throw new Error(ERRORS.AUTH.EMAIL_EXISTS);

  if (roles?.length) {
    const uniqueRoleIds = [...new Set(roles.map(String))];
    const validRoles = await Role.find({ _id: { $in: uniqueRoleIds }, isActive: true });
    if (validRoles.length !== uniqueRoleIds.length) throw new Error(ERRORS.ROLE.INVALID_ROLES);
  }

  if (permissions?.length) {
    const normalizedPerms = permissions
      .filter(p => p && p.permission)
      .map(p => ({ permission: String(p.permission), granted: p.granted !== false }))
      .filter((p, i, arr) => arr.findIndex(x => x.permission === p.permission) === i);

    const permissionIds = normalizedPerms.map(p => p.permission);
    const validPermissions = await Permission.find({ _id: { $in: permissionIds }, isActive: true });
    if (validPermissions.length !== permissionIds.length) throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);

    otherData.permissions = normalizedPerms;
  }

  const user = new User({
    ...otherData,
    email: normalizedEmail,
    roles: roles || [],
    permissions: otherData.permissions || []
  });

  await user.save();
  return getUserById(user._id);
};

const updateUser = async (userId, updates) => {
  if (!isValidObjectId(userId)) throw new Error(ERRORS.USER.NOT_FOUND);

  const { roles, permissions, email, ...otherUpdates } = updates;

  if (roles !== undefined) {
    if (Array.isArray(roles) && roles.length > 0) {
      const uniqueRoleIds = [...new Set(roles.map(String))];
      const validRoles = await Role.find({ _id: { $in: uniqueRoleIds }, isActive: true });
      if (validRoles.length !== uniqueRoleIds.length) throw new Error(ERRORS.ROLE.INVALID_ROLES);
      otherUpdates.roles = uniqueRoleIds;
    } else {
      otherUpdates.roles = [];
    }
  }

  if (permissions !== undefined) {
    if (Array.isArray(permissions) && permissions.length > 0) {
      const normalizedPerms = permissions
        .filter(p => p && p.permission)
        .map(p => ({ permission: String(p.permission), granted: p.granted !== false }))
        .filter((p, i, arr) => arr.findIndex(x => x.permission === p.permission) === i);

      const permissionIds = normalizedPerms.map(p => p.permission);
      const validPermissions = await Permission.find({ _id: { $in: permissionIds }, isActive: true });
      if (validPermissions.length !== permissionIds.length) throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);

      otherUpdates.permissions = normalizedPerms;
    } else {
      otherUpdates.permissions = [];
    }
  }

  if (email !== undefined) {
    const normalizedEmail = normalizeEmail(email);
    const exists = await User.findOne({ email: normalizedEmail, _id: { $ne: userId } });
    if (exists) throw new Error(ERRORS.AUTH.EMAIL_EXISTS);
    otherUpdates.email = normalizedEmail;
  }

  const user = await User.findByIdAndUpdate(userId, otherUpdates, { new: true, runValidators: true });
  if (!user) throw new Error(ERRORS.USER.NOT_FOUND);

  return getUserById(userId);
};

const deleteUser = async (userId) => {
  if (!isValidObjectId(userId)) throw new Error(ERRORS.USER.NOT_FOUND);

  const user = await User.findById(userId);
  if (!user) throw new Error(ERRORS.USER.NOT_FOUND);

  await User.findByIdAndDelete(userId);
  return true;
};

const toggleUserStatus = async (userId, isActive, actorId) => {
  if (!isValidObjectId(userId)) throw new Error(ERRORS.USER.NOT_FOUND);

  const updates = {
    isActive: !!isActive,
    metadata: {
      updatedBy: actorId,
      updatedAt: new Date()
    }
  };

  const doUpdate = async (session = null) => {
    const doc = await User.findByIdAndUpdate(userId, updates, {
      new: true,
      runValidators: true,
      session: session || undefined
    });
    if (!doc) throw new Error(ERRORS.USER.NOT_FOUND);
    return getUserById(userId);
  };

  let session;
  try {
    session = await mongoose.startSession();
    session.startTransaction();
    const updated = await doUpdate(session);
    await session.commitTransaction();
    session.endSession();
    return updated;
  } catch (err) {
    if (session) {
      try { await session.abortTransaction(); } catch (_) { }
      session.endSession();
    }
    const msg = String(err?.message || '');
    if (msg.includes('Transaction numbers are only allowed') || msg.includes('replica set') || err?.code === 20) {
      return doUpdate();
    }
    throw err;
  }
};

const assignRoles = async (userId, roleIds) => {
  if (!isValidObjectId(userId)) throw new Error(ERRORS.USER.NOT_FOUND);

  const uniqueRoleIds = [...new Set((roleIds || []).map(String))];
  if (!uniqueRoleIds.length) {
    const doc = await User.findByIdAndUpdate(userId, { roles: [] }, { new: true, runValidators: true });
    if (!doc) throw new Error(ERRORS.USER.NOT_FOUND);
    return getUserById(userId);
  }

  const validRoles = await Role.find({ _id: { $in: uniqueRoleIds }, isActive: true });
  if (validRoles.length !== uniqueRoleIds.length) throw new Error(ERRORS.ROLE.INVALID_ROLES);

  const user = await User.findByIdAndUpdate(userId, { roles: uniqueRoleIds }, { new: true, runValidators: true });
  if (!user) throw new Error(ERRORS.USER.NOT_FOUND);

  return getUserById(userId);
};

const assignPermissions = async (userId, permissions) => {
  if (!isValidObjectId(userId)) throw new Error(ERRORS.USER.NOT_FOUND);

  const normalizedPerms = (permissions || [])
    .filter(p => p && p.permission)
    .map(p => ({ permission: String(p.permission), granted: p.granted !== false }))
    .filter((p, i, arr) => arr.findIndex(x => x.permission === p.permission) === i);

  if (!normalizedPerms.length) {
    const doc = await User.findByIdAndUpdate(userId, { permissions: [] }, { new: true, runValidators: true });
    if (!doc) throw new Error(ERRORS.USER.NOT_FOUND);
    return getUserById(userId);
  }

  const permissionIds = normalizedPerms.map(p => p.permission);
  const validPermissions = await Permission.find({ _id: { $in: permissionIds }, isActive: true });
  if (validPermissions.length !== permissionIds.length) throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);

  const user = await User.findByIdAndUpdate(userId, { permissions: normalizedPerms }, { new: true, runValidators: true });
  if (!user) throw new Error(ERRORS.USER.NOT_FOUND);

  return getUserById(userId);
};

const getUserPermissions = async (userId) => {
  if (!isValidObjectId(userId)) throw new Error(ERRORS.USER.NOT_FOUND);

  const user = await User.findById(userId)
    .populate('roles')
    .populate('permissions.permission');

  if (!user) throw new Error(ERRORS.USER.NOT_FOUND);
  return user.getAllPermissions();
};

const resetPassword = async (userId, newPassword) => {
  if (!isValidObjectId(userId)) throw new Error(ERRORS.USER.NOT_FOUND);

  const user = await User.findById(userId).select('+password');
  if (!user) throw new Error(ERRORS.USER.NOT_FOUND);

  user.password = newPassword;
  await user.save();

  return true;
};

const unlockUser = async (userId) => {
  if (!isValidObjectId(userId)) throw new Error(ERRORS.USER.NOT_FOUND);

  const current = await User.findById(userId).select('loginAttempts lockoutUntil');
  if (!current) throw new Error(ERRORS.USER.NOT_FOUND);

  const now = Date.now();
  const wasLocked =
    !!(current.lockoutUntil && current.lockoutUntil > now) ||
    (current.loginAttempts && current.loginAttempts > 0);

  if (!wasLocked) {
    return { user: current, wasLocked, unlocked: false };
  }

  await User.updateOne({ _id: userId }, { $unset: { loginAttempts: 1, lockoutUntil: 1 } });
  const updated = await User.findById(userId).select('loginAttempts lockoutUntil');

  return { user: updated, wasLocked, unlocked: true };
};

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
