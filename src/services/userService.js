const mongoose = require('mongoose');
const User = require('../models/User');
const Role = require('../models/Role');
const Permission = require('../models/Permission');
const tokenService = require('../services/tokenService');
const { ERRORS } = require('../utils/constants');
const { normalizeEmail, hashPassword } = require('../utils/helpers');
const KeycloakRoleService = require('./keycloakRoleService');
const { mapLocalRolesToKeycloak } = require('../utils/sso');

const getUsers = async (filters = {}, options = {}) => {
  const { page = 1, limit = 10, sort = '-createdAt' } = options;
  const skip = (page - 1) * limit;

  const users = await User.find(filters)
    .populate([
      {
        path: 'roles',
        select: 'name displayName description priority isActive permissions',
        populate: {
          path: 'permissions',
          select: 'name displayName resource action description category isActive'
        }
      },
      {
        path: 'permissions.permission',
        select: 'name displayName resource action description category isActive'
      }
    ])
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await User.countDocuments(filters);

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

const getUserById = async (userId) => {
  const user = await User.findById(userId).populate([
    {
      path: 'roles',
      select: 'name displayName description priority isActive permissions',
      populate: {
        path: 'permissions',
        select: 'name displayName resource action description category isActive'
      }
    },
    {
      path: 'permissions.permission',
      select: 'name displayName resource action description category isActive'
    }
  ]);

  if (!user) {
    throw new Error(ERRORS.USER.NOT_FOUND);
  }

  return user;
};

const createUser = async (userData) => {
  const { email, roles = [], permissions = [], password, ...otherData } = userData;

  const normalizedEmail = normalizeEmail(email);
  const existingUser = await User.findOne({ email: normalizedEmail });
  if (existingUser) {
    const error = new Error(ERRORS.USER.EMAIL_EXISTS);
    error.statusCode = 409;
    throw error;
  }

  if (roles.length) {
    const validRoles = await Role.find({ _id: { $in: roles }, isActive: true });
    if (validRoles.length !== roles.length) {
      const error = new Error(ERRORS.ROLE.INVALID_ROLES);
      error.statusCode = 400;
      throw error;
    }
  }

  let normalizedPerms = [];
  if (permissions.length) {
    normalizedPerms = permissions
      .filter(p => p?.permission)
      .map(p => ({ permission: p.permission, granted: p.granted !== false }));
    const pIds = normalizedPerms.map(p => p.permission);
    const valid = await Permission.find({ _id: { $in: pIds }, isActive: true });
    if (valid.length !== pIds.length) {
      const error = new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);
      error.statusCode = 400;
      throw error;
    }
  }

  const user = new User({
    ...otherData,
    email: normalizedEmail,
    password,
    roles,
    permissions: normalizedPerms
  });

  await user.save();
  return getUserById(user._id);
};

const updateUser = async (userId, updates) => {
  const user = await User.findById(userId);
  if (!user) {
    const error = new Error(ERRORS.USER.NOT_FOUND);
    error.statusCode = 404;
    throw error;
  }

  // SSO kullanıcı: profil güncellemeleri Keycloak üzerinden
  if (user.sso?.provider === 'keycloak') {
    if (updates.password) {
      const error = new Error('errors.sso.password_via_keycloak');
      error.statusCode = 400;
      throw error;
    }

    let normalizedEmail = user.email;
    if (updates.email && updates.email !== user.email) {
      normalizedEmail = normalizeEmail(updates.email);
      const emailExists = await User.findOne({ email: normalizedEmail, _id: { $ne: userId } });
      if (emailExists) {
        const error = new Error(ERRORS.USER.EMAIL_EXISTS);
        error.statusCode = 409;
        throw error;
      }
    }

    await KeycloakRoleService.kcUpdateUserProfile(user.sso.keycloakId, {
      firstName: updates.firstName,
      lastName: updates.lastName,
      email: updates.email ? normalizedEmail : undefined
    });

    // Lokal senkron (tutarlılık için)
    const localUpdates = {
      ...updates,
      email: normalizedEmail,
      password: undefined
    };
    await User.findByIdAndUpdate(userId, localUpdates, { new: true, runValidators: true });
    return getUserById(userId);
  }

  if (updates.email && updates.email !== user.email) {
    const normalizedEmail = normalizeEmail(updates.email);
    const emailExists = await User.findOne({ email: normalizedEmail, _id: { $ne: userId } });
    if (emailExists) {
      const error = new Error(ERRORS.USER.EMAIL_EXISTS);
      error.statusCode = 409;
      throw error;
    }
    updates.email = normalizedEmail;
  }

  if (updates.roles !== undefined && updates.roles.length > 0) {
    const validRoles = await Role.find({ _id: { $in: updates.roles }, isActive: true });
    if (validRoles.length !== updates.roles.length) {
      const error = new Error(ERRORS.ROLE.INVALID_ROLES);
      error.statusCode = 400;
      throw error;
    }
  }

  // ŞİFRE DOĞRULAMA VE HASH'LEME - Düzeltildi
  if (updates.password) {
    // Şifre kompleksite kontrolü - validator ile aynı regex
    const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$/;
    
    if (!strongPasswordRegex.test(updates.password)) {
      const error = new Error('errors.validation.password_complexity');
      error.statusCode = 400;
      throw error;
    }
    
    // Şifreyi hash'le
    updates.password = await hashPassword(updates.password);
  }

  await User.findByIdAndUpdate(userId, updates, { new: true, runValidators: true });
  return getUserById(userId);
};

const deleteUser = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    const error = new Error(ERRORS.USER.NOT_FOUND);
    error.statusCode = 404;
    throw error;
  }

  if (user.sso?.provider === 'keycloak') {
    await KeycloakRoleService.kcDeleteUser(user.sso.keycloakId);
  }

  await User.findByIdAndDelete(userId);
  return true;
};

const toggleUserStatus = async (userId, isActive, actorId) => {
  const user = await User.findById(userId);
  if (!user) {
    const e = new Error(ERRORS.USER.NOT_FOUND);
    e.statusCode = 404;
    throw e;
  }

  if (user.sso?.provider === 'keycloak') {
    await KeycloakRoleService.kcSetUserEnabled(user.sso.keycloakId, !!isActive);
  }

  const updates = {
    isActive: !!isActive,
    metadata: {
      ...user.metadata,
      updatedBy: actorId,
      updatedAt: new Date()
    }
  };

  await User.findByIdAndUpdate(userId, updates, { new: true, runValidators: true });
  return getUserById(userId);
};

const assignRoles = async (userId, roleIds, actorId) => {
  const user = await User.findById(userId);
  if (!user) {
    const e = new Error(ERRORS.USER.NOT_FOUND);
    e.statusCode = 404;
    throw e;
  }

  if (roleIds?.length) {
    const validRoles = await Role.find({ _id: { $in: roleIds }, isActive: true });
    if (validRoles.length !== roleIds.length) {
      throw new Error(ERRORS.ROLE.INVALID_ROLES);
    }
    // SSO ise Keycloak rolleri ata
    if (user.sso?.provider === 'keycloak') {
      const localRoleNames = validRoles.map(r => r.name);
      const kcRoleNames = mapLocalRolesToKeycloak(localRoleNames);
      await KeycloakRoleService.kcAssignRealmRoles(user.sso.keycloakId, kcRoleNames);
      
      // SSO kullanıcısı için: Keycloak'tan güncel profil bilgilerini de çek ve lokal DB'ye yaz
      try {
        const kcUser = await KeycloakRoleService.kcGetUser(user.sso.keycloakId);
        if (kcUser) {
          // Keycloak'tan gelen güncel profil bilgilerini lokal DB'ye senkronize et
          const profileUpdates = {};
          if (kcUser.firstName && kcUser.firstName !== user.firstName) {
            profileUpdates.firstName = kcUser.firstName;
          }
          if (kcUser.lastName && kcUser.lastName !== user.lastName) {
            profileUpdates.lastName = kcUser.lastName;
          }
          if (kcUser.email && kcUser.email !== user.email) {
            // Email çakışması kontrolü
            const emailExists = await User.findOne({ 
              email: kcUser.email.toLowerCase(), 
              _id: { $ne: userId } 
            });
            if (!emailExists) {
              profileUpdates.email = kcUser.email.toLowerCase();
            }
          }
          
          // Profil güncellemeleri varsa yaz
          if (Object.keys(profileUpdates).length > 0) {
            await User.findByIdAndUpdate(userId, profileUpdates, { new: true });
          }
        }
      } catch (syncError) {
        console.warn('assignRoles: Keycloak profil senkronizasyonu başarısız:', syncError.message);
        // Rol ataması başarılı; profil senkronizasyon hatası role assignment'ı iptal etmez
      }
    }
  }

  const updates = {
    roles: roleIds || [],
    metadata: {
      ...user.metadata,
      updatedBy: actorId,
      updatedAt: new Date()
    }
  };

  await User.findByIdAndUpdate(userId, updates, { new: true, runValidators: true });
  return getUserById(userId);
};

const assignPermissions = async (userId, permissions, actorId) => {
  const user = await User.findById(userId);
  if (!user) {
    const e = new Error(ERRORS.USER.NOT_FOUND);
    e.statusCode = 404;
    throw e;
  }

  // SSO kullanıcılar için doğrudan permission atamasını engelle
  if (user.sso?.provider === 'keycloak') {
    const err = new Error('errors.sso.permissions_via_roles');
    err.statusCode = 400;
    throw err;
  }

  let normalizedPerms = [];
  if (permissions?.length) {
    normalizedPerms = permissions
      .filter(p => p?.permission)
      .map(p => ({ permission: p.permission, granted: p.granted !== false }));

    const permissionIds = normalizedPerms.map(p => p.permission);
    const validPermissions = await Permission.find({ _id: { $in: permissionIds }, isActive: true });
    if (validPermissions.length !== permissionIds.length) {
      throw new Error(ERRORS.PERMISSION.INVALID_PERMISSIONS);
    }
  }

  const updates = {
    permissions: normalizedPerms,
    metadata: {
      ...user.metadata,
      updatedBy: actorId,
      updatedAt: new Date()
    }
  };

  await User.findByIdAndUpdate(userId, updates, { new: true, runValidators: true });
  return getUserById(userId);
};

const getUserPermissions = async (userId) => {
  const user = await getUserById(userId);
  return user.getAllPermissions();
};

const resetPassword = async (userId, newPassword) => {
  const user = await User.findById(userId);
  if (!user) {
    const e = new Error(ERRORS.USER.NOT_FOUND);
    e.statusCode = 404;
    throw e;
  }

  if (user.sso?.provider === 'keycloak') {
    await KeycloakRoleService.kcResetPassword(user.sso.keycloakId, newPassword, false);
    return true;
  }

  const hashedPassword = await hashPassword(newPassword);
  await User.findByIdAndUpdate(userId, { password: hashedPassword });
  return true;
};

const unlockUser = async (userId) => {
  const user = await User.findById(userId).select('loginAttempts lockoutUntil');
  if (!user) {
    throw new Error(ERRORS.USER.NOT_FOUND);
  }

  const now = Date.now();
  const wasLocked = !!(user.lockoutUntil && user.lockoutUntil > now) || (user.loginAttempts > 0);

  if (!wasLocked) {
    return { wasLocked: false, unlocked: false };
  }

  await User.updateOne({ _id: userId }, { $unset: { loginAttempts: 1, lockoutUntil: 1 } });
  return { wasLocked: true, unlocked: true };
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
