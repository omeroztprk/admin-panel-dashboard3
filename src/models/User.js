const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const config = require('../config');

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'errors.validation.first_name_required'],
    trim: true,
    maxlength: [50, 'errors.validation.first_name_length'],
  },
  lastName: {
    type: String,
    required: [true, 'errors.validation.last_name_required'],
    trim: true,
    maxlength: [50, 'errors.validation.last_name_length'],
  },
  email: {
    type: String,
    required: [true, 'errors.validation.email_required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'errors.validation.invalid_email'],
    maxlength: [100, 'errors.validation.email_max_length'],
  },
  password: {
    type: String,
    required: [true, 'errors.validation.password_required'],
    minlength: [8, 'errors.validation.password_min_length'],
    select: false,
  },

  roles: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Role' }],
  permissions: [{
    _id: false,
    permission: { type: mongoose.Schema.Types.ObjectId, ref: 'Permission' },
    granted: { type: Boolean, default: true },
  }],

  isActive: { type: Boolean, default: true },
  isEmailVerified: { type: Boolean, default: false },
  lastLogin: Date,

  loginAttempts: { type: Number, default: 0 },
  lockoutUntil: Date,

  profile: {
    avatar: String,
    phone: String,
    address: String,
    timezone: { type: String, default: 'UTC' },
    language: {
      type: String,
      default: () => (config.i18n?.defaultLanguage ? config.i18n.defaultLanguage : 'tr'),
    },
  },

  metadata: {
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    ipAddress: String,
    userAgent: String,
  },
  sso: {
    provider: { type: String, enum: ['keycloak'], required: false },
    keycloakId: { type: String }
  },
}, {
  timestamps: true,
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ isActive: 1, createdAt: -1 });
userSchema.index({ roles: 1 });
userSchema.index({ loginAttempts: 1, lockoutUntil: 1 });
userSchema.index({ 'profile.language': 1 });
userSchema.index({ lastLogin: -1 });
userSchema.index({ 'sso.keycloakId': 1 }, { sparse: true });

userSchema.index({ firstName: 'text', lastName: 'text', email: 'text' }, {
  weights: { email: 10, firstName: 5, lastName: 5 },
  name: 'user_text_search',
});

userSchema.virtual('fullName').get(function () {
  return `${this.firstName} ${this.lastName}`;
});

userSchema.virtual('isLocked').get(function () {
  return !!(this.lockoutUntil && this.lockoutUntil.getTime() > Date.now());
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const saltRounds = config.security?.bcrypt?.saltRounds ?? 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.incLoginAttempts = async function () {
  const maxAttempts = config.security?.lockout?.maxAttempts ?? 5;
  const lockMs = config.security?.lockout?.lockoutTime ?? (15 * 60 * 1000);

  if (this.lockoutUntil && this.lockoutUntil.getTime() < Date.now()) {
    return this.updateOne({ $unset: { lockoutUntil: 1 }, $set: { loginAttempts: 1 } });
  }
  const updates = { $inc: { loginAttempts: 1 } };
  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { lockoutUntil: new Date(Date.now() + lockMs) };
  }
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = async function () {
  return this.updateOne({ $unset: { loginAttempts: 1, lockoutUntil: 1 } });
};

userSchema.methods.getAllPermissions = async function () {
  if (this._permissionsCache && this._permissionsCacheTime && 
      (Date.now() - this._permissionsCacheTime) < 5 * 60 * 1000) {
    return this._permissionsCache;
  }

  await this.populate([
    {
      path: 'roles',
      populate: { path: 'permissions', select: 'name displayName resource action description category isActive' },
    },
    {
      path: 'permissions.permission',
      select: 'name displayName resource action description category isActive',
    },
  ]);

  const permissionMap = new Map();

  (this.roles || []).forEach((role) => {
    (role.permissions || []).forEach((perm) => {
      if (perm?.isActive) permissionMap.set(perm._id.toString(), perm);
    });
  });

  (this.permissions || []).forEach((p) => {
    const key = p?.permission?._id?.toString?.();
    if (!key || !p.permission?.isActive) return;
    if (p.granted === true) {
      permissionMap.set(key, p.permission);
    } else if (p.granted === false) {
      permissionMap.delete(key);
    }
  });

  const result = Array.from(permissionMap.values());
  
  this._permissionsCache = result;
  this._permissionsCacheTime = Date.now();

  return result;
};

userSchema.methods.clearPermissionsCache = function() {
  this._permissionsCache = null;
  this._permissionsCacheTime = null;
};

userSchema.pre('save', function() {
  if (this.isModified('roles') || this.isModified('permissions')) {
    this.clearPermissionsCache();
  }
});

userSchema.methods.hasPermission = async function (resource, action, useCache = true) {
  const cacheKey = `user_${this._id}_perm_${resource}_${action}`;
  if (useCache && this._permissionCache?.[cacheKey]) return this._permissionCache[cacheKey];

  const permissions = await this.getAllPermissions();
  const granted = permissions.some((perm) => perm.resource === resource && perm.action === action);

  this._permissionCache = this._permissionCache || {};
  this._permissionCache[cacheKey] = granted;
  setTimeout(() => delete this._permissionCache[cacheKey], 5 * 60 * 1000);

  return granted;
};

userSchema.methods.hasPermissions = async function (permissionList) {
  const userPermissions = await this.getAllPermissions();
  const permissionMap = new Map();
  userPermissions.forEach((p) => permissionMap.set(`${p.resource}:${p.action}`, true));

  return permissionList.map(({ resource, action }) => ({
    resource,
    action,
    granted: permissionMap.has(`${resource}:${action}`),
  }));
};

userSchema.methods.getSecurityProfile = async function () {
  const AuditLog = mongoose.model('AuditLog');
  const last30Days = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const [loginCount, failedLogins, lastActivity, ipAddresses] = await Promise.all([
    AuditLog.countDocuments({ user: this._id, action: 'login', statusCode: 200, createdAt: { $gte: last30Days } }),
    AuditLog.countDocuments({
      user: this._id,
      createdAt: { $gte: last30Days },
      $or: [
        { action: 'login_failed' },
        { action: 'login_rate_limited' },
        { action: 'login', statusCode: { $gte: 400 } },
      ],
    }),
    AuditLog.findOne({ user: this._id }).sort({ createdAt: -1 }).select('createdAt ipAddress'),
    AuditLog.distinct('ipAddress', { user: this._id, createdAt: { $gte: last30Days } }),
  ]);

  return {
    loginCount,
    failedLogins,
    lastActivity: lastActivity?.createdAt,
    lastIP: lastActivity?.ipAddress,
    uniqueIPs: ipAddresses.length,
    riskScore: this.calculateRiskScore(failedLogins, ipAddresses.length),
  };
};

userSchema.methods.calculateRiskScore = function (failedLogins, uniqueIPs) {
  let score = 0;
  if (failedLogins > 10) score += 30;
  else if (failedLogins > 5) score += 15;

  if (uniqueIPs > 5) score += 20;
  else if (uniqueIPs > 2) score += 10;

  if (this.loginAttempts > 0) score += 10;
  if (!this.isEmailVerified) score += 15;

  return Math.min(score, 100);
};

module.exports = mongoose.model('User', userSchema);
