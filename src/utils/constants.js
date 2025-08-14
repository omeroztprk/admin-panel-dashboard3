const ERRORS = {
  GENERAL: {
    INTERNAL_ERROR: 'errors.general.internal_error',
    NOT_FOUND: 'errors.general.not_found',
    UNAUTHORIZED: 'errors.general.unauthorized',
    FORBIDDEN: 'errors.general.forbidden',
    RATE_LIMIT_DYNAMIC: 'errors.general.rate_limit_dynamic',
  },
  VALIDATION: {
    INVALID_INPUT: 'errors.validation.invalid_input',
    INVALID_ID: 'errors.validation.invalid_id',
    INVALID_OBJECT_ID: 'errors.validation.invalid_object_id',
    PASSWORDS_SAME: 'errors.validation.passwords_same',
    REQUIRED_FIELDS: 'errors.validation.required_fields',
    PASSWORD_MIN_LENGTH: 'errors.validation.password_min_length',
    DUPLICATE_VALUE: 'errors.validation.duplicate_value',
  },
  AUTH: {
    INVALID_CREDENTIALS: 'errors.auth.invalid_credentials',
    INVALID_TOKEN: 'errors.auth.invalid_token',
    TOKEN_EXPIRED: 'errors.auth.token_expired',
    TOKEN_MISSING: 'errors.auth.token_missing',
    REFRESH_TOKEN_MISSING: 'errors.auth.refresh_token_missing',
    INVALID_REFRESH_TOKEN: 'errors.auth.invalid_refresh_token',
    INVALID_SESSION: 'errors.auth.invalid_session',
    ACCOUNT_LOCKED: 'errors.auth.account_locked',
    ACCOUNT_LOCKED_DYNAMIC: 'errors.auth.account_locked_dynamic',
    ACCOUNT_INACTIVE: 'errors.auth.account_inactive',
    EMAIL_EXISTS: 'errors.auth.email_exists',
    USER_NOT_FOUND: 'errors.auth.user_not_found',
    INVALID_CURRENT_PASSWORD: 'errors.auth.invalid_current_password',
    INSUFFICIENT_PERMISSIONS: 'errors.auth.insufficient_permissions',
    AUTHENTICATION_REQUIRED: 'errors.auth.authentication_required',
    TOO_MANY_ATTEMPTS_DYNAMIC: 'errors.auth.too_many_attempts_dynamic',
    TOO_MANY_FAILED_DYNAMIC: 'errors.auth.too_many_failed_dynamic',
  },
  USER: {
    NOT_FOUND: 'errors.user.not_found',
    EMAIL_EXISTS: 'errors.user.email_exists',
  },
  ROLE: {
    NOT_FOUND: 'errors.role.not_found',
    NAME_EXISTS: 'errors.role.name_exists',
    INVALID_ROLES: 'errors.role.invalid_roles',
    SYSTEM_ROLE_DELETE: 'errors.role.system_role_delete',
    ASSIGNED_TO_USERS: 'errors.role.assigned_to_users',
    SYSTEM_ROLE_MODIFICATION: 'errors.role.system_role_modification',
  },
  PERMISSION: {
    NOT_FOUND: 'errors.permission.not_found',
    NAME_EXISTS: 'errors.permission.name_exists',
    INVALID_PERMISSIONS: 'errors.permission.invalid_permissions',
    SYSTEM_PERMISSION_DELETE: 'errors.permission.system_permission_delete',
    ASSIGNED_TO_ROLES: 'errors.permission.assigned_to_roles',
    ASSIGNED_TO_USERS: 'errors.permission.assigned_to_users',
    SYSTEM_PERMISSION_MODIFICATION: 'errors.permission.system_permission_modification',
  },
  AUDIT: {
    NOT_FOUND: 'errors.audit.not_found',
  },
};

const MESSAGES = {
  GENERAL: {
    SUCCESS: 'messages.general.success',
    CREATED: 'messages.general.created',
    UPDATED: 'messages.general.updated',
    DELETED: 'messages.general.deleted',
    API_RUNNING: 'messages.general.api_running',
    API_UNHEALTHY: 'messages.general.api_unhealthy',
    API_ERROR: 'messages.general.api_error',
  },
  AUTH: {
    LOGIN_SUCCESS: 'messages.auth.login_success',
    LOGOUT_SUCCESS: 'messages.auth.logout_success',
    LOGOUT_ALL_SUCCESS: 'messages.auth.logout_all_success',
    REGISTER_SUCCESS: 'messages.auth.register_success',
    TOKEN_REFRESHED: 'messages.auth.token_refreshed',
    PROFILE_UPDATED: 'messages.auth.profile_updated',
    PASSWORD_CHANGED: 'messages.auth.password_changed',
    SESSION_REVOKED: 'messages.auth.session_revoked',
  },
  USER: {
    CREATED: 'messages.user.created',
    UPDATED: 'messages.user.updated',
    DELETED: 'messages.user.deleted',
    STATUS_UPDATED: 'messages.user.status_updated',
    ROLES_ASSIGNED: 'messages.user.roles_assigned',
    PERMISSIONS_ASSIGNED: 'messages.user.permissions_assigned',
    PASSWORD_RESET: 'messages.user.password_reset',
    UNLOCKED: 'messages.user.unlocked',
    ALREADY_UNLOCKED: 'messages.user.already_unlocked',
  },
  ROLE: {
    CREATED: 'messages.role.created',
    UPDATED: 'messages.role.updated',
    DELETED: 'messages.role.deleted',
    STATUS_UPDATED: 'messages.role.status_updated',
    PERMISSIONS_ASSIGNED: 'messages.role.permissions_assigned',
    PERMISSIONS_REMOVED: 'messages.role.permissions_removed',
  },
  PERMISSION: {
    CREATED: 'messages.permission.created',
    UPDATED: 'messages.permission.updated',
    DELETED: 'messages.permission.deleted',
    STATUS_UPDATED: 'messages.permission.status_updated',
  },
};

const ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
  USER: 'user',
};

const PERMISSIONS = {
  USER_READ: 'user:read',
  USER_CREATE: 'user:create',
  USER_UPDATE: 'user:update',
  USER_DELETE: 'user:delete',
  USER_MANAGE: 'user:manage',
  USER_UNLOCK: 'user:unlock',

  ROLE_READ: 'role:read',
  ROLE_CREATE: 'role:create',
  ROLE_UPDATE: 'role:update',
  ROLE_DELETE: 'role:delete',
  ROLE_MANAGE: 'role:manage',

  PERMISSION_READ: 'permission:read',
  PERMISSION_CREATE: 'permission:create',
  PERMISSION_UPDATE: 'permission:update',
  PERMISSION_DELETE: 'permission:delete',
  PERMISSION_MANAGE: 'permission:manage',

  AUDIT_READ: 'audit:read',
  AUDIT_EXPORT: 'audit:export',
  SYSTEM_HEALTH: 'system:health',
};

const PERMISSION_CATEGORIES = {
  USER_MANAGEMENT: 'User Management',
  ROLE_MANAGEMENT: 'Role Management',
  PERMISSION_MANAGEMENT: 'Permission Management',
  AUDIT_MANAGEMENT: 'Audit Management',
  SYSTEM_MANAGEMENT: 'System Management',
};

const RESOURCES = {
  USER: 'user',
  ROLE: 'role',
  PERMISSION: 'permission',
  AUDIT: 'audit',
  SYSTEM: 'system',
};

const ACTIONS = {
  READ: 'read',
  CREATE: 'create',
  UPDATE: 'update',
  DELETE: 'delete',
  MANAGE: 'manage',
  UNLOCK: 'unlock',
  EXPORT: 'export',
  HEALTH: 'health',
};

module.exports = {
  MESSAGES,
  ERRORS,
  ROLES,
  PERMISSIONS,
  PERMISSION_CATEGORIES,
  RESOURCES,
  ACTIONS,
};
