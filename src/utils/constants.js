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
    DATE_RANGE_TOO_LARGE: 'errors.validation.date_range_too_large'
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
    ALREADY_UNLOCKED: 'errors.user.already_unlocked',
    CANNOT_DELETE_SELF: 'errors.user.cannot_delete_self',
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
  CATEGORY: {
    NOT_FOUND: 'errors.category.not_found',
    NAME_EXISTS: 'errors.category.name_exists',
    SLUG_EXISTS: 'errors.category.slug_exists',
    INVALID_PARENT: 'errors.category.invalid_parent',
    CIRCULAR_PARENT: 'errors.category.circular_parent',
    HAS_CHILDREN: 'errors.category.has_children',
    SYSTEM_CATEGORY_DELETE: 'errors.category.system_category_delete',
    SYSTEM_CATEGORY_MODIFICATION: 'errors.category.system_category_modification',
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
  CATEGORY: {
    CREATED: 'messages.category.created',
    UPDATED: 'messages.category.updated',
    DELETED: 'messages.category.deleted',
    STATUS_UPDATED: 'messages.category.status_updated',
    MOVED: 'messages.category.moved',
  },
};

const ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
  USER: 'user',
};

const PERMISSION_CATEGORIES = {
  USER_MANAGEMENT: 'user_management',
  ROLE_MANAGEMENT: 'role_management',
  PERMISSION_MANAGEMENT: 'permission_management',
  AUDIT_MANAGEMENT: 'audit_management',
  CATEGORY_MANAGEMENT: 'category_management'
};

const PERMISSIONS = {
  USER_READ: 'user:read',
  USER_CREATE: 'user:create',
  USER_UPDATE: 'user:update',
  USER_DELETE: 'user:delete',
  USER_MANAGE: 'user:manage',

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

  CATEGORY_READ: 'category:read',
  CATEGORY_CREATE: 'category:create',
  CATEGORY_UPDATE: 'category:update',
  CATEGORY_DELETE: 'category:delete',
  CATEGORY_MANAGE: 'category:manage',
};

const RESOURCES = {
  AUTH: 'auth',
  USER: 'user',
  ROLE: 'role',
  PERMISSION: 'permission',
  AUDIT: 'audit',
  CATEGORY: 'category'
};

const ACTIONS = {
  READ: 'read',
  CREATE: 'create',
  UPDATE: 'update',
  DELETE: 'delete',
  MANAGE: 'manage',

  LOGIN: 'login',
  LOGOUT: 'logout',
  REGISTER: 'register',
  REFRESH: 'refresh',

  ASSIGN: 'assign',
  REMOVE: 'remove',
  TOGGLE: 'toggle',
  UNLOCK: 'unlock',
  MOVE: 'move',

  EXPORT: 'export',
  HEALTH: 'health'
};

const SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  LOCKED: 423,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  SERVICE_UNAVAILABLE: 503,
};

module.exports = {
  MESSAGES,
  ERRORS,
  ROLES,
  PERMISSION_CATEGORIES,
  PERMISSIONS,
  RESOURCES,
  ACTIONS,
  SEVERITY,
  HTTP_STATUS,
};
