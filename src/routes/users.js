const express = require('express');
const { ensureAuthUnified } = require('../middleware/auth-unified');
const rbac = require('../middleware/rbac-unified');
const userController = require('../controllers/userController');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const { logUserAction } = require('../middleware/audit');
const userValidators = require('../validators/userValidators');
const { PERMISSIONS, ACTIONS, RESOURCES, SEVERITY } = require('../utils/constants');

const router = express.Router();

router.use(ensureAuthUnified);

router.get('/',
  rbac.hasPermission(PERMISSIONS.USER_READ),
  userValidators.getUsersQuery,
  validateRequest,
  userController.getUsers
);

router.get('/:id',
  validateObjectId(),
  rbac.isSelfOrHasPermission(PERMISSIONS.USER_READ),
  userController.getUserById
);

router.get('/:id/permissions',
  validateObjectId(),
  rbac.isSelfOrHasPermission(PERMISSIONS.USER_READ),
  userController.getUserPermissions
);

router.post('/',
  rbac.hasPermission(PERMISSIONS.USER_CREATE),
  userValidators.createUser,
  validateRequest,
  logUserAction(ACTIONS.CREATE, RESOURCES.USER, SEVERITY.MEDIUM),
  userController.createUser
);

router.patch('/:id',
  validateObjectId(),
  rbac.isSelfOrHasPermission(PERMISSIONS.USER_UPDATE),
  userValidators.updateUser,
  validateRequest,
  logUserAction(ACTIONS.UPDATE, RESOURCES.USER, SEVERITY.MEDIUM),
  userController.updateUser
);

router.delete('/:id',
  validateObjectId(),
  rbac.hasPermission(PERMISSIONS.USER_DELETE),
  logUserAction(ACTIONS.DELETE, RESOURCES.USER, SEVERITY.HIGH),
  userController.deleteUser
);

router.patch('/:id/status',
  validateObjectId(),
  rbac.hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.toggleStatus,
  validateRequest,
  logUserAction(ACTIONS.TOGGLE, RESOURCES.USER, SEVERITY.MEDIUM),
  userController.toggleUserStatus
);

router.put('/:id/roles', ensureAuthUnified, rbac.hasPermission('user:update'), userController.assignRoles);

router.patch('/:id/permissions',
  validateObjectId(),
  rbac.hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.assignPermissions,
  validateRequest,
  logUserAction(ACTIONS.ASSIGN, RESOURCES.USER, SEVERITY.HIGH),
  userController.assignPermissions
);

router.patch('/:id/reset-password',
  validateObjectId(),
  rbac.hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.resetPassword,
  validateRequest,
  logUserAction(ACTIONS.UPDATE, RESOURCES.USER, SEVERITY.CRITICAL),
  userController.resetPassword
);

router.patch('/:id/unlock',
  validateObjectId(),
  rbac.hasPermission(PERMISSIONS.USER_MANAGE),
  logUserAction(ACTIONS.UNLOCK, RESOURCES.USER, SEVERITY.MEDIUM),
  userController.unlockUser
);

module.exports = router;