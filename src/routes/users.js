const express = require('express');
const userController = require('../controllers/userController');
const { authenticate } = require('../middleware/auth');
const { hasPermission, isSelfOrHasPermission } = require('../middleware/rbac');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const { logUserAction } = require('../middleware/audit');
const userValidators = require('../validators/userValidators');
const { PERMISSIONS, ACTIONS, RESOURCES, SEVERITY } = require('../utils/constants');

const router = express.Router();

router.use(authenticate);

router.get('/',
  hasPermission(PERMISSIONS.USER_READ),
  userValidators.getUsersQuery,
  validateRequest,
  userController.getUsers
);

router.get('/:id',
  validateObjectId(),
  isSelfOrHasPermission(PERMISSIONS.USER_READ),
  userController.getUserById
);

router.get('/:id/permissions',
  validateObjectId(),
  isSelfOrHasPermission(PERMISSIONS.USER_READ),
  userController.getUserPermissions
);

router.post('/',
  hasPermission(PERMISSIONS.USER_CREATE),
  userValidators.createUser,
  validateRequest,
  logUserAction(ACTIONS.CREATE, RESOURCES.USER, SEVERITY.MEDIUM),
  userController.createUser
);

router.patch('/:id',
  validateObjectId(),
  isSelfOrHasPermission(PERMISSIONS.USER_UPDATE),
  userValidators.updateUser,
  validateRequest,
  logUserAction(ACTIONS.UPDATE, RESOURCES.USER, SEVERITY.MEDIUM),
  userController.updateUser
);

router.delete('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_DELETE),
  logUserAction(ACTIONS.DELETE, RESOURCES.USER, SEVERITY.HIGH),
  userController.deleteUser
);

router.patch('/:id/status',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.toggleStatus,
  validateRequest,
  logUserAction(ACTIONS.TOGGLE, RESOURCES.USER, SEVERITY.MEDIUM),
  userController.toggleUserStatus
);

router.patch('/:id/roles',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.assignRoles,
  validateRequest,
  logUserAction(ACTIONS.ASSIGN, RESOURCES.USER, SEVERITY.HIGH),
  userController.assignRoles
);

router.patch('/:id/permissions',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.assignPermissions,
  validateRequest,
  logUserAction(ACTIONS.ASSIGN, RESOURCES.USER, SEVERITY.HIGH),
  userController.assignPermissions
);

router.patch('/:id/reset-password',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.resetPassword,
  validateRequest,
  logUserAction(ACTIONS.UPDATE, RESOURCES.USER, SEVERITY.CRITICAL),
  userController.resetPassword
);

router.patch('/:id/unlock',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  logUserAction(ACTIONS.UNLOCK, RESOURCES.USER, SEVERITY.MEDIUM),
  userController.unlockUser
);

module.exports = router;