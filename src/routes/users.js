const express = require('express');
const userController = require('../controllers/userController');
const { authenticate } = require('../middleware/auth');
const { hasPermission, isSelfOrHasPermission } = require('../middleware/rbac');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const userValidators = require('../validators/userValidators');
const { PERMISSIONS } = require('../utils/constants');

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

router.post('/',
  hasPermission(PERMISSIONS.USER_CREATE),
  userValidators.createUser,
  validateRequest,
  userController.createUser
);

router.patch('/:id',
  validateObjectId(),
  isSelfOrHasPermission(PERMISSIONS.USER_UPDATE),
  userValidators.updateUser,
  validateRequest,
  userController.updateUser
);

router.delete('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_DELETE),
  userController.deleteUser
);

router.patch('/:id/status',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.toggleStatus,
  validateRequest,
  userController.toggleUserStatus
);

router.patch('/:id/roles',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.assignRoles,
  validateRequest,
  userController.assignRoles
);

router.patch('/:id/permissions',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.assignPermissions,
  validateRequest,
  userController.assignPermissions
);

router.get('/:id/permissions',
  validateObjectId(),
  isSelfOrHasPermission(PERMISSIONS.USER_READ),
  userController.getUserPermissions
);

router.patch('/:id/reset-password',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  userValidators.resetPassword,
  validateRequest,
  userController.resetPassword
);

router.patch('/:id/unlock',
  validateObjectId(),
  hasPermission(PERMISSIONS.USER_MANAGE),
  userController.unlockUser
);

module.exports = router;