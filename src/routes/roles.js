const express = require('express');
const roleController = require('../controllers/roleController');
const { authenticate } = require('../middleware/auth');
const { hasPermission } = require('../middleware/rbac');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const { logUserAction } = require('../middleware/audit');
const roleValidators = require('../validators/roleValidators');
const { PERMISSIONS, ACTIONS, RESOURCES, SEVERITY } = require('../utils/constants');

const router = express.Router();

router.use(authenticate);

router.get('/',
  hasPermission(PERMISSIONS.ROLE_READ),
  roleValidators.getRolesQuery,
  validateRequest,
  roleController.getRoles
);

router.get('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_READ),
  roleController.getRoleById
);

router.get('/:id/users',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_READ),
  roleValidators.getRoleUsersQuery,
  validateRequest,
  roleController.getRoleUsers
);

router.post('/',
  hasPermission(PERMISSIONS.ROLE_CREATE),
  roleValidators.createRole,
  validateRequest,
  logUserAction(ACTIONS.CREATE, RESOURCES.ROLE, SEVERITY.MEDIUM),
  roleController.createRole
);

router.patch('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_UPDATE),
  roleValidators.updateRole,
  validateRequest,
  logUserAction(ACTIONS.UPDATE, RESOURCES.ROLE, SEVERITY.MEDIUM),
  roleController.updateRole
);

router.delete('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_DELETE),
  logUserAction(ACTIONS.DELETE, RESOURCES.ROLE, SEVERITY.HIGH),
  roleController.deleteRole
);

router.patch('/:id/status',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_MANAGE),
  roleValidators.toggleStatus,
  validateRequest,
  logUserAction(ACTIONS.TOGGLE, RESOURCES.ROLE, SEVERITY.MEDIUM),
  roleController.toggleRoleStatus
);

router.patch('/:id/permissions',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_MANAGE),
  roleValidators.assignPermissions,
  validateRequest,
  logUserAction(ACTIONS.ASSIGN, RESOURCES.ROLE, SEVERITY.HIGH),
  roleController.assignPermissions
);

router.delete('/:id/permissions',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_MANAGE),
  roleValidators.removePermissions,
  validateRequest,
  logUserAction(ACTIONS.REMOVE, RESOURCES.ROLE, SEVERITY.HIGH),
  roleController.removePermissions
);

module.exports = router;