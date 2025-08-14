const express = require('express');
const roleController = require('../controllers/roleController');
const { authenticate } = require('../middleware/auth');
const { hasPermission } = require('../middleware/rbac');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const roleValidators = require('../validators/roleValidators');
const { PERMISSIONS } = require('../utils/constants');

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

router.post('/',
  hasPermission(PERMISSIONS.ROLE_CREATE),
  roleValidators.createRole,
  validateRequest,
  roleController.createRole
);

router.patch('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_UPDATE),
  roleValidators.updateRole,
  validateRequest,
  roleController.updateRole
);

router.delete('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_DELETE),
  roleController.deleteRole
);

router.patch('/:id/status',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_MANAGE),
  roleValidators.toggleStatus,
  validateRequest,
  roleController.toggleRoleStatus
);

router.patch('/:id/permissions',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_MANAGE),
  roleValidators.assignPermissions,
  validateRequest,
  roleController.assignPermissions
);

router.delete('/:id/permissions',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_MANAGE),
  roleValidators.removePermissions,
  validateRequest,
  roleController.removePermissions
);

router.get('/:id/users',
  validateObjectId(),
  hasPermission(PERMISSIONS.ROLE_READ),
  roleValidators.getRoleUsersQuery,
  validateRequest,
  roleController.getRoleUsers
);

module.exports = router;