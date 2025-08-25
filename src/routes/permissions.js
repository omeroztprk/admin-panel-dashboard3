const express = require('express');
const permissionController = require('../controllers/permissionController');
const { ensureAuthUnified } = require('../middleware/auth-unified');
const { hasPermission } = require('../middleware/rbac-unified');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const { logUserAction } = require('../middleware/audit');
const permissionValidators = require('../validators/permissionValidators');
const { PERMISSIONS, ACTIONS, RESOURCES, SEVERITY } = require('../utils/constants');

const router = express.Router();

router.use(ensureAuthUnified);

router.get('/meta/resources',
  hasPermission(PERMISSIONS.PERMISSION_READ),
  permissionController.getAvailableResources
);

router.get('/meta/actions',
  hasPermission(PERMISSIONS.PERMISSION_READ),
  permissionController.getAvailableActions
);

router.get('/meta/categories',
  hasPermission(PERMISSIONS.PERMISSION_READ),
  permissionController.getPermissionCategories
);

router.get('/resource/:resource',
  hasPermission(PERMISSIONS.PERMISSION_READ),
  permissionController.getPermissionsByResource
);

router.get('/',
  hasPermission(PERMISSIONS.PERMISSION_READ),
  permissionValidators.getPermissionsQuery,
  validateRequest,
  permissionController.getPermissions
);

router.get('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.PERMISSION_READ),
  permissionController.getPermissionById
);

router.post('/',
  hasPermission(PERMISSIONS.PERMISSION_CREATE),
  permissionValidators.createPermission,
  validateRequest,
  logUserAction(ACTIONS.CREATE, RESOURCES.PERMISSION, SEVERITY.HIGH),
  permissionController.createPermission
);

router.patch('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.PERMISSION_UPDATE),
  permissionValidators.updatePermission,
  validateRequest,
  logUserAction(ACTIONS.UPDATE, RESOURCES.PERMISSION, SEVERITY.HIGH),
  permissionController.updatePermission
);

router.delete('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.PERMISSION_DELETE),
  logUserAction(ACTIONS.DELETE, RESOURCES.PERMISSION, SEVERITY.CRITICAL),
  permissionController.deletePermission
);

router.patch('/:id/status',
  validateObjectId(),
  hasPermission(PERMISSIONS.PERMISSION_MANAGE),
  permissionValidators.toggleStatus,
  validateRequest,
  logUserAction(ACTIONS.TOGGLE, RESOURCES.PERMISSION, SEVERITY.HIGH),
  permissionController.togglePermissionStatus
);

module.exports = router;