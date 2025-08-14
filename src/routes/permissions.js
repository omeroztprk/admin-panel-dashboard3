const express = require('express');
const permissionController = require('../controllers/permissionController');
const { authenticate } = require('../middleware/auth');
const { hasPermission } = require('../middleware/rbac');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const permissionValidators = require('../validators/permissionValidators');
const { PERMISSIONS } = require('../utils/constants');

const router = express.Router();

router.use(authenticate);

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
  permissionController.createPermission
);

router.patch('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.PERMISSION_UPDATE),
  permissionValidators.updatePermission,
  validateRequest,
  permissionController.updatePermission
);

router.delete('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.PERMISSION_DELETE),
  permissionController.deletePermission
);

router.patch('/:id/status',
  validateObjectId(),
  hasPermission(PERMISSIONS.PERMISSION_MANAGE),
  permissionValidators.toggleStatus,
  validateRequest,
  permissionController.togglePermissionStatus
);

module.exports = router;