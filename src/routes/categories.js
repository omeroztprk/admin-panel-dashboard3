const express = require('express');
const categoryController = require('../controllers/categoryController');
const { authenticate } = require('../middleware/auth');
const { hasPermission } = require('../middleware/rbac');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const { logUserAction } = require('../middleware/audit');
const categoryValidators = require('../validators/categoryValidators');
const { PERMISSIONS, ACTIONS, RESOURCES, SEVERITY } = require('../utils/constants');

const router = express.Router();

router.use(authenticate);

router.get('/',
  hasPermission(PERMISSIONS.CATEGORY_READ),
  categoryValidators.getCategoriesQuery,
  validateRequest,
  categoryController.getCategories
);

router.get('/tree',
  hasPermission(PERMISSIONS.CATEGORY_READ),
  categoryValidators.getTreeQuery,
  validateRequest,
  categoryController.getTree
);

router.get('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.CATEGORY_READ),
  categoryController.getCategoryById
);

router.post('/',
  hasPermission(PERMISSIONS.CATEGORY_CREATE),
  categoryValidators.createCategory,
  validateRequest,
  logUserAction(ACTIONS.CREATE, RESOURCES.CATEGORY, SEVERITY.MEDIUM),
  categoryController.createCategory
);

router.patch('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.CATEGORY_UPDATE),
  categoryValidators.updateCategory,
  validateRequest,
  logUserAction(ACTIONS.UPDATE, RESOURCES.CATEGORY, SEVERITY.MEDIUM),
  categoryController.updateCategory
);

router.patch('/:id/status',
  validateObjectId(),
  hasPermission(PERMISSIONS.CATEGORY_MANAGE),
  categoryValidators.toggleStatus,
  validateRequest,
  logUserAction(ACTIONS.TOGGLE, RESOURCES.CATEGORY, SEVERITY.MEDIUM),
  categoryController.toggleCategoryStatus
);

router.patch('/:id/move',
  validateObjectId(),
  hasPermission(PERMISSIONS.CATEGORY_MANAGE),
  categoryValidators.moveCategory,
  validateRequest,
  logUserAction(ACTIONS.MOVE, RESOURCES.CATEGORY, SEVERITY.MEDIUM),
  categoryController.moveCategory
);

router.delete('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.CATEGORY_DELETE),
  logUserAction(ACTIONS.DELETE, RESOURCES.CATEGORY, SEVERITY.HIGH),
  categoryController.deleteCategory
);

module.exports = router;
