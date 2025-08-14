const { body, query } = require('express-validator');

const getRolesQuery = [
  query('page').optional().isInt({ min: 1 }).withMessage('errors.validation.invalid_input'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('errors.validation.invalid_input'),
  query('sort').optional().isString().withMessage('errors.validation.invalid_input'),
  query('search').optional().isString().isLength({ min: 2 }).withMessage('errors.validation.invalid_input'),
  query('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
  query('includePermissions').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const createRole = [
  body('name').trim()
    .isLength({ min: 2, max: 50 }).withMessage('errors.validation.role_name_length')
    .matches(/^[a-zA-Z0-9_-]+$/).withMessage('errors.validation.invalid_input'),
  body('displayName').trim().isLength({ min: 2, max: 100 }).withMessage('errors.validation.display_name_length'),
  body('description').optional().trim().isLength({ max: 500 }).withMessage('errors.validation.description_max'),
  body('priority').optional().isInt({ min: 0, max: 100 }).withMessage('errors.validation.invalid_input'),
  body('permissions').optional().isArray().withMessage('errors.validation.invalid_input'),
  body('permissions.*').optional().isMongoId().withMessage('errors.validation.invalid_object_id'),
  body('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const updateRole = [
  body('name').optional().trim()
    .isLength({ min: 2, max: 50 }).withMessage('errors.validation.role_name_length')
    .matches(/^[a-zA-Z0-9_-]+$/).withMessage('errors.validation.invalid_input'),
  body('displayName').optional().trim().isLength({ min: 2, max: 100 }).withMessage('errors.validation.display_name_length'),
  body('description').optional().trim().isLength({ max: 500 }).withMessage('errors.validation.description_max'),
  body('priority').optional().isInt({ min: 0, max: 100 }).withMessage('errors.validation.invalid_input'),
  body('permissions').optional().isArray().withMessage('errors.validation.invalid_input'),
  body('permissions.*').optional().isMongoId().withMessage('errors.validation.invalid_object_id'),
  body('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const toggleStatus = [body('isActive').isBoolean().toBoolean().withMessage('errors.validation.invalid_input')];

const assignPermissions = [
  body('permissions').isArray().withMessage('errors.validation.invalid_input'),
  body('permissions.*').isMongoId().withMessage('errors.validation.invalid_object_id'),
];

const removePermissions = [
  body('permissions').isArray().withMessage('errors.validation.invalid_input'),
  body('permissions.*').isMongoId().withMessage('errors.validation.invalid_object_id'),
];

const getRoleUsersQuery = [
  query('page').optional().isInt({ min: 1 }).withMessage('errors.validation.invalid_input'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('errors.validation.invalid_input'),
  query('sort').optional().isString().withMessage('errors.validation.invalid_input'),
];

module.exports = {
  getRolesQuery,
  createRole,
  updateRole,
  toggleStatus,
  assignPermissions,
  removePermissions,
  getRoleUsersQuery,
};
