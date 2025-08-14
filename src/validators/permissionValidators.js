const { body, query } = require('express-validator');
const { RESOURCES, ACTIONS, PERMISSION_CATEGORIES } = require('../utils/constants');

const getPermissionsQuery = [
  query('page').optional().isInt({ min: 1 }).withMessage('errors.validation.invalid_input'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('errors.validation.invalid_input'),
  query('sort').optional().isString().withMessage('errors.validation.invalid_input'),
  query('search').optional().isString().isLength({ min: 2 }).withMessage('errors.validation.invalid_input'),
  query('resource').optional().isIn(Object.values(RESOURCES)).withMessage('errors.validation.invalid_resource'),
  query('action').optional().isIn(Object.values(ACTIONS)).withMessage('errors.validation.invalid_action'),
  query('category').optional().isIn(Object.values(PERMISSION_CATEGORIES)).withMessage('errors.validation.invalid_category'),
  query('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const createPermission = [
  body('name').optional().trim().isLength({ min: 2, max: 100 }).withMessage('errors.validation.permission_name_length'),
  body('displayName').trim().isLength({ min: 2, max: 100 }).withMessage('errors.validation.display_name_length'),
  body('description').optional().trim().isLength({ max: 500 }).withMessage('errors.validation.description_max'),
  body('resource').isIn(Object.values(RESOURCES)).withMessage('errors.validation.invalid_resource'),
  body('action').isIn(Object.values(ACTIONS)).withMessage('errors.validation.invalid_action'),
  body('category').optional().isIn(Object.values(PERMISSION_CATEGORIES)).withMessage('errors.validation.invalid_category'),
  body('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const updatePermission = [
  body('name').optional().trim().isLength({ min: 2, max: 100 }).withMessage('errors.validation.permission_name_length'),
  body('displayName').optional().trim().isLength({ min: 2, max: 100 }).withMessage('errors.validation.display_name_length'),
  body('description').optional().trim().isLength({ max: 500 }).withMessage('errors.validation.description_max'),
  body('resource').optional().isIn(Object.values(RESOURCES)).withMessage('errors.validation.invalid_resource'),
  body('action').optional().isIn(Object.values(ACTIONS)).withMessage('errors.validation.invalid_action'),
  body('category').optional().isIn(Object.values(PERMISSION_CATEGORIES)).withMessage('errors.validation.invalid_category'),
  body('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const toggleStatus = [body('isActive').isBoolean().toBoolean().withMessage('errors.validation.invalid_input')];

module.exports = {
  getPermissionsQuery,
  createPermission,
  updatePermission,
  toggleStatus,
};
