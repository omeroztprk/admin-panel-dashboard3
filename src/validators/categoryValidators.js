const { body, query } = require('express-validator');

const getCategoriesQuery = [
  query('page').optional().isInt({ min: 1 }).withMessage('errors.validation.invalid_input'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('errors.validation.invalid_input'),
  query('sort').optional().isString().withMessage('errors.validation.invalid_input'),
  query('search').optional().isString().isLength({ min: 2 }).withMessage('errors.validation.invalid_input'),
  query('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
  query('parent').optional().isMongoId().withMessage('errors.validation.invalid_object_id'),
  query('level').optional().isInt({ min: 0, max: 32 }).withMessage('errors.validation.invalid_input'),
];

const getTreeQuery = [
  query('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
  query('maxDepth').optional().isInt({ min: 0, max: 32 }).withMessage('errors.validation.invalid_input'),
];

const createCategory = [
  body('name').trim().isLength({ min: 2, max: 100 }).withMessage('errors.validation.category_name_length'),
  body('slug').trim().notEmpty().withMessage('errors.validation.slug_required')
    .matches(/^[a-z0-9-]+$/).withMessage('errors.validation.slug_format'),
  body('description').optional().trim().isLength({ max: 500 }).withMessage('errors.validation.description_max'),
  body('parent').optional({ nullable: true }).isMongoId().withMessage('errors.validation.invalid_object_id'),
  body('order').optional().isInt({ min: 0, max: 10000 }).withMessage('errors.validation.order_range'),
  body('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const updateCategory = [
  body('name').optional().trim().isLength({ min: 2, max: 100 }).withMessage('errors.validation.category_name_length'),
  body('slug').optional().trim().matches(/^[a-z0-9-]+$/).withMessage('errors.validation.slug_format'),
  body('description').optional().trim().isLength({ max: 500 }).withMessage('errors.validation.description_max'),
  body('parent').optional({ nullable: true }).custom((v) => (v === null || typeof v === 'string')).withMessage('errors.validation.invalid_input'),
  body('order').optional().isInt({ min: 0, max: 10000 }).withMessage('errors.validation.order_range'),
  body('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const toggleStatus = [
  body('isActive').isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
  body('cascade').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const moveCategory = [
  body('newParent').optional({ nullable: true }).custom((v) => (v === null || typeof v === 'string')).withMessage('errors.validation.invalid_input'),
];

module.exports = {
  getCategoriesQuery,
  getTreeQuery,
  createCategory,
  updateCategory,
  toggleStatus,
  moveCategory,
};
