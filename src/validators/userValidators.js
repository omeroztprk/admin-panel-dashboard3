const { body, query } = require('express-validator');
const { supportedLanguages, resolveLanguage } = require('../config/i18n');

const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$/;

const getUsersQuery = [
  query('page').optional().isInt({ min: 1 }).withMessage('errors.validation.invalid_input'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('errors.validation.invalid_input'),
  query('sort').optional().isString().withMessage('errors.validation.invalid_input'),
  query('search').optional().isString().isLength({ min: 2 }).withMessage('errors.validation.invalid_input'),
  query('role').optional().isMongoId().withMessage('errors.validation.invalid_object_id'),
  query('isActive').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
  query('startDate').optional().isISO8601().withMessage('errors.validation.invalid_input'),
  query('endDate').optional().isISO8601().withMessage('errors.validation.invalid_input'),
];

const createUser = [
  body('firstName').trim().isLength({ min: 2, max: 50 }).withMessage('errors.validation.first_name_length'),
  body('lastName').trim().isLength({ min: 2, max: 50 }).withMessage('errors.validation.last_name_length'),
  body('email').isEmail().normalizeEmail().withMessage('errors.validation.invalid_email'),
  body('password')
    .isLength({ min: 8 }).withMessage('errors.validation.password_min_length')
    .matches(strongPasswordRegex).withMessage('errors.validation.password_complexity'),
  body('roles').optional().isArray().withMessage('errors.validation.invalid_input'),
  body('roles.*').optional().isMongoId().withMessage('errors.validation.invalid_object_id'),
  body('permissions').optional().isArray().withMessage('errors.validation.invalid_input'),
  body('permissions.*.permission').optional().isMongoId().withMessage('errors.validation.invalid_object_id'),
  body('permissions.*.granted').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
  body('profile.language')
    .optional()
    .customSanitizer((v) => resolveLanguage(v))
    .isIn(supportedLanguages).withMessage('errors.validation.invalid_input'),
];

const updateUser = [
  body('firstName').optional().trim().isLength({ min: 2, max: 50 }).withMessage('errors.validation.first_name_length'),
  body('lastName').optional().trim().isLength({ min: 2, max: 50 }).withMessage('errors.validation.last_name_length'),
  body('email').optional().isEmail().normalizeEmail().withMessage('errors.validation.invalid_email'),
  // ŞİFRE DOĞRULAMASI EKLENDİ - güncelleme sırasında şifre varsa aynı kurallar geçerli
  body('password')
    .optional()
    .if((value) => value && value.trim()) // Boş değilse kontrol et
    .isLength({ min: 8 }).withMessage('errors.validation.password_min_length')
    .matches(strongPasswordRegex).withMessage('errors.validation.password_complexity'),
  body('roles').optional().isArray().withMessage('errors.validation.invalid_input'),
  body('roles.*').optional().isMongoId().withMessage('errors.validation.invalid_object_id'),
  body('profile.language')
    .optional()
    .customSanitizer((v) => resolveLanguage(v))
    .isIn(supportedLanguages).withMessage('errors.validation.invalid_input'),
];

const toggleStatus = [
  body('isActive').isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const assignRoles = [
  body('roles').isArray().withMessage('errors.validation.invalid_input'),
  body('roles.*').isMongoId().withMessage('errors.validation.invalid_object_id'),
];

const assignPermissions = [
  body('permissions').isArray().withMessage('errors.validation.invalid_input'),
  body('permissions.*.permission').isMongoId().withMessage('errors.validation.invalid_object_id'),
  body('permissions.*.granted').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
];

const resetPassword = [
  body('newPassword')
    .isLength({ min: 8 }).withMessage('errors.validation.password_min_length')
    .matches(strongPasswordRegex).withMessage('errors.validation.password_complexity'),
];

module.exports = {
  getUsersQuery,
  createUser,
  updateUser,
  toggleStatus,
  assignRoles,
  assignPermissions,
  resetPassword,
};
