const { body } = require('express-validator');
const { supportedLanguages, resolveLanguage } = require('../config/i18n');

const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$/;

const register = [
  body('firstName').trim().isLength({ min: 2, max: 50 }).withMessage('errors.validation.first_name_length'),
  body('lastName').trim().isLength({ min: 2, max: 50 }).withMessage('errors.validation.last_name_length'),
  body('email').isEmail().normalizeEmail().withMessage('errors.validation.invalid_email'),
  body('password')
    .isLength({ min: 8 }).withMessage('errors.validation.password_min_length')
    .matches(strongPasswordRegex).withMessage('errors.validation.password_complexity'),
  body('profile.language')
    .optional()
    .customSanitizer((v) => resolveLanguage(v))
    .isIn(supportedLanguages).withMessage('errors.validation.invalid_input'),
];

const login = [
  body('email').isEmail().normalizeEmail().withMessage('errors.validation.invalid_email'),
  body('password').notEmpty().withMessage('errors.validation.password_required'),
];

const refreshToken = [body('refreshToken').notEmpty().withMessage('errors.auth.refresh_token_missing')];

const logout = [body('refreshToken').optional().isString().withMessage('errors.validation.invalid_input')];

const updateProfile = [
  body('firstName').optional().trim().isLength({ min: 2, max: 50 }).withMessage('errors.validation.first_name_length'),
  body('lastName').optional().trim().isLength({ min: 2, max: 50 }).withMessage('errors.validation.last_name_length'),
  body('profile.phone').optional().isMobilePhone('any').withMessage('errors.validation.invalid_input'),
  body('profile.timezone').optional().isString().withMessage('errors.validation.invalid_input'),
  body('profile.language')
    .optional()
    .customSanitizer((v) => resolveLanguage(v))
    .isIn(supportedLanguages).withMessage('errors.validation.invalid_input'),
];

const changePassword = [
  body('currentPassword').notEmpty().withMessage('errors.validation.current_password_required'),
  body('newPassword')
    .isLength({ min: 8 }).withMessage('errors.validation.password_min_length')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,128}$/).withMessage('errors.validation.password_complexity'),
];

const verifyTfa = [
  body('email').isEmail().normalizeEmail().withMessage('errors.validation.invalid_email'),
  body('tfaCode')
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('errors.auth.tfa_invalid_code'),
];

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  updateProfile,
  changePassword,
  verifyTfa,
};
