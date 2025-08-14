const { query } = require('express-validator');
const config = require('../config');

const MAX_RANGE_DAYS = Number(config.audit?.export?.maxRangeDays || process.env.AUDIT_EXPORT_MAX_RANGE_DAYS) || 31;

const methodValues = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

const commonPaging = [
  query('page').optional().isInt({ min: 1 }).withMessage('errors.validation.invalid_input'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('errors.validation.invalid_input'),
  query('sort').optional().isString().withMessage('errors.validation.invalid_input'),
];

const commonDateRange = [
  query('startDate').optional().isISO8601().withMessage('errors.validation.invalid_input'),
  query('endDate')
    .optional()
    .isISO8601().withMessage('errors.validation.invalid_input')
    .custom((value, { req }) => {
      if (req.query.startDate && new Date(value) < new Date(req.query.startDate)) {
        throw new Error('errors.validation.invalid_input');
      }
      return true;
    }),
];

const getAuditLogsQuery = [
  ...commonPaging,
  query('search').optional().isString().isLength({ min: 2 }).withMessage('errors.validation.invalid_input'),
  query('method').optional().isIn(methodValues).withMessage('errors.validation.invalid_input'),
  query('user').optional().isMongoId().withMessage('errors.validation.invalid_object_id'),
  query('action').optional().isString().withMessage('errors.validation.invalid_input'),
  query('resource').optional().isString().withMessage('errors.validation.invalid_input'),
  query('statusCode').optional().isInt({ min: 100, max: 599 }).toInt().withMessage('errors.validation.invalid_input'),
  query('severity').optional().isIn(['low', 'medium', 'high', 'critical']).withMessage('errors.validation.invalid_input'),
  query('ipAddress').optional().isIP().withMessage('errors.validation.invalid_input'),
  ...commonDateRange,
];

const getLoginAttemptsQuery = [
  ...commonPaging,
  query('ipAddress').optional().isIP().withMessage('errors.validation.invalid_input'),
  query('success').optional().isBoolean().toBoolean().withMessage('errors.validation.invalid_input'),
  ...commonDateRange,
];

const getAuditStatsQuery = [
  query('groupBy').optional().isIn(['hour', 'day', 'week', 'month']).withMessage('errors.validation.invalid_input'),
  query('timezone').optional().isString().withMessage('errors.validation.invalid_input'),
  ...commonDateRange,
];

const getExportLogsQuery = [
  query('format').optional().isIn(['csv', 'json', 'ndjson']).withMessage('errors.validation.invalid_input'),
  query('startDate').exists().withMessage('errors.validation.invalid_input').bail().isISO8601().withMessage('errors.validation.invalid_input'),
  query('endDate')
    .exists().withMessage('errors.validation.invalid_input')
    .bail()
    .isISO8601().withMessage('errors.validation.invalid_input')
    .custom((value, { req }) => {
      const s = new Date(req.query.startDate);
      const e = new Date(value);
      if (Number.isNaN(s.getTime()) || Number.isNaN(e.getTime()) || e < s) {
        throw new Error('errors.validation.invalid_input');
      }
      const diffDays = Math.ceil((e - s) / (24 * 60 * 60 * 1000)) + 1;
      if (diffDays > MAX_RANGE_DAYS) throw new Error('errors.validation.invalid_input');
      return true;
    }),
  query('search').optional().isString().isLength({ min: 2 }).withMessage('errors.validation.invalid_input'),
  query('method').optional().isIn(methodValues).withMessage('errors.validation.invalid_input'),
  query('user').optional().isMongoId().withMessage('errors.validation.invalid_object_id'),
  query('action').optional().isString().withMessage('errors.validation.invalid_input'),
  query('resource').optional().isString().withMessage('errors.validation.invalid_input'),
  query('severity').optional().isIn(['low', 'medium', 'high', 'critical']).withMessage('errors.validation.invalid_input'),
  query('ipAddress').optional().isIP().withMessage('errors.validation.invalid_input'),
  query('statusCode').optional().isInt({ min: 100, max: 599 }).toInt().withMessage('errors.validation.invalid_input'),
];

module.exports = {
  getAuditLogsQuery,
  getLoginAttemptsQuery,
  getAuditStatsQuery,
  getExportLogsQuery,
};
