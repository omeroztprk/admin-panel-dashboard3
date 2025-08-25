const { validationResult } = require('express-validator');
const response = require('../utils/response');
const { ERRORS } = require('../utils/constants');
const { isValidObjectId } = require('../utils/helpers');

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) return next();

  const errorMessages = errors.array().map((error) => ({
    field: error.path || error.param,
    message: req.t(error.msg),
    value: typeof error.value === 'string'
      ? error.value.slice(0, 100)
      : (error.value !== null && error.value !== undefined)
        ? String(error.value).slice(0, 100)
        : error.value
  }));

  return response.validationError(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), errorMessages);
};

const validateObjectId = (paramName = 'id') => (req, res, next) => {
  const id = req.params[paramName];
  if (!id || !/^[0-9a-fA-F]{24}$/.test(id)) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_OBJECT_ID), 400);
  }
  next();
};

function validateSessionId(paramName = 'tokenId') {
  return (req, res, next) => {
    const v = String(req.params[paramName] || '');
    const isKc = /^kc-session-[A-Za-z0-9._:\-]+$/.test(v);
    if (isKc || isValidObjectId(v)) return next();
    return res.status(400).json({ message: 'Invalid session id format' });
  };
}

module.exports = { validateRequest, validateObjectId, validateSessionId };
