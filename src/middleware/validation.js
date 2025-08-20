const { validationResult } = require('express-validator');
const response = require('../utils/response');
const { ERRORS } = require('../utils/constants');

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

module.exports = { validateRequest, validateObjectId };
