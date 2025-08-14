const { validationResult } = require('express-validator');
const response = require('../utils/response');
const { ERRORS } = require('../utils/constants');

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) return next();

  const errorMessages = errors.array().map((error) => ({
    field: error.path || error.param,
    message: req.t ? req.t(error.msg) : error.msg,
    value: error.value,
  }));

  const validationMessage = req.t ? req.t(ERRORS.VALIDATION.INVALID_INPUT) : 'Invalid input data';
  return response.validationError(res, validationMessage, errorMessages);
};

const validateObjectId = (paramName = 'id') => (req, res, next) => {
  const id = req.params[paramName];
  if (!id || !/^[0-9a-fA-F]{24}$/.test(id)) {
    const message = req.t ? req.t(ERRORS.VALIDATION.INVALID_OBJECT_ID) : 'Invalid ObjectId format';
    return response.error(res, message, 400);
  }
  next();
};

module.exports = { validateRequest, validateObjectId };
