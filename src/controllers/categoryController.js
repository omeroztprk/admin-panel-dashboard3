const auditService = require('../services/auditService');
const categoryService = require('../services/categoryService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { getClientIP, toInt, toBool, sanitizeObject } = require('../utils/helpers');

const getCategories = asyncHandler(async (req, res) => {
  const {
    page = 1, limit = 20, sort = 'order',
    search, isActive, parent, level
  } = req.query;

  const result = await categoryService.getCategories({
    page: toInt(page, 1),
    limit: toInt(limit, 20),
    sort: sort || 'order',
    search,
    isActive: (isActive !== undefined) ? toBool(isActive) : undefined,
    parent: (parent === 'null') ? null : parent,
    level: (level !== undefined) ? toInt(level) : undefined,
  });

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const getTree = asyncHandler(async (req, res) => {
  const { isActive } = req.query;
  const maxDepthRaw = (req.query.maxDepth !== undefined) ? req.query.maxDepth : req.query.depth;

  const tree = await categoryService.getTree({
    isActive: (isActive !== undefined) ? toBool(isActive) : undefined,
    maxDepth: (maxDepthRaw !== undefined) ? toInt(maxDepthRaw) : undefined,
  });

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { tree });
});

const getCategoryById = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const cat = await categoryService.getCategoryById(id);
  if (!cat) return response.notFound(res, req.t(ERRORS.CATEGORY.NOT_FOUND));
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { category: cat });
});

const createCategory = asyncHandler(async (req, res) => {
  const payload = {
    ...req.body,
    metadata: { createdBy: req.user._id }
  };
  const cat = await categoryService.createCategory(payload);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'create',
    resource: 'category',
    resourceId: cat._id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 201,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { after: sanitizeObject(payload, ['__v']) },
    severity: 'medium'
  });

  return response.created(res, req.t(MESSAGES.CATEGORY.CREATED), { category: cat });
});

const updateCategory = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const before = await categoryService.getCategoryById(id);
  if (!before) return response.notFound(res, req.t(ERRORS.CATEGORY.NOT_FOUND));

  const updates = {
    ...req.body,
    metadata: { ...(before.metadata || {}), updatedBy: req.user._id, updatedAt: new Date() }
  };

  const cat = await categoryService.updateCategory(id, updates);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'update',
    resource: 'category',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: sanitizeObject(before, ['__v']), after: sanitizeObject(updates, ['__v']) },
    severity: 'medium'
  });

  return response.success(res, req.t(MESSAGES.CATEGORY.UPDATED), { category: cat });
});

const toggleCategoryStatus = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { isActive, cascade = false } = req.body;

  if (typeof isActive !== 'boolean') {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const before = await categoryService.getCategoryById(id);
  if (!before) return response.notFound(res, req.t(ERRORS.CATEGORY.NOT_FOUND));

  const cat = await categoryService.toggleCategoryStatus(id, isActive, { cascade: !!cascade });

  await auditService.logUserAction({
    user: req.user._id,
    action: isActive ? 'activate' : 'deactivate',
    resource: 'category',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: { isActive: before.isActive }, after: { isActive, cascade: !!cascade } },
    severity: 'medium'
  });

  return response.success(res, req.t(MESSAGES.CATEGORY.STATUS_UPDATED), { category: cat });
});

const moveCategory = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { newParent } = req.body;

  const before = await categoryService.getCategoryById(id);
  if (!before) return response.notFound(res, req.t(ERRORS.CATEGORY.NOT_FOUND));

  const cat = await categoryService.moveCategory(id, newParent || null);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'move',
    resource: 'category',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: { parent: before.parent }, after: { parent: newParent || null } },
    severity: 'medium'
  });

  return response.success(res, req.t(MESSAGES.CATEGORY.MOVED), { category: cat });
});

const deleteCategory = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const before = await categoryService.getCategoryById(id);
  if (!before) return response.notFound(res, req.t(ERRORS.CATEGORY.NOT_FOUND));

  await categoryService.deleteCategory(id);

  await auditService.logUserAction({
    user: req.user._id,
    action: 'delete',
    resource: 'category',
    resourceId: id,
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { before: sanitizeObject(before, ['__v']) },
    severity: 'high'
  });

  return response.success(res, req.t(MESSAGES.CATEGORY.DELETED));
});

module.exports = {
  getCategories,
  getTree,
  getCategoryById,
  createCategory,
  updateCategory,
  toggleCategoryStatus,
  moveCategory,
  deleteCategory,
};
