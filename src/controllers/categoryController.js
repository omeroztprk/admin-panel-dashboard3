const categoryService = require('../services/categoryService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { sanitizeObject, toInt, escapeRegex, isValidObjectId, toBool } = require('../utils/helpers');

const getCategories = asyncHandler(async (req, res) => {
  const filters = {};
  const options = {
    page: Math.max(1, toInt(req.query.page, 1)),
    limit: Math.min(100, Math.max(1, toInt(req.query.limit, 20))),
    sort: req.query.sort || 'order'
  };

  if (req.query.search?.trim()) {
    const re = new RegExp(escapeRegex(req.query.search.trim()), 'i');
    filters.$or = [{ name: { $regex: re } }, { description: { $regex: re } }];
  }
  if (req.query.isActive !== undefined) filters.isActive = toBool(req.query.isActive);
  if (req.query.parent === 'null') filters.parent = null;
  else if (req.query.parent && isValidObjectId(req.query.parent)) filters.parent = req.query.parent;
  if (req.query.level !== undefined && Number.isFinite(+req.query.level)) filters.level = +req.query.level;

  const result = await categoryService.getCategories(filters, options);
  const categories = (result.categories || []).map(sanitizeObject);

  return response.paginated(res, req.t(MESSAGES.GENERAL.SUCCESS), { categories }, result.pagination);
});

const getTree = asyncHandler(async (req, res) => {
  const filters = {};
  const maxDepth = req.query.maxDepth;

  if (req.query.isActive !== undefined) {
    filters.isActive = toBool(req.query.isActive);
  }

  const tree = await categoryService.getTree(filters, { maxDepth });
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { tree });
});

const getCategoryById = asyncHandler(async (req, res) => {
  const category = await categoryService.getCategoryById(req.params.id);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { category: sanitizeObject(category) });
});

const createCategory = asyncHandler(async (req, res) => {
  const categoryData = {
    ...req.body,
    metadata: { createdBy: req.user._id }
  };

  const category = await categoryService.createCategory(categoryData);
  return response.created(res, req.t(MESSAGES.CATEGORY.CREATED), { category: sanitizeObject(category) });
});

const updateCategory = asyncHandler(async (req, res) => {
  const updates = {
    ...req.body,
    metadata: { updatedBy: req.user._id }
  };

  const category = await categoryService.updateCategory(req.params.id, updates);
  return response.success(res, req.t(MESSAGES.CATEGORY.UPDATED), { category: sanitizeObject(category) });
});

const deleteCategory = asyncHandler(async (req, res) => {
  await categoryService.deleteCategory(req.params.id);
  return response.success(res, req.t(MESSAGES.CATEGORY.DELETED));
});

const toggleCategoryStatus = asyncHandler(async (req, res) => {
  const category = await categoryService.toggleCategoryStatus(
    req.params.id,
    req.body.isActive,
    { cascade: toBool(req.body.cascade, false), actorId: req.user._id }
  );
  return response.success(res, req.t(MESSAGES.CATEGORY.STATUS_UPDATED), { category: sanitizeObject(category) });
});

const moveCategory = asyncHandler(async (req, res) => {
  const category = await categoryService.moveCategory(req.params.id, req.body.newParent);
  return response.success(res, req.t(MESSAGES.CATEGORY.MOVED), { category: sanitizeObject(category) });
});

module.exports = {
  getCategories,
  getTree,
  getCategoryById,
  createCategory,
  updateCategory,
  deleteCategory,
  toggleCategoryStatus,
  moveCategory
};
