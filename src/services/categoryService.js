const Category = require('../models/Category');
const { ERRORS } = require('../utils/constants');

const getCategories = async (filters = {}, options = {}) => {
  const { page = 1, limit = 20, sort = 'order' } = options;
  const skip = (page - 1) * limit;

  const categories = await Category.find(filters)
    .populate('parent', 'name slug fullSlug')
    .populate('metadata.createdBy', 'firstName lastName')
    .populate('metadata.updatedBy', 'firstName lastName')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await Category.countDocuments(filters);

  return {
    categories,
    pagination: {
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      totalItems: total,
      itemsPerPage: limit,
      hasNextPage: page < Math.ceil(total / limit),
      hasPrevPage: page > 1
    }
  };
};

const getTree = async (filters = {}, options = {}) => {
  const { maxDepth } = options;

  const categories = await Category.find(filters)
    .sort({ order: 1, name: 1 })
    .lean();

  const categoryMap = new Map();
  const rootCategories = [];

  categories.forEach((cat) => {
    categoryMap.set(String(cat._id), { ...cat, children: [] });
  });

  categories.forEach((cat) => {
    const categoryNode = categoryMap.get(String(cat._id));
    if (cat.parent) {
      const parentNode = categoryMap.get(String(cat.parent));
      if (parentNode) {
        parentNode.children.push(categoryNode);
      }
    } else {
      rootCategories.push(categoryNode);
    }
  });

  if (maxDepth !== undefined && Number.isFinite(+maxDepth)) {
    const trimDepth = (node, depth = 0) => {
      if (depth >= +maxDepth) {
        node.children = [];
        return;
      }
      node.children.forEach((child) => trimDepth(child, depth + 1));
    };
    rootCategories.forEach((root) => trimDepth(root, 0));
  }

  return rootCategories;
};

const getCategoryById = async (categoryId) => {
  const category = await Category.findById(categoryId)
    .populate('parent', 'name slug fullSlug')
    .populate('metadata.createdBy', 'firstName lastName')
    .populate('metadata.updatedBy', 'firstName lastName');

  if (!category) {
    throw new Error(ERRORS.CATEGORY.NOT_FOUND);
  }

  return category;
};

const createCategory = async (categoryData) => {
  const { name, slug, parent, ...otherData } = categoryData;

  if (parent && String(parent) !== 'null') {
    const parentDoc = await Category.findById(parent);
    if (!parentDoc) {
      throw new Error(ERRORS.CATEGORY.INVALID_PARENT);
    }
  }

  let derivedFields;
  if (!parent || String(parent) === 'null') {
    derivedFields = { path: [], fullSlug: slug, level: 0 };
  } else {
    const parentDoc = await Category.findById(parent).select('path fullSlug level');
    if (!parentDoc) {
      throw new Error(ERRORS.CATEGORY.INVALID_PARENT);
    }

    derivedFields = {
      path: [...(parentDoc.path || []), parentDoc._id],
      fullSlug: `${parentDoc.fullSlug}/${slug}`,
      level: (parentDoc.level || 0) + 1
    };
  }

  const category = new Category({
    name,
    slug,
    parent: parent || null,
    ...derivedFields,
    ...otherData
  });

  try {
    await category.save();
  } catch (error) {
    if (error.code === 11000) {
      if (error.message.includes('parent_1_slug_1')) {
        throw new Error(ERRORS.CATEGORY.SLUG_EXISTS);
      }
      if (error.message.includes('parent_1_name_1')) {
        throw new Error(ERRORS.CATEGORY.NAME_EXISTS);
      }
    }
    throw error;
  }

  return getCategoryById(category._id);
};

const updateCategory = async (categoryId, updates) => {
  const existingCategory = await Category.findById(categoryId);
  if (!existingCategory) {
    throw new Error(ERRORS.CATEGORY.NOT_FOUND);
  }

  if (existingCategory.isSystem) {
    throw new Error(ERRORS.CATEGORY.SYSTEM_CATEGORY_MODIFICATION);
  }

  const finalUpdates = { ...updates };
  delete finalUpdates._id;
  delete finalUpdates.__v;

  const parentChanged = Object.prototype.hasOwnProperty.call(finalUpdates, 'parent') &&
    String(finalUpdates.parent || '') !== String(existingCategory.parent || '');
  const slugChanged = finalUpdates.slug && finalUpdates.slug !== existingCategory.slug;

  if (parentChanged || slugChanged) {
    const effectiveParent = (finalUpdates.parent !== undefined) ? (finalUpdates.parent || null) : (existingCategory.parent || null);
    const effectiveSlug = finalUpdates.slug || existingCategory.slug;

    if (effectiveParent) {
      if (String(effectiveParent) === String(categoryId)) {
        throw new Error(ERRORS.CATEGORY.CIRCULAR_PARENT);
      }

      const parentDoc = await Category.findById(effectiveParent).select('path');
      if (!parentDoc) {
        throw new Error(ERRORS.CATEGORY.INVALID_PARENT);
      }

      const parentPathIds = [...(parentDoc.path || []), parentDoc._id].map(String);
      if (parentPathIds.includes(String(categoryId))) {
        throw new Error(ERRORS.CATEGORY.CIRCULAR_PARENT);
      }
    }

    let derivedFields;
    if (!effectiveParent) {
      derivedFields = { path: [], fullSlug: effectiveSlug, level: 0 };
    } else {
      const parentDoc = await Category.findById(effectiveParent).select('path fullSlug level');
      derivedFields = {
        path: [...(parentDoc.path || []), parentDoc._id],
        fullSlug: `${parentDoc.fullSlug}/${effectiveSlug}`,
        level: (parentDoc.level || 0) + 1
      };
    }

    Object.assign(finalUpdates, derivedFields);
  }

  finalUpdates.metadata = {
    ...existingCategory.metadata,
    ...finalUpdates.metadata,
    updatedAt: new Date()
  };

  try {
    await Category.findByIdAndUpdate(categoryId, finalUpdates, { new: true, runValidators: true });
  } catch (error) {
    if (error.code === 11000) {
      if (error.message.includes('parent_1_slug_1')) {
        throw new Error(ERRORS.CATEGORY.SLUG_EXISTS);
      }
      if (error.message.includes('parent_1_name_1')) {
        throw new Error(ERRORS.CATEGORY.NAME_EXISTS);
      }
    }
    throw error;
  }

  if (parentChanged || slugChanged) {
    await updateChildrenHierarchy(categoryId, existingCategory.fullSlug);
  }

  return getCategoryById(categoryId);
};

const updateChildrenHierarchy = async (categoryId, oldFullSlug) => {
  const self = await Category.findById(categoryId).select('fullSlug path level');
  const children = await Category.find({ path: categoryId }).select('_id path fullSlug');

  if (children.length > 0) {
    const bulkOps = children.map((child) => {
      const pathIndex = child.path.map(String).indexOf(String(categoryId));
      const newPath = pathIndex >= 0
        ? [...self.path, self._id, ...child.path.slice(pathIndex + 1)]
        : child.path;

      const newFullSlug = child.fullSlug.replace(new RegExp(`^${oldFullSlug}`), self.fullSlug);

      return {
        updateOne: {
          filter: { _id: child._id },
          update: {
            $set: {
              path: newPath,
              fullSlug: newFullSlug,
              level: newPath.length
            }
          }
        }
      };
    });

    await Category.bulkWrite(bulkOps);
  }
};

const toggleCategoryStatus = async (categoryId, isActive, options = {}) => {
  const { cascade = false, actorId } = options;

  const category = await Category.findById(categoryId);
  if (!category) {
    throw new Error(ERRORS.CATEGORY.NOT_FOUND);
  }

  if (category.isSystem) {
    throw new Error(ERRORS.CATEGORY.SYSTEM_CATEGORY_MODIFICATION);
  }

  const updates = {
    isActive: !!isActive,
    metadata: {
      ...category.metadata,
      updatedBy: actorId,
      updatedAt: new Date()
    }
  };

  await Category.findByIdAndUpdate(categoryId, updates, { new: true, runValidators: true });

  if (cascade) {
    await Category.updateMany(
      { path: categoryId },
      { $set: { isActive: !!isActive } }
    );
  }

  return getCategoryById(categoryId);
};

const moveCategory = async (categoryId, newParentId) => {
  return updateCategory(categoryId, { parent: newParentId || null });
};

const deleteCategory = async (categoryId) => {
  const category = await Category.findById(categoryId);
  if (!category) {
    throw new Error(ERRORS.CATEGORY.NOT_FOUND);
  }

  if (category.isSystem) {
    throw new Error(ERRORS.CATEGORY.SYSTEM_CATEGORY_DELETE);
  }

  const childCount = await Category.countDocuments({ parent: categoryId });
  if (childCount > 0) {
    throw new Error(ERRORS.CATEGORY.HAS_CHILDREN);
  }

  await Category.findByIdAndDelete(categoryId);
  return true;
};

module.exports = {
  getCategories,
  getCategoryById,
  createCategory,
  updateCategory,
  deleteCategory,
  toggleCategoryStatus,
  moveCategory,
  getTree
};
