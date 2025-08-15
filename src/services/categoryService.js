const Category = require('../models/Category');
const { ERRORS } = require('../utils/constants');
const { isValidObjectId, escapeRegex } = require('../utils/helpers');

const buildDerived = async (parentId, slug) => {
  if (!parentId) return { path: [], fullSlug: slug, level: 0 };

  const parent = await Category.findById(parentId).select('path fullSlug level');
  if (!parent) throw new Error(ERRORS.CATEGORY.INVALID_PARENT);

  return {
    path: [...(parent.path || []), parent._id],
    fullSlug: `${parent.fullSlug}/${slug}`,
    level: (parent.level || 0) + 1,
  };
};

const checkCircular = (parentId, selfId) => {
  if (!parentId || !selfId) return false;
  return String(parentId) === String(selfId);
};

const getCategories = async (options = {}) => {
  const {
    page = 1, limit = 20, sort = 'order', search, isActive, parent, level
  } = options;

  const query = {};
  if (search && search.trim()) {
    const re = new RegExp(escapeRegex(search.trim()), 'i');
    query.$or = [{ name: { $regex: re } }, { description: { $regex: re } }];
  }
  if (typeof isActive === 'boolean') query.isActive = isActive;
  if (parent === null) query.parent = null;
  else if (parent && isValidObjectId(parent)) query.parent = parent;
  if (level !== undefined && Number.isFinite(+level)) query.level = +level;

  const skip = (page - 1) * limit;
  const categories = await Category.find(query)
    .populate('parent', 'name slug fullSlug')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await Category.countDocuments(query);

  return {
    categories,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  };
};

const getCategoryById = async (id) => {
  if (!isValidObjectId(id)) return null;
  return Category.findById(id)
    .populate('parent', 'name slug fullSlug')
    .lean();
};

const createCategory = async (data) => {
  const { name, slug, parent, ...rest } = data;

  if (checkCircular(parent, null)) throw new Error(ERRORS.CATEGORY.INVALID_PARENT);

  const derived = await buildDerived(parent || null, slug);

  const doc = new Category({
    name,
    slug,
    parent: parent || null,
    ...derived,
    ...rest,
  });

  try {
    await doc.save();
  } catch (e) {
    const msg = String(e?.message || '');
    if (msg.includes('E11000') && msg.includes('index') && msg.includes('parent_1_slug_1')) {
      throw new Error(ERRORS.CATEGORY.SLUG_EXISTS);
    }
    if (msg.includes('E11000') && msg.includes('index') && msg.includes('parent_1_name_1')) {
      throw new Error(ERRORS.CATEGORY.NAME_EXISTS);
    }
    throw e;
  }

  return getCategoryById(doc._id);
};

const updateCategory = async (id, updates) => {
  const existing = await Category.findById(id);
  if (!existing) throw new Error(ERRORS.CATEGORY.NOT_FOUND);
  if (existing.isSystem) throw new Error(ERRORS.CATEGORY.SYSTEM_CATEGORY_MODIFICATION);

  const next = { ...updates };
  delete next._id; delete next.__v;

  let parentChanged = false;
  let slugChanged = false;

  if (Object.prototype.hasOwnProperty.call(next, 'parent')) {
    const newParent = next.parent || null;
    if (checkCircular(newParent, id)) throw new Error(ERRORS.CATEGORY.INVALID_PARENT);
    parentChanged = String(existing.parent || '') !== String(newParent || '');
  }

  if (next.slug && next.slug !== existing.slug) slugChanged = true;

  if (parentChanged || slugChanged) {
    const effectiveParent = (next.parent !== undefined) ? (next.parent || null) : (existing.parent || null);
    const effectiveSlug = next.slug || existing.slug;

    if (effectiveParent) {
      const parentDoc = await Category.findById(effectiveParent).select('_id path');
      if (!parentDoc) throw new Error(ERRORS.CATEGORY.INVALID_PARENT);
      const parentPathIds = [...(parentDoc.path || []), parentDoc._id].map(String);
      if (parentPathIds.includes(String(id))) throw new Error(ERRORS.CATEGORY.CIRCULAR_PARENT);
    }

    const derived = await buildDerived(effectiveParent, effectiveSlug);
    next.path = derived.path;
    next.fullSlug = derived.fullSlug;
    next.level = derived.level;
  }

  try {
    await Category.findByIdAndUpdate(id, next, { new: true, runValidators: true });
  } catch (e) {
    const msg = String(e?.message || '');
    if (msg.includes('E11000') && msg.includes('parent_1_slug_1')) throw new Error(ERRORS.CATEGORY.SLUG_EXISTS);
    if (msg.includes('E11000') && msg.includes('parent_1_name_1')) throw new Error(ERRORS.CATEGORY.NAME_EXISTS);
    throw e;
  }

  if (parentChanged || slugChanged) {
    const self = await Category.findById(id).select('fullSlug path level');
    const children = await Category.find({ path: id }).select('_id parent slug path fullSlug level');

    if (children.length) {
      const bulk = [];
      for (const child of children) {
        const idx = child.path.map(String).indexOf(String(id));
        const tail = idx >= 0 ? child.path.slice(idx + 1) : [];
        const newPath = [...self.path, self._id, ...tail];

        const oldPrefix = existing.fullSlug;
        const newPrefix = self.fullSlug;
        const newFullSlug = child.fullSlug.replace(new RegExp(`^${oldPrefix}`), newPrefix);

        bulk.push({
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
        });
      }
      if (bulk.length) await Category.bulkWrite(bulk);
    }
  }

  return getCategoryById(id);
};

const toggleCategoryStatus = async (id, isActive, { cascade = false } = {}) => {
  const cat = await Category.findById(id);
  if (!cat) throw new Error(ERRORS.CATEGORY.NOT_FOUND);
  if (cat.isSystem) throw new Error(ERRORS.CATEGORY.SYSTEM_CATEGORY_MODIFICATION);

  cat.isActive = !!isActive;
  await cat.save();

  if (cascade) {
    await Category.updateMany({ path: id }, { $set: { isActive: !!isActive } });
  }
  return getCategoryById(id);
};

const moveCategory = async (id, newParentId) => {
  return updateCategory(id, { parent: newParentId || null });
};

const deleteCategory = async (id) => {
  const cat = await Category.findById(id);
  if (!cat) throw new Error(ERRORS.CATEGORY.NOT_FOUND);
  await cat.deleteOne();
  return true;
};

const getTree = async ({ isActive, maxDepth } = {}) => {
  const q = {};
  if (typeof isActive === 'boolean') q.isActive = isActive;
  const all = await Category.find(q).sort({ order: 1, name: 1 }).lean();

  const byId = new Map(all.map(c => [String(c._id), { ...c, children: [] }]));
  const roots = [];

  for (const c of byId.values()) {
    if (c.parent) {
      const p = byId.get(String(c.parent));
      if (p) p.children.push(c);
    } else roots.push(c);
  }

  if (Number.isFinite(maxDepth)) {
    const trim = (node, depth = 0) => {
      if (depth >= maxDepth) { node.children = []; return; }
      node.children.forEach(n => trim(n, depth + 1));
    };
    roots.forEach(r => trim(r, 0));
  }

  return roots;
};

module.exports = {
  getCategories,
  getCategoryById,
  createCategory,
  updateCategory,
  toggleCategoryStatus,
  moveCategory,
  deleteCategory,
  getTree,
};
