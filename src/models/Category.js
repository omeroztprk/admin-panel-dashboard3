const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'errors.validation.category_name_length'],
    trim: true,
    minlength: [2, 'errors.validation.category_name_length'],
    maxlength: [100, 'errors.validation.category_name_length'],
  },
  slug: {
    type: String,
    required: [true, 'errors.validation.slug_required'],
    trim: true,
    lowercase: true,
    match: [/^[a-z0-9-]+$/, 'errors.validation.slug_format'],
  },
  description: { type: String, maxlength: [500, 'errors.validation.description_max'] },
  parent: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', default: null },

  path: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Category' }],
  fullSlug: { type: String, index: true },
  level: { type: Number, default: 0 },

  order: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  isSystem: { type: Boolean, default: false },

  metadata: {
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
}, {
  timestamps: true,
  versionKey: false,
});

categorySchema.index({ parent: 1, name: 1 }, { unique: true });
categorySchema.index({ parent: 1, slug: 1 }, { unique: true });
categorySchema.index({ isActive: 1, order: 1, createdAt: -1 });
categorySchema.index({ name: 'text', description: 'text' }, { 
  weights: { name: 5, description: 3 },
  name: 'category_text_search'
});

categorySchema.pre('deleteOne', { document: true, query: false }, async function () {
  if (this.isSystem) {
    const err = new Error('errors.category.system_category_delete');
    err.isTranslatable = true;
    throw err;
  }
  const Category = this.constructor;
  const childCount = await Category.countDocuments({ parent: this._id });
  if (childCount > 0) {
    const err = new Error('errors.category.has_children');
    err.isTranslatable = true;
    throw err;
  }
});

async function guardOnQueryDelete() {
  const filter = this.getFilter();
  const doc = await this.model.findOne(filter).select('isSystem');
  if (!doc) return;

  if (doc.isSystem) {
    const err = new Error('errors.category.system_category_delete');
    err.isTranslatable = true;
    throw err;
  }
  const Category = this.model;
  const childCount = await Category.countDocuments({ parent: doc._id });
  if (childCount > 0) {
    const err = new Error('errors.category.has_children');
    err.isTranslatable = true;
    throw err;
  }
}

categorySchema.pre('findOneAndDelete', guardOnQueryDelete);
categorySchema.pre('deleteOne', { document: false, query: true }, guardOnQueryDelete);

module.exports = mongoose.model('Category', categorySchema);
