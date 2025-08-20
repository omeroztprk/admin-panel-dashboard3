const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'errors.validation.role_name_required'],
    unique: true,
    trim: true,
    maxlength: [50, 'errors.validation.role_name_length'],
  },
  displayName: {
    type: String,
    required: [true, 'errors.validation.display_name_required'],
    trim: true,
    maxlength: [100, 'errors.validation.display_name_length'],
  },
  description: { type: String, maxlength: [500, 'errors.validation.description_max'] },

  permissions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Permission' }],

  isSystem: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  priority: { type: Number, default: 0 },

  metadata: {
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
}, {
  timestamps: true,
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

roleSchema.index({ name: 1 }, { unique: true });
roleSchema.index({ isActive: 1 });
roleSchema.index({ priority: -1 });
roleSchema.index({ isActive: 1, priority: -1 });
roleSchema.index({ isSystem: 1, isActive: 1 });
roleSchema.index({ permissions: 1 });

roleSchema.index({ name: 'text', displayName: 'text' }, {
  weights: { name: 5, displayName: 3 },
  name: 'role_text_search',
});

roleSchema.virtual('userCount', {
  ref: 'User',
  localField: '_id',
  foreignField: 'roles',
  count: true,
});

roleSchema.pre('deleteOne', { document: true, query: false }, async function () {
  if (this.isSystem) {
    const error = new Error('errors.role.system_role_delete');
    error.isTranslatable = true;
    throw error;
  }

  const User = mongoose.model('User');
  const userCount = await User.countDocuments({ roles: this._id });
  if (userCount > 0) {
    const error = new Error('errors.role.assigned_to_users');
    error.isTranslatable = true;
    throw error;
  }
});

async function guardOnQueryDelete() {
  const filter = this.getFilter();
  const doc = await this.model.findOne(filter);
  if (!doc) return;

  if (doc.isSystem) {
    const error = new Error('errors.role.system_role_delete');
    error.isTranslatable = true;
    throw error;
  }

  const User = mongoose.model('User');
  const userCount = await User.countDocuments({ roles: doc._id });
  if (userCount > 0) {
    const error = new Error('errors.role.assigned_to_users');
    error.isTranslatable = true;
    throw error;
  }
}

roleSchema.pre('findOneAndDelete', guardOnQueryDelete);
roleSchema.pre('deleteOne', { document: false, query: true }, guardOnQueryDelete);

module.exports = mongoose.model('Role', roleSchema);
