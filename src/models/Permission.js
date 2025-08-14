const mongoose = require('mongoose');
const { RESOURCES, ACTIONS, PERMISSION_CATEGORIES } = require('../utils/constants');

const permissionSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'errors.validation.permission_name_required'],
    unique: true,
    trim: true,
    maxlength: [100, 'errors.validation.permission_name_length'],
    default: function () { return `${this.resource}:${this.action}`; }
  },
  displayName: {
    type: String,
    required: [true, 'errors.validation.display_name_required'],
    trim: true,
    maxlength: [100, 'errors.validation.display_name_length'],
  },
  description: { type: String, maxlength: [500, 'errors.validation.description_max'] },
  resource: {
    type: String,
    required: [true, 'errors.validation.resource_required'],
    enum: { values: Object.values(RESOURCES), message: 'errors.validation.invalid_resource' },
    trim: true,
  },
  action: {
    type: String,
    required: [true, 'errors.validation.action_required'],
    enum: { values: Object.values(ACTIONS), message: 'errors.validation.invalid_action' },
    trim: true,
  },
  category: {
    type: String,
    required: [true, 'errors.validation.category_required'],
    enum: { values: Object.values(PERMISSION_CATEGORIES), message: 'errors.validation.invalid_category' },
    default: PERMISSION_CATEGORIES.USER_MANAGEMENT,
  },
  isSystem: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  metadata: {
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
}, {
  timestamps: true,
  versionKey: false,
});

permissionSchema.index({ name: 1 }, { unique: true });
permissionSchema.index({ resource: 1, action: 1 });
permissionSchema.index({ isActive: 1 });
permissionSchema.index({ category: 1, isActive: 1 });
permissionSchema.index({ resource: 1, action: 1, isActive: 1 });
permissionSchema.index({ isSystem: 1, isActive: 1 });

permissionSchema.index({ name: 'text', displayName: 'text', description: 'text' }, {
  weights: { name: 10, displayName: 5, description: 1 },
});

permissionSchema.pre('deleteOne', { document: true, query: false }, async function () {
  if (this.isSystem) {
    const error = new Error('errors.permission.system_permission_delete');
    error.isTranslatable = true;
    throw error;
  }
  const Role = mongoose.model('Role');
  await Role.updateMany({ permissions: this._id }, { $pull: { permissions: this._id } });

  const User = mongoose.model('User');
  await User.updateMany({ 'permissions.permission': this._id }, { $pull: { permissions: { permission: this._id } } });
});

async function guardAndCleanupOnQueryDelete() {
  const filter = this.getFilter();
  const doc = await this.model.findOne(filter);
  if (!doc) return;

  if (doc.isSystem) {
    const error = new Error('errors.permission.system_permission_delete');
    error.isTranslatable = true;
    throw error;
  }
  const Role = mongoose.model('Role');
  await Role.updateMany({ permissions: doc._id }, { $pull: { permissions: doc._id } });

  const User = mongoose.model('User');
  await User.updateMany({ 'permissions.permission': doc._id }, { $pull: { permissions: { permission: doc._id } } });
}

permissionSchema.pre('findOneAndDelete', guardAndCleanupOnQueryDelete);
permissionSchema.pre('deleteOne', { document: false, query: true }, guardAndCleanupOnQueryDelete);

module.exports = mongoose.model('Permission', permissionSchema);
