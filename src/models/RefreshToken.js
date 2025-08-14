const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true, unique: true },
  jti: { type: String, required: true, unique: true },

  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },

  expiresAt: { type: Date, required: true, index: true },
  isBlacklisted: { type: Boolean, default: false, index: true },

  deviceInfo: {
    userAgent: String,
    ipAddress: String,
    deviceId: { type: String, index: true },
    platform: String,
    browser: String,
  },

  lastUsed: { type: Date, default: Date.now, index: true },
}, {
  timestamps: true,
  versionKey: false,
});

refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
refreshTokenSchema.index({ user: 1, isBlacklisted: 1, expiresAt: 1 });

refreshTokenSchema.virtual('isExpired').get(function () {
  return Date.now() >= this.expiresAt.getTime();
});

refreshTokenSchema.virtual('isValid').get(function () {
  return !this.isBlacklisted && !this.isExpired;
});

refreshTokenSchema.methods.blacklist = async function () {
  this.isBlacklisted = true;
  return this.save();
};

refreshTokenSchema.statics.cleanupExpired = async function () {
  return this.deleteMany({
    $or: [
      { expiresAt: { $lte: new Date() } },
      { isBlacklisted: true, updatedAt: { $lte: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
    ],
  });
};

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);