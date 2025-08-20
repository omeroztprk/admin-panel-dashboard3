const mongoose = require('mongoose');
const logger = require('../utils/logger');
const config = require('../config');
const { SEVERITY } = require('../utils/constants');
const { escapeRegex, isValidObjectId } = require('../utils/helpers');

const auditLogSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },

  action: { type: String, required: [true, 'errors.validation.action_required'], trim: true },
  resource: { type: String, required: [true, 'errors.validation.resource_required'], trim: true },
  resourceId: { type: String, trim: true },

  method: { type: String, enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], required: true },
  endpoint: { type: String, required: true },
  statusCode: { type: Number, required: true },

  userAgent: String,
  ipAddress: { type: String, required: true },
  sessionId: String,

  requestData: {
    query: mongoose.Schema.Types.Mixed,
    body: mongoose.Schema.Types.Mixed,
    params: mongoose.Schema.Types.Mixed,
  },
  responseData: mongoose.Schema.Types.Mixed,
  changes: {
    before: mongoose.Schema.Types.Mixed,
    after: mongoose.Schema.Types.Mixed,
  },

  duration: Number,
  errorMessage: String,

  severity: { type: String, enum: Object.values(SEVERITY), default: SEVERITY.LOW },
  metadata: mongoose.Schema.Types.Mixed,
}, {
  timestamps: true,
  versionKey: false,
});

auditLogSchema.index({ user: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ resource: 1, createdAt: -1 });
auditLogSchema.index({ ipAddress: 1, createdAt: -1 });
auditLogSchema.index({ severity: 1, createdAt: -1 });
auditLogSchema.index({ statusCode: 1, createdAt: -1 });
auditLogSchema.index({ user: 1, action: 1, createdAt: -1 });
auditLogSchema.index({ resource: 1, action: 1, createdAt: -1 });
auditLogSchema.index({ ipAddress: 1, severity: 1, createdAt: -1 });
auditLogSchema.index({ statusCode: 1, method: 1, createdAt: -1 });

const ttlDays = Number(config.audit?.ttlDays || process.env.AUDIT_TTL_DAYS) || 365;
auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: ttlDays * 24 * 60 * 60 });

auditLogSchema.statics.createLog = async function (logData) {
  try {
    const log = new this(logData);
    await log.save();
    return log;
  } catch (error) {
    logger.error('Failed to create audit log:', { error: error.message, stack: error.stack });
    return null;
  }
};

auditLogSchema.statics.findWithFilters = function (filters = {}, options = {}) {
  const { user, action, resource, ipAddress, startDate, endDate, severity, statusCode, method, search } = filters;

  const query = {};
  if (user && isValidObjectId(user)) query.user = user;

  if (action) {
    query.action = { $regex: new RegExp(escapeRegex(String(action)), 'i') };
  }
  if (resource) {
    query.resource = { $regex: new RegExp(escapeRegex(String(resource)), 'i') };
  }

  if (ipAddress) query.ipAddress = ipAddress;
  if (severity) query.severity = severity;
  if (method) query.method = method;

  if (statusCode !== undefined && statusCode !== null && statusCode !== '') {
    const sc = Number(statusCode);
    if (!Number.isNaN(sc)) query.statusCode = sc;
  }

  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }

  if (search) {
    const re = new RegExp(escapeRegex(String(search)), 'i');
    query.$or = [
      { action: { $regex: re } },
      { resource: { $regex: re } },
      { endpoint: { $regex: re } },
      { errorMessage: { $regex: re } },
    ];
  }

  const { page = 1, limit = 50, sort = '-createdAt' } = options;

  return this.find(query)
    .populate('user', 'firstName lastName email')
    .sort(sort)
    .limit(limit * 1)
    .skip((page - 1) * limit)
    .lean();
};

auditLogSchema.statics.getSecurityMetrics = async function (timeframe = 24) {
  const since = new Date(Date.now() - timeframe * 60 * 60 * 1000);
  const pipeline = [
    { $match: { createdAt: { $gte: since } } },
    {
      $facet: {
        failedLogins: [
          {
            $match: {
              resource: 'auth',
              $or: [
                { action: 'login_failed' },
                { action: 'login_rate_limited' },
                { action: 'login', statusCode: { $gte: 400 } },
              ],
            },
          },
          { $count: 'count' },
        ],
        suspiciousIPs: [
          {
            $match: {
              resource: 'auth',
              $or: [
                { action: 'login_failed' },
                { action: 'login_rate_limited' },
                { action: 'login', statusCode: { $gte: 400 } },
              ],
            },
          },
          { $group: { _id: '$ipAddress', attempts: { $sum: 1 } } },
          { $match: { attempts: { $gte: 5 } } },
          { $sort: { attempts: -1 } },
          { $limit: 10 },
        ],
        criticalEvents: [{ $match: { severity: 'critical' } }, { $count: 'count' }],
        topErrors: [
          { $match: { statusCode: { $gte: 400 } } },
          { $group: { _id: '$statusCode', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 5 },
        ],
      },
    },
  ];
  const [result] = await this.aggregate(pipeline);
  return {
    failedLogins: result.failedLogins[0]?.count || 0,
    suspiciousIPs: result.suspiciousIPs,
    criticalEvents: result.criticalEvents[0]?.count || 0,
    topErrors: result.topErrors,
  };
};

auditLogSchema.statics.getPerformanceMetrics = async function (timeframe = 24) {
  const since = new Date(Date.now() - timeframe * 60 * 60 * 1000);
  const pipeline = [
    { $match: { createdAt: { $gte: since }, duration: { $exists: true } } },
    {
      $group: {
        _id: '$endpoint',
        avgDuration: { $avg: '$duration' },
        maxDuration: { $max: '$duration' },
        requestCount: { $sum: 1 },
        errorRate: { $avg: { $cond: [{ $gte: ['$statusCode', 400] }, 1, 0] } },
      },
    },
    { $sort: { avgDuration: -1 } },
    { $limit: 10 },
  ];
  return this.aggregate(pipeline);
};

module.exports = mongoose.model('AuditLog', auditLogSchema);
