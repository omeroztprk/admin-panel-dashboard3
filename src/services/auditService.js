const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { isValidObjectId, escapeRegex } = require('../utils/helpers');

const EXPORT_PROJECTION = {
  createdAt: 1,
  user: 1,
  action: 1,
  resource: 1,
  method: 1,
  endpoint: 1,
  statusCode: 1,
  ipAddress: 1,
  duration: 1,
  severity: 1
};

const logUserAction = async (actionData) => {
  try {
    if (typeof AuditLog.createLog === 'function') {
      return await AuditLog.createLog(actionData);
    }
    const log = new AuditLog(actionData);
    await log.save();
    return log;
  } catch (error) {
    logger.error('Failed to create audit log:', { error: error.message, stack: error.stack });
    throw error;
  }
};

const getAuditStats = async ({ startDate, endDate, groupBy = 'day', timezone } = {}) => {
  const matchStage = {};
  if (startDate || endDate) {
    matchStage.createdAt = {};
    if (startDate) matchStage.createdAt.$gte = new Date(startDate);
    if (endDate) matchStage.createdAt.$lte = new Date(endDate);
  }

  const validUnits = { hour: 'hour', day: 'day', week: 'week', month: 'month' };
  const unit = validUnits[groupBy] || 'day';

  const pipeline = [
    { $match: matchStage },
    {
      $group: {
        _id: {
          period: {
            $dateTrunc: { date: '$createdAt', unit, ...(timezone ? { timezone } : {}) }
          },
          action: '$action',
          severity: '$severity'
        },
        count: { $sum: 1 },
        avgDuration: { $avg: '$duration' },
        successCount: { $sum: { $cond: [{ $lt: ['$statusCode', 400] }, 1, 0] } },
        errorCount: { $sum: { $cond: [{ $gte: ['$statusCode', 400] }, 1, 0] } }
      }
    },
    {
      $group: {
        _id: '$_id.period',
        totalRequests: { $sum: '$count' },
        totalSuccess: { $sum: '$successCount' },
        totalErrors: { $sum: '$errorCount' },
        avgDuration: { $avg: '$avgDuration' },
        actions: {
          $push: { action: '$_id.action', severity: '$_id.severity', count: '$count' }
        }
      }
    },
    { $sort: { _id: 1 } }
  ];

  const timeline = await AuditLog.aggregate(pipeline);

  const topUsers = await AuditLog.aggregate([
    { $match: matchStage },
    { $group: { _id: '$user', count: { $sum: 1 } } },
    { $match: { _id: { $ne: null } } },
    { $sort: { count: -1 } },
    { $limit: 10 },
    {
      $lookup: {
        from: 'users',
        localField: '_id',
        foreignField: '_id',
        as: 'user'
      }
    },
    { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } }
  ]);

  const topResources = await AuditLog.aggregate([
    { $match: matchStage },
    { $group: { _id: '$resource', count: { $sum: 1 } } },
    { $sort: { count: -1 } },
    { $limit: 10 }
  ]);

  return { timeline, topUsers, topResources };
};

const getSecurityEvents = async (filters = {}, options = {}) => {
  const base = buildFilterQuery(filters);

  const securityOr = [
    { severity: { $in: ['high', 'critical'] } },
    { statusCode: { $gte: 400 } },
    { action: { $in: ['login', 'logout', 'login_failed', 'login_rate_limited'] } },
    { tags: { $in: ['authentication', 'authorization_failure'] } }
  ];

  const securityFilters = {
    ...base,
    $and: [...(base.$and || []), { $or: securityOr }]
  };

  const { page = 1, limit = 50, sort = '-createdAt' } = options;
  const skip = (page - 1) * limit;

  const events = await AuditLog.find(securityFilters)
    .populate('user', 'firstName lastName email')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await AuditLog.countDocuments(securityFilters);

  return {
    events,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  };
};

const getLoginAttempts = async (filters = {}, options = {}) => {
  const { ipAddress, success, startDate, endDate } = filters;

  const query = { action: { $in: ['login', 'login_failed', 'login_rate_limited'] } };

  if (ipAddress) query.ipAddress = ipAddress;
  if (success === true) query.statusCode = { $lt: 400 };
  else if (success === false) query.statusCode = { $gte: 400 };

  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }

  const { page = 1, limit = 50, sort = '-createdAt' } = options;
  const skip = (page - 1) * limit;

  const attempts = await AuditLog.find(query)
    .populate('user', 'firstName lastName email')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await AuditLog.countDocuments(query);

  return {
    attempts,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  };
};

const getSystemHealth = async () => {
  const now = new Date();
  const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  const totalRequestsLastHour = await AuditLog.countDocuments({ createdAt: { $gte: oneHourAgo } });
  const errorRequestsLastHour = await AuditLog.countDocuments({
    createdAt: { $gte: oneHourAgo },
    statusCode: { $gte: 400 }
  });

  const errorRate = totalRequestsLastHour > 0 ? (errorRequestsLastHour / totalRequestsLastHour) * 100 : 0;

  const failedLoginsLastDay = await AuditLog.countDocuments({
    createdAt: { $gte: oneDayAgo },
    action: 'login_failed'
  });

  const avgResponseTime = await AuditLog.aggregate([
    { $match: { createdAt: { $gte: oneHourAgo }, duration: { $exists: true } } },
    { $group: { _id: null, avgDuration: { $avg: '$duration' } } }
  ]);

  const criticalEvents = await AuditLog.countDocuments({
    createdAt: { $gte: oneDayAgo },
    severity: 'critical'
  });

  return {
    errorRate: Math.round(errorRate * 100) / 100,
    failedLoginsLastDay,
    avgResponseTime: avgResponseTime[0]?.avgDuration || 0,
    criticalEvents,
    status: errorRate > 10 ? 'unhealthy' : errorRate > 5 ? 'warning' : 'healthy'
  };
};

const getExportCursor = async (filters = {}, { sort = '-createdAt', limit = 50000 } = {}) => {
  const query = buildFilterQuery(filters);
  return AuditLog.find(query, EXPORT_PROJECTION).sort(sort).limit(limit).lean().cursor();
};

const serializeExportDoc = (doc) => ({
  createdAt: doc.createdAt ? new Date(doc.createdAt).toISOString() : '',
  user: doc.user || null,
  action: doc.action || '',
  resource: doc.resource || '',
  method: doc.method || '',
  endpoint: doc.endpoint || '',
  statusCode: typeof doc.statusCode === 'number' ? doc.statusCode : '',
  ipAddress: doc.ipAddress || '',
  duration: typeof doc.duration === 'number' ? doc.duration : '',
  severity: doc.severity || ''
});

const csvHeaderLine = () =>
  ['Date', 'User', 'Action', 'Resource', 'Method', 'Endpoint', 'Status Code', 'IP Address', 'Duration', 'Severity'].join(
    ','
  );

const escapeCSV = (val) => {
  if (val === null || val === undefined) return '';
  const s = String(val).replace(/\r?\n|\r/g, ' ');
  if (/[",]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
};

const toCsvLine = (doc) => {
  const d = serializeExportDoc(doc);
  return [
    d.createdAt,
    d.user || 'Anonymous',
    d.action,
    d.resource,
    d.method,
    d.endpoint,
    d.statusCode,
    d.ipAddress,
    d.duration,
    d.severity
  ]
    .map(escapeCSV)
    .join(',');
};

const exportAuditLogsArray = async (filters = {}, { limit = 50000 } = {}) => {
  const query = buildFilterQuery(filters);
  const logs = await AuditLog.find(query, EXPORT_PROJECTION).sort('-createdAt').limit(limit).lean();
  return logs.map(serializeExportDoc);
};

const getAuditLogs = async (filters = {}, options = {}) => {
  const { page = 1, limit = 50, sort = '-createdAt' } = options;

  if (typeof AuditLog.findWithFilters === 'function') {
    const auditLogs = await AuditLog.findWithFilters(filters, { page, limit, sort });
    const total = await AuditLog.countDocuments(buildFilterQuery(filters));
    return { auditLogs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } };
  }
  const query = buildFilterQuery(filters);
  const skip = (page - 1) * limit;

  const auditLogs = await AuditLog.find(query)
    .populate('user', 'firstName lastName email')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await AuditLog.countDocuments(query);

  return {
    auditLogs,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  };
};

const getAuditLogById = async (logId) => {
  if (!isValidObjectId(logId)) return null;
  return AuditLog.findById(logId).populate('user', 'firstName lastName email').lean();
};

const buildFilterQuery = (filters = {}) => {
  const query = {};

  if (filters.user && isValidObjectId(filters.user)) query.user = filters.user;

  if (filters.action) {
    const re = new RegExp(escapeRegex(String(filters.action)), 'i');
    query.action = { $regex: re };
  }

  if (filters.resource) {
    const re = new RegExp(escapeRegex(String(filters.resource)), 'i');
    query.resource = { $regex: re };
  }

  if (filters.ipAddress) query.ipAddress = filters.ipAddress;
  if (filters.severity) query.severity = filters.severity;
  if (filters.method) query.method = filters.method;

  if (filters.search) {
    const re = new RegExp(escapeRegex(String(filters.search)), 'i');
    const orParts = [
      { action: { $regex: re } },
      { resource: { $regex: re } },
      { endpoint: { $regex: re } },
      { errorMessage: { $regex: re } }
    ];
    if (query.$or) {
      query.$and = (query.$and || []).concat([{ $or: orParts }]);
    } else {
      query.$or = orParts;
    }
  }

  if (filters.statusCode !== undefined && filters.statusCode !== null && filters.statusCode !== '') {
    const sc = Number(filters.statusCode);
    if (!Number.isNaN(sc)) query.statusCode = sc;
  }

  if (filters.startDate || filters.endDate) {
    query.createdAt = {};
    if (filters.startDate) query.createdAt.$gte = new Date(filters.startDate);
    if (filters.endDate) query.createdAt.$lte = new Date(filters.endDate);
  }

  return query;
};

module.exports = {
  logUserAction,
  getAuditStats,
  getSecurityEvents,
  getLoginAttempts,
  getSystemHealth,
  getExportCursor,
  exportAuditLogsArray,
  getAuditLogs,
  getAuditLogById,
  csvHeaderLine,
  toCsvLine,
  serializeExportDoc
};
