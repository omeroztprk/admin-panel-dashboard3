const AuditLog = require('../models/AuditLog');
const { isValidObjectId, escapeRegex } = require('../utils/helpers');

const getAuditLogs = async (filters = {}, options = {}) => {
  const { page = 1, limit = 50, sort = '-createdAt' } = options;
  const skip = (page - 1) * limit;

  const query = buildAuditQuery(filters);

  const auditLogs = await AuditLog.find(query)
    .populate('user', 'firstName lastName email')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await AuditLog.countDocuments(query);

  return {
    auditLogs,
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

const getAuditLogById = async (logId) => {
  return AuditLog.findById(logId)
    .populate('user', 'firstName lastName email')
    .lean();
};

const getUserAuditLogs = async (filters = {}, options = {}) => {
  return getAuditLogs(filters, options);
};

const getAuditStats = async (options = {}) => {
  const { startDate, endDate, groupBy = 'day', timezone } = options;
  
  const matchStage = {};
  if (startDate || endDate) {
    matchStage.createdAt = {};
    if (startDate) matchStage.createdAt.$gte = new Date(startDate);
    if (endDate) matchStage.createdAt.$lte = new Date(endDate);
  }

  const unit = ['hour', 'day', 'week', 'month'].includes(groupBy) ? groupBy : 'day';

  const pipeline = [
    { $match: matchStage },
    {
      $group: {
        _id: {
          period: { $dateTrunc: { date: '$createdAt', unit, ...(timezone && { timezone }) } },
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
        actions: { $push: { action: '$_id.action', severity: '$_id.severity', count: '$count' } }
      }
    },
    { $sort: { _id: 1 } }
  ];

  const timeline = await AuditLog.aggregate(pipeline);

  const [topUsers, topResources] = await Promise.all([
    getTopUsers(matchStage),
    getTopResources(matchStage)
  ]);

  return { timeline, topUsers, topResources };
};

const getSecurityEvents = async (filters = {}, options = {}) => {
  const { page = 1, limit = 50, sort = '-createdAt' } = options;
  const skip = (page - 1) * limit;

  const query = {
    $and: [
      buildAuditQuery(filters),
      {
        $or: [
          { severity: { $in: ['high', 'critical'] } },
          { statusCode: { $gte: 400 } },
          { action: { $in: ['login', 'logout', 'login_failed', 'login_rate_limited'] } }
        ]
      }
    ]
  };

  const events = await AuditLog.find(query)
    .populate('user', 'firstName lastName email')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await AuditLog.countDocuments(query);

  return {
    events,
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

const getLoginAttempts = async (filters = {}, options = {}) => {
  const { page = 1, limit = 50, sort = '-createdAt' } = options;
  const skip = (page - 1) * limit;

  const query = {
    action: { $in: ['login', 'login_failed', 'login_rate_limited'] },
    ...buildLoginAttemptsQuery(filters)
  };

  const attempts = await AuditLog.find(query)
    .populate('user', 'firstName lastName email')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .lean();

  const total = await AuditLog.countDocuments(query);

  return {
    attempts,
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

const getSystemHealth = async () => {
  const now = new Date();
  const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  const [
    totalRequestsLastHour,
    errorRequestsLastHour,
    failedLoginsLastDay,
    avgResponseTime,
    criticalEvents
  ] = await Promise.all([
    AuditLog.countDocuments({ createdAt: { $gte: oneHourAgo } }),
    AuditLog.countDocuments({ createdAt: { $gte: oneHourAgo }, statusCode: { $gte: 400 } }),
    AuditLog.countDocuments({ createdAt: { $gte: oneDayAgo }, action: 'login_failed' }),
    getAverageResponseTime(oneHourAgo),
    AuditLog.countDocuments({ createdAt: { $gte: oneDayAgo }, severity: 'critical' })
  ]);

  const errorRate = totalRequestsLastHour > 0 ? (errorRequestsLastHour / totalRequestsLastHour) * 100 : 0;

  return {
    errorRate: Math.round(errorRate * 100) / 100,
    failedLoginsLastDay,
    avgResponseTime: avgResponseTime[0]?.avgDuration || 0,
    criticalEvents,
    status: errorRate > 10 ? 'unhealthy' : errorRate > 5 ? 'warning' : 'healthy'
  };
};

const getExportData = async (filters = {}, options = {}) => {
  const { limit = 50000 } = options;
  const query = buildAuditQuery(filters);

  const projection = {
    createdAt: 1, user: 1, action: 1, resource: 1, method: 1,
    endpoint: 1, statusCode: 1, ipAddress: 1, duration: 1, severity: 1
  };

  return AuditLog.find(query, projection)
    .populate('user', 'firstName lastName email')
    .sort('-createdAt')
    .limit(limit)
    .lean()
    .cursor();
};

const buildAuditQuery = (filters) => {
  const query = {};
  
  if (filters.user && isValidObjectId(filters.user)) query.user = filters.user;
  if (filters.action) query.action = { $regex: new RegExp(escapeRegex(filters.action), 'i') };
  if (filters.resource) query.resource = { $regex: new RegExp(escapeRegex(filters.resource), 'i') };
  if (filters.ipAddress) query.ipAddress = filters.ipAddress;
  if (filters.severity) query.severity = filters.severity;
  if (filters.method) query.method = filters.method;

  if (filters.statusCode !== undefined && filters.statusCode !== null && filters.statusCode !== '') {
    const sc = Number(filters.statusCode);
    if (!Number.isNaN(sc)) query.statusCode = sc;
  }

  if (filters.startDate || filters.endDate) {
    query.createdAt = {};
    if (filters.startDate) query.createdAt.$gte = new Date(filters.startDate);
    if (filters.endDate) query.createdAt.$lte = new Date(filters.endDate);
  }

  if (filters.search) {
    const re = new RegExp(escapeRegex(filters.search), 'i');
    query.$or = [
      { action: { $regex: re } },
      { resource: { $regex: re } },
      { endpoint: { $regex: re } },
      { errorMessage: { $regex: re } }
    ];
  }

  return query;
};

const buildLoginAttemptsQuery = (filters) => {
  const query = {};
  
  if (filters.ipAddress) query.ipAddress = filters.ipAddress;
  if (filters.success === true) query.statusCode = { $lt: 400 };
  else if (filters.success === false) query.statusCode = { $gte: 400 };

  if (filters.startDate || filters.endDate) {
    query.createdAt = {};
    if (filters.startDate) query.createdAt.$gte = new Date(filters.startDate);
    if (filters.endDate) query.createdAt.$lte = new Date(filters.endDate);
  }

  return query;
};

const getAverageResponseTime = async (since) => {
  return AuditLog.aggregate([
    { $match: { createdAt: { $gte: since }, duration: { $exists: true } } },
    { $group: { _id: null, avgDuration: { $avg: '$duration' } } }
  ]);
};

const getTopUsers = async (matchStage) => {
  return AuditLog.aggregate([
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
};

const getTopResources = async (matchStage) => {
  return AuditLog.aggregate([
    { $match: matchStage },
    { $group: { _id: '$resource', count: { $sum: 1 } } },
    { $sort: { count: -1 } },
    { $limit: 10 }
  ]);
};

module.exports = {
  getAuditLogs,
  getAuditLogById,
  getUserAuditLogs,
  getAuditStats,
  getSecurityEvents,
  getLoginAttempts,
  getSystemHealth,
  getExportData
};
