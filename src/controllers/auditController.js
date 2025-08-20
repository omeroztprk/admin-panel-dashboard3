const auditService = require('../services/auditService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { toInt, toBool, sanitizeObject } = require('../utils/helpers');

const getAuditLogs = asyncHandler(async (req, res) => {
  const filters = {
    user: req.query.user,
    action: req.query.action,
    resource: req.query.resource,
    ipAddress: req.query.ipAddress,
    startDate: req.query.startDate,
    endDate: req.query.endDate,
    severity: req.query.severity,
    statusCode: req.query.statusCode,
    search: req.query.search,
    method: req.query.method
  };

  const options = {
    page: Math.max(1, toInt(req.query.page, 1)),
    limit: Math.min(100, Math.max(1, toInt(req.query.limit, 50))),
    sort: req.query.sort || '-createdAt'
  };

  const result = await auditService.getAuditLogs(filters, options);
  const auditLogs = (result.auditLogs || []).map(sanitizeObject);
  return response.paginated(res, req.t(MESSAGES.GENERAL.SUCCESS), { auditLogs }, result.pagination);
});

const getAuditLogById = asyncHandler(async (req, res) => {
  const auditLog = await auditService.getAuditLogById(req.params.id);
  if (!auditLog) {
    return response.notFound(res, req.t(ERRORS.AUDIT.NOT_FOUND));
  }
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { auditLog: sanitizeObject(auditLog) });
});

const getUserAuditLogs = asyncHandler(async (req, res) => {
  const filters = {
    user: req.params.userId,
    action: req.query.action,
    resource: req.query.resource,
    startDate: req.query.startDate,
    endDate: req.query.endDate,
    search: req.query.search,
    method: req.query.method
  };

  const options = {
    page: Math.max(1, toInt(req.query.page, 1)),
    limit: Math.min(100, Math.max(1, toInt(req.query.limit, 50))),
    sort: req.query.sort || '-createdAt'
  };

  const result = await auditService.getUserAuditLogs(filters, options);
  const auditLogs = (result.auditLogs || []).map(sanitizeObject);
  return response.paginated(res, req.t(MESSAGES.GENERAL.SUCCESS), { auditLogs }, result.pagination);
});

const getAuditStats = asyncHandler(async (req, res) => {
  const options = {
    startDate: req.query.startDate,
    endDate: req.query.endDate,
    groupBy: req.query.groupBy || 'day',
    timezone: req.query.timezone
  };

  const stats = await auditService.getAuditStats(options);
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { stats });
});

const getSecurityEvents = asyncHandler(async (req, res) => {
  const filters = {
    severity: req.query.severity,
    startDate: req.query.startDate,
    endDate: req.query.endDate
  };

  const options = {
    page: Math.max(1, toInt(req.query.page, 1)),
    limit: Math.min(100, Math.max(1, toInt(req.query.limit, 50))),
    sort: req.query.sort || '-createdAt'
  };

  const result = await auditService.getSecurityEvents(filters, options);
  const events = (result.events || []).map(sanitizeObject);
  return response.paginated(res, req.t(MESSAGES.GENERAL.SUCCESS), { events }, result.pagination);
});

const getLoginAttempts = asyncHandler(async (req, res) => {
  const filters = {
    ipAddress: req.query.ipAddress,
    success: req.query.success !== undefined ? toBool(req.query.success) : undefined,
    startDate: req.query.startDate,
    endDate: req.query.endDate
  };

  const options = {
    page: Math.max(1, toInt(req.query.page, 1)),
    limit: Math.min(100, Math.max(1, toInt(req.query.limit, 50))),
    sort: req.query.sort || '-createdAt'
  };

  const result = await auditService.getLoginAttempts(filters, options);
  const attempts = (result.attempts || []).map(sanitizeObject);
  return response.paginated(res, req.t(MESSAGES.GENERAL.SUCCESS), { attempts }, result.pagination);
});

const getSystemHealth = asyncHandler(async (req, res) => {
  const health = await auditService.getSystemHealth();
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { health });
});

const exportAuditLogs = asyncHandler(async (req, res) => {
  const filters = {
    user: req.query.user,
    action: req.query.action,
    resource: req.query.resource,
    startDate: req.query.startDate,
    endDate: req.query.endDate,
    severity: req.query.severity,
    search: req.query.search,
    method: req.query.method,
    ipAddress: req.query.ipAddress,
    statusCode: req.query.statusCode
  };

  const options = {
    format: req.query.format || 'csv',
    limit: 100000
  };

  const cursor = await auditService.getExportData(filters, options);
  
  const filename = `audit-logs-${new Date().toISOString().split('T')[0]}.${options.format}`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', options.format === 'csv' ? 'text/csv' : 'application/json');

  try {
    if (options.format === 'csv') {
      res.write('Date,User,Action,Resource,Method,Endpoint,Status,IP,Duration,Severity\n');
      
      for (let doc = await cursor.next(); doc != null; doc = await cursor.next()) {
        const userEmail = doc.user?.email || 'System';
        const csvLine = [
          doc.createdAt?.toISOString() || '',
          `"${userEmail}"`,
          `"${doc.action || ''}"`,
          `"${doc.resource || ''}"`,
          doc.method || '',
          `"${doc.endpoint || ''}"`,
          doc.statusCode || '',
          doc.ipAddress || '',
          doc.duration || '',
          doc.severity || ''
        ].join(',') + '\n';
        
        if (!res.write(csvLine)) {
          await new Promise(resolve => res.once('drain', resolve));
        }
      }
    } else {
      res.write('[');
      let first = true;
      
      for (let doc = await cursor.next(); doc != null; doc = await cursor.next()) {
        if (!first) res.write(',');
        const jsonStr = JSON.stringify(doc);
        
        if (!res.write(jsonStr)) {
          await new Promise(resolve => res.once('drain', resolve));
        }
        first = false;
      }
      
      res.write(']');
    }

    res.end();
  } catch (error) {
    if (!res.headersSent) {
      return response.error(res, req.t(ERRORS.GENERAL.INTERNAL_ERROR), 500);
    }
    res.end();
  } finally {
    await cursor.close();
  }
});

module.exports = {
  getAuditLogs,
  getAuditLogById,
  getUserAuditLogs,
  getAuditStats,
  getSecurityEvents,
  getLoginAttempts,
  getSystemHealth,
  exportAuditLogs
};
