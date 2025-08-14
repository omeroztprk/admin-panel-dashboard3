const zlib = require('zlib');
const auditService = require('../services/auditService');
const response = require('../utils/response');
const { asyncHandler } = require('../middleware/errorHandler');
const { ERRORS, MESSAGES } = require('../utils/constants');
const { getClientIP, toInt, toBool } = require('../utils/helpers');
const config = require('../config');

const getAuditStats = asyncHandler(async (req, res) => {
  const { startDate, endDate, groupBy = 'day', timezone } = req.query;
  const stats = await auditService.getAuditStats({ startDate, endDate, groupBy, timezone });
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { stats });
});

const getSecurityEvents = asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, sort = '-createdAt', severity, startDate, endDate } = req.query;

  const result = await auditService.getSecurityEvents(
    { severity, startDate, endDate },
    { page: toInt(page, 1), limit: toInt(limit, 50), sort }
  );

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const getLoginAttempts = asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, sort = '-createdAt', ipAddress, success, startDate, endDate } = req.query;

  const result = await auditService.getLoginAttempts(
    {
      ipAddress,
      success: (success !== undefined) ? toBool(success) : undefined,
      startDate,
      endDate
    },
    { page: toInt(page, 1), limit: toInt(limit, 50), sort }
  );

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const getSystemHealth = asyncHandler(async (req, res) => {
  const health = await auditService.getSystemHealth();
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { health });
});

const exportAuditLogs = asyncHandler(async (req, res) => {
  const {
    format = 'csv',
    user,
    action,
    resource,
    startDate,
    endDate,
    severity,
    search,
    method,
    ipAddress,
    statusCode
  } = req.query;

  const allowedFormats = ['csv', 'json', 'ndjson'];
  if (!allowedFormats.includes(format)) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  if (!startDate || !endDate) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }
  const start = new Date(startDate);
  const end = new Date(endDate);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start > end) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const rangeDays = Math.ceil((end - start) / (24 * 60 * 60 * 1000)) + 1;
  if (rangeDays > config.audit.export.maxRangeDays) {
    return response.error(res, req.t(ERRORS.VALIDATION.INVALID_INPUT), 400);
  }

  const filters = { user, action, resource, startDate, endDate, severity, search, method, ipAddress, statusCode };

  await auditService.logUserAction({
    user: req.user._id,
    action: 'export_audit_logs',
    resource: 'audit',
    method: req.method,
    endpoint: req.originalUrl,
    statusCode: 200,
    ipAddress: getClientIP(req),
    userAgent: req.get('User-Agent') || 'Unknown',
    changes: { filters, format, maxRows: config.audit.export.maxRows, rangeDays },
    severity: 'medium'
  });

  if (format === 'json') {
    const data = await auditService.exportAuditLogsArray(filters, { limit: config.audit.export.maxRows });
    return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), data);
  }

  const cursor = await auditService.getExportCursor(filters, { sort: '-createdAt', limit: config.audit.export.maxRows });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').replace('Z', '');
  const filename = `audit_logs_${timestamp}.${format}`;

  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('X-Export-Limit', String(config.audit.export.maxRows));
  res.setHeader('X-Export-Range-Days', String(config.audit.export.maxRangeDays));

  const acceptsGzip = /\bgzip\b/.test(req.headers['accept-encoding'] || '');
  let sink = res;
  let gzip;

  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  } else {
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  }

  if (acceptsGzip) {
    res.setHeader('Content-Encoding', 'gzip');
    gzip = zlib.createGzip();
    gzip.on('error', () => {
      try { res.end(); } catch (_) { }
    });
    gzip.pipe(res);
    sink = gzip;
  }

  if (format === 'csv') {
    sink.write(auditService.csvHeaderLine() + '\n');
  }

  const onClose = () => {
    try { cursor.close(); } catch (_) { }
    try { if (gzip) gzip.end(); } catch (_) { }
  };
  res.once('close', onClose);
  res.once('finish', onClose);

  const write = async (chunk) => {
    if (!sink.write(chunk)) await new Promise((resolve) => sink.once('drain', resolve));
  };

  try {
    for await (const doc of cursor) {
      if (format === 'csv') {
        await write(auditService.toCsvLine(doc) + '\n');
      } else {
        await write(JSON.stringify(auditService.serializeExportDoc(doc)) + '\n');
      }
    }
    sink.end();
  } catch (_) {
    try { sink.end(); } catch (_) { }
  } finally {
    res.removeListener('close', onClose);
    res.removeListener('finish', onClose);
    try { await cursor.close(); } catch (_) { }
  }
});

const getUserAuditLogs = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  
  const {
    page = 1,
    limit = 50,
    sort = '-createdAt',
    action,
    resource,
    startDate,
    endDate,
    search,
    method
  } = req.query;

  const filters = { user: userId, action, resource, startDate, endDate, search, method };

  const result = await auditService.getAuditLogs(filters, {
    page: toInt(page, 1),
    limit: toInt(limit, 50),
    sort
  });

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const getAuditLogs = asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 50,
    sort = '-createdAt',
    user,
    action,
    resource,
    ipAddress,
    startDate,
    endDate,
    severity,
    statusCode,
    search,
    method
  } = req.query;

  const filters = { user, action, resource, ipAddress, startDate, endDate, severity, statusCode, search, method };

  const result = await auditService.getAuditLogs(filters, {
    page: toInt(page, 1),
    limit: toInt(limit, 50),
    sort
  });

  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), result);
});

const getAuditLogById = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const auditLog = await auditService.getAuditLogById(id);
  if (!auditLog) return response.notFound(res, req.t(ERRORS.AUDIT.NOT_FOUND));
  return response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), { auditLog });
});

module.exports = {
  getAuditStats,
  getSecurityEvents,
  getLoginAttempts,
  getSystemHealth,
  exportAuditLogs,
  getUserAuditLogs,
  getAuditLogs,
  getAuditLogById
};
