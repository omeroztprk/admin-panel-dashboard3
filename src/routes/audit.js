const express = require('express');
const auditController = require('../controllers/auditController');
const { authenticate } = require('../middleware/auth');
const { hasPermission } = require('../middleware/rbac');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const { limiter } = require('../middleware/security');
const auditValidators = require('../validators/auditValidators');
const { PERMISSIONS } = require('../utils/constants');

const router = express.Router();

router.use(authenticate);

router.get('/stats/overview',
  hasPermission(PERMISSIONS.AUDIT_READ),
  auditValidators.getAuditStatsQuery,
  validateRequest,
  auditController.getAuditStats
);

router.get('/security/events',
  hasPermission(PERMISSIONS.AUDIT_READ),
  auditValidators.getAuditLogsQuery,
  validateRequest,
  auditController.getSecurityEvents
);

router.get('/security/login-attempts',
  hasPermission(PERMISSIONS.AUDIT_READ),
  auditValidators.getLoginAttemptsQuery,
  validateRequest,
  auditController.getLoginAttempts
);

router.get('/system/health',
  hasPermission(PERMISSIONS.SYSTEM_HEALTH),
  auditController.getSystemHealth
);

router.get('/export/logs',
  hasPermission(PERMISSIONS.AUDIT_EXPORT),
  limiter('audit:export'),
  auditValidators.getExportLogsQuery,
  validateRequest,
  auditController.exportAuditLogs
);

router.get('/user/:userId',
  validateObjectId('userId'),
  hasPermission(PERMISSIONS.AUDIT_READ),
  auditValidators.getAuditLogsQuery,
  validateRequest,
  auditController.getUserAuditLogs
);

router.get('/',
  hasPermission(PERMISSIONS.AUDIT_READ),
  auditValidators.getAuditLogsQuery,
  validateRequest,
  auditController.getAuditLogs
);

router.get('/:id',
  validateObjectId(),
  hasPermission(PERMISSIONS.AUDIT_READ),
  auditController.getAuditLogById
);

module.exports = router;
