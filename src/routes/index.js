const express = require('express');
const mongoose = require('mongoose');
const auditRoutes = require('./audit');
const authRoutes = require('./auth');
const permissionRoutes = require('./permissions');
const roleRoutes = require('./roles');
const userRoutes = require('./users');
const response = require('../utils/response');
const { MESSAGES } = require('../utils/constants');
const logger = require('../utils/logger');

const router = express.Router();

router.get('/health', async (req, res) => {
  try {
    const dbState = mongoose.connection.readyState;
    const isHealthy = dbState === 1;

    const healthData = {
      status: isHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      uptime: Math.round(process.uptime()),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
      },
      database: {
        status: isHealthy ? 'connected' : 'disconnected',
        readyState: dbState,
        host: mongoose.connection.host,
        name: mongoose.connection.name
      }
    };

    if (isHealthy) {
      return response.success(res, req.t(MESSAGES.GENERAL.API_RUNNING), healthData, 200);
    } else {
      logger.warn('Health check failed - database not connected', {
        dbState,
        connection: mongoose.connection.readyState
      });
      const msg = req.t(MESSAGES.GENERAL.API_UNHEALTHY);
      if (typeof res.set === 'function' && req.getLanguage) {
        res.set('Content-Language', req.getLanguage());
      }
      return res.status(503).json({
        status: 'error',
        message: msg,
        data: healthData,
        timestamp: new Date().toISOString()
      });
    }

  } catch (error) {
    logger.error('Health check error:', {
      error: error.message,
      stack: error.stack
    });

    return response.error(res, req.t(MESSAGES.GENERAL.API_ERROR), 500);
  }
});

router.get('/info', (req, res) => {
  try {
    const info = {
      name: 'Admin Panel API',
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      endpoints: {
        auth: '/api/v1/auth',
        users: '/api/v1/users',
        roles: '/api/v1/roles',
        permissions: '/api/v1/permissions',
        audit: '/api/v1/audit'
      }
    };

    response.success(res, req.t(MESSAGES.GENERAL.SUCCESS), info);
  } catch (error) {
    logger.error('API info error:', error);
    response.error(res, req.t(MESSAGES.GENERAL.INTERNAL_ERROR), 500);
  }
});

router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/roles', roleRoutes);
router.use('/permissions', permissionRoutes);
router.use('/audit', auditRoutes);

module.exports = router;
