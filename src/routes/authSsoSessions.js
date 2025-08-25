const express = require('express');
const authController = require('../controllers/authController');
const { ensureAuthUnified } = require('../middleware/auth-unified');
const { validateObjectId } = require('../middleware/validation');
const { logUserAction } = require('../middleware/audit');
const { ACTIONS, RESOURCES, SEVERITY } = require('../utils/constants');

const router = express.Router();

// Sessions endpoint'leri
router.get('/sessions',
  ensureAuthUnified,
  authController.getActiveSessions
);

router.delete('/sessions/:tokenId',
  ensureAuthUnified,
  validateObjectId('tokenId'),
  logUserAction(ACTIONS.DELETE, RESOURCES.AUTH, SEVERITY.MEDIUM),
  authController.revokeSession
);

router.post('/logout-all',
  ensureAuthUnified,
  logUserAction(ACTIONS.LOGOUT, RESOURCES.AUTH, SEVERITY.MEDIUM),
  authController.logoutAll
);

module.exports = router;