const express = require('express');
const authController = require('../controllers/authController');
const { authenticate, refreshTokenAuth, precheckAccountLock } = require('../middleware/auth');
const { ensureAuthUnified } = require('../middleware/auth-unified');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const { limiter } = require('../middleware/security');
const { logUserAction } = require('../middleware/audit');
const authValidators = require('../validators/authValidators');
const { PERMISSIONS, ACTIONS, RESOURCES, SEVERITY } = require('../utils/constants');

const router = express.Router();

router.post('/register',
  limiter('auth:register'),
  authValidators.register,
  validateRequest,
  logUserAction(ACTIONS.REGISTER, RESOURCES.AUTH, SEVERITY.MEDIUM),
  authController.register
);

router.post('/login',
  authValidators.login,
  validateRequest,
  precheckAccountLock,
  limiter('auth:login:ip'),
  logUserAction(ACTIONS.LOGIN, RESOURCES.AUTH, SEVERITY.MEDIUM),
  authController.login
);

router.post('/verify-tfa',
  authValidators.verifyTfa,
  validateRequest,
  limiter('auth:login:ip'),
  logUserAction(ACTIONS.LOGIN, RESOURCES.AUTH, SEVERITY.MEDIUM),
  authController.verifyTfa
);

router.post('/refresh-token',
  authValidators.refreshToken,
  validateRequest,
  refreshTokenAuth,
  limiter('auth:refresh'),
  logUserAction(ACTIONS.REFRESH, RESOURCES.AUTH, SEVERITY.LOW),
  authController.refreshToken
);

router.use(ensureAuthUnified);

router.post('/logout',
  authValidators.logout,
  validateRequest,
  logUserAction(ACTIONS.LOGOUT, RESOURCES.AUTH, SEVERITY.LOW),
  authController.logout
);

router.post('/logout-all',
  ensureAuthUnified,
  logUserAction(ACTIONS.LOGOUT, RESOURCES.AUTH, SEVERITY.MEDIUM),
  authController.logoutAll
);

router.get('/me',
  authController.getMe
);

router.patch('/profile',
  authValidators.updateProfile,
  validateRequest,
  logUserAction(ACTIONS.UPDATE, RESOURCES.AUTH, SEVERITY.LOW),
  authController.updateProfile
);

router.patch('/change-password',
  authValidators.changePassword,
  validateRequest,
  logUserAction(ACTIONS.UPDATE, RESOURCES.AUTH, SEVERITY.HIGH),
  authController.changePassword
);

router.get('/sessions',
  ensureAuthUnified, // Unified auth middleware kullanarak SSO bilgilerini doğru şekilde aktar
  authController.getActiveSessions
);

router.delete('/sessions/:tokenId',
  ensureAuthUnified,
  validateObjectId('tokenId'),
  logUserAction(ACTIONS.DELETE, RESOURCES.AUTH, SEVERITY.MEDIUM),
  authController.revokeSession
);

module.exports = router;
