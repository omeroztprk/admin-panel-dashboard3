const express = require('express');
const authController = require('../controllers/authController');
const { authenticate, refreshTokenAuth, precheckAccountLock } = require('../middleware/auth');
const { validateObjectId, validateRequest } = require('../middleware/validation');
const { limiter } = require('../middleware/security');
const authValidators = require('../validators/authValidators');

const router = express.Router();

router.post('/register',
  limiter('auth:register'),
  authValidators.register,
  validateRequest,
  authController.register
);

router.post('/login',
  authValidators.login,
  validateRequest,
  precheckAccountLock,
  limiter('auth:login:ip'),
  authController.login
);

router.post('/refresh-token',
  authValidators.refreshToken,
  validateRequest,
  refreshTokenAuth,
  limiter('auth:refresh'),
  authController.refreshToken
);

router.use(authenticate);

router.post('/logout',
  authValidators.logout,
  validateRequest,
  authController.logout
);

router.post('/logout-all',
  authController.logoutAll
);

router.get('/me',
  authController.getMe
);

router.patch('/profile',
  authValidators.updateProfile,
  validateRequest,
  authController.updateProfile
);

router.patch('/change-password',
  authValidators.changePassword,
  validateRequest,
  authController.changePassword
);

router.get('/sessions',
  authController.getActiveSessions
);

router.delete('/sessions/:tokenId',
  validateObjectId('tokenId'),
  authController.revokeSession
);

module.exports = router;
