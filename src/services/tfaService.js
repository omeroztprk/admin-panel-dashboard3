const crypto = require('crypto');
const config = require('../config');
const { getRedis, prefixKey } = require('../config/redis');
const { ERRORS } = require('../utils/constants');
const logger = require('../utils/logger');

const generateTfaCode = () => {
  return crypto.randomInt(100000, 999999).toString();
};

const getTfaKey = (email, type = 'code') => {
  return prefixKey(`tfa:${type}:${email.toLowerCase()}`);
};

const storeTfaCode = async (email, code) => {
  const redis = getRedis();
  if (!redis?.isOpen) {
    logger.warn('Redis not available for TFA code storage');
    return false;
  }

  try {
    const key = getTfaKey(email);
    const attemptsKey = getTfaKey(email, 'attempts');
    
    await redis.set(key, code, { EX: Math.floor(config.tfa.codeExpiry / 1000) });
    await redis.del(attemptsKey);
    
    if (config.env === 'development' && config.i18n.debug) {
      logger.debug(`TFA code stored for email: ${email}`);
    }
    return true;
  } catch (error) {
    logger.error('Failed to store TFA code:', error);
    return false;
  }
};

const verifyTfaCode = async (email, inputCode) => {
  const redis = getRedis();
  if (!redis?.isOpen) {
    logger.warn('Redis not available for TFA verification');
    throw new Error(ERRORS.GENERAL.INTERNAL_ERROR);
  }

  try {
    const key = getTfaKey(email);
    const attemptsKey = getTfaKey(email, 'attempts');
    
    const storedCode = await redis.get(key);
    const attempts = await redis.get(attemptsKey);

    if (config.env === 'development' && config.i18n.debug) {
      logger.debug(`TFA verification for ${email}: stored=${!!storedCode}, attempts=${attempts || 0}`);
    }

    if (!storedCode) {
      logger.warn('TFA code not found or expired');
      throw new Error(ERRORS.AUTH.TFA_CODE_EXPIRED);
    }

    const currentAttempts = parseInt(attempts || '0', 10);
    if (currentAttempts >= config.tfa.maxAttempts) {
      await redis.del(key);
      logger.warn('TFA max attempts reached');
      throw new Error(ERRORS.AUTH.TFA_MAX_ATTEMPTS);
    }

    if (storedCode !== inputCode) {
      await redis.incr(attemptsKey);
      await redis.expire(attemptsKey, Math.floor(config.tfa.codeExpiry / 1000));
      logger.warn('Invalid TFA code provided');
      throw new Error(ERRORS.AUTH.TFA_INVALID_CODE);
    }

    await redis.del(key);
    await redis.del(attemptsKey);
    
    if (config.env === 'development' && config.i18n.debug) {
      logger.debug(`TFA verification successful for email: ${email}`);
    }
    return true;
  } catch (error) {
    if (error.message.startsWith('errors.')) {
      throw error;
    }
    logger.error('TFA verification error:', error);
    throw new Error(ERRORS.GENERAL.INTERNAL_ERROR);
  }
};

const cleanupExpiredCodes = async () => {
  const redis = getRedis();
  if (!redis?.isOpen) return;

  try {
    const pattern = prefixKey('tfa:*');
    const keys = await redis.keys(pattern);
    
    for (const key of keys) {
      const ttl = await redis.ttl(key);
      if (ttl === -1) {
        await redis.del(key);
      }
    }
    
    if (keys.length > 0) {
      logger.debug(`TFA cleanup: processed ${keys.length} keys`);
    }
  } catch (error) {
    logger.error('TFA cleanup error:', error);
  }
};

module.exports = {
  generateTfaCode,
  storeTfaCode,
  verifyTfaCode,
  cleanupExpiredCodes
};