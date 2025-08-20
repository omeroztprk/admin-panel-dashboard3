const parseNumber = (value, fallback) => {
  const num = Number(value);
  return Number.isNaN(num) ? fallback : num;
};

const buildCorsConfig = () => {
  const raw = (process.env.CORS_ORIGIN || '*').trim();
  if (raw === '*') return { origin: true, credentials: true };

  const origins = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (origins.length === 0) return { origin: false, credentials: false };

  return {
    origin: (origin, cb) => (!origin || origins.includes(origin) ? cb(null, true) : cb(new Error('Not allowed by CORS'))),
    credentials: true
  };
};

const validateJwtSecret = (secret, name) => {
  if (!secret) return `${name} is required`;
  if (secret.length < 32) return `${name} must be at least 32 characters`;
  if (secret === 'default' || secret === 'change-me') return `${name} must be changed from default`;
  return null;
};

const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseNumber(process.env.PORT, 5001),

  database: { uri: process.env.MONGODB_URI },

  jwt: {
    issuer: process.env.JWT_ISSUER,
    audience: process.env.JWT_AUDIENCE,
    access: {
      secret: process.env.JWT_ACCESS_SECRET,
      expiresIn: process.env.JWT_ACCESS_EXPIRE || '15m',
    },
    refresh: {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d',
    },
  },

  email: {
    enabled: process.env.TFA_ENABLED === 'true' && !!process.env.EMAIL_USER,
    service: process.env.EMAIL_SERVICE || 'gmail',
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseNumber(process.env.EMAIL_PORT, 587),
    secure: process.env.EMAIL_SECURE === 'true',
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
  },

  tfa: {
    enabled: process.env.TFA_ENABLED === 'true',
    codeExpiry: parseNumber(process.env.TFA_CODE_EXPIRY, 5 * 60 * 1000),
    maxAttempts: parseNumber(process.env.TFA_MAX_ATTEMPTS, 3),
  },

  security: {
    bcrypt: { saltRounds: parseNumber(process.env.BCRYPT_SALT_ROUNDS, 12) },
    rateLimit: {
      windowMs: parseNumber(process.env.RATE_LIMIT_WINDOW_MS, 60 * 1000),
      max: parseNumber(process.env.RATE_LIMIT_MAX_REQUESTS, 100),
    },
    authRateLimit: {
      windowMs: parseNumber(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 60 * 1000),
      max: parseNumber(process.env.AUTH_RATE_LIMIT_MAX, 10),
      skipSuccessfulRequests: true,
    },
    authLoginIpRateLimit: {
      windowMs: parseNumber(process.env.AUTH_LOGIN_IP_WINDOW_MS, 10 * 1000),
      max: parseNumber(process.env.AUTH_LOGIN_IP_MAX, 8),
    },
    lockout: {
      lockoutTime: parseNumber(process.env.LOCKOUT_TIME, 30 * 60 * 1000),
      maxAttempts: parseNumber(process.env.LOCKOUT_MAX_ATTEMPTS, 5),
    },
  },

  cors: buildCorsConfig(),
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    file: process.env.LOG_FILE || 'logs/app.log',
  },
  i18n: {
    defaultLanguage: process.env.DEFAULT_LANGUAGE || 'en',
    debug: process.env.DEBUG_I18N === 'true' && process.env.NODE_ENV !== 'production',
  },
  redis: {
    url: process.env.REDIS_URL,
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: parseNumber(process.env.REDIS_PORT, 6379),
    password: process.env.REDIS_PASSWORD,
    db: parseNumber(process.env.REDIS_DB, 0),
    tls: process.env.REDIS_TLS === 'true',
    keyPrefix: process.env.REDIS_KEY_PREFIX || 'apd:',
  },

  audit: {
    export: {
      maxRows: parseNumber(process.env.AUDIT_EXPORT_MAX_ROWS, 50000),
      maxRangeDays: parseNumber(process.env.AUDIT_EXPORT_MAX_RANGE_DAYS, 31)
    },
    exportRate: {
      windowMs: parseNumber(process.env.AUDIT_EXPORT_RATE_WINDOW_MS, 60 * 1000),
      max: parseNumber(process.env.AUDIT_EXPORT_RATE_MAX, 5)
    }
  }
};

const validationErrors = [
  ...(process.env.MONGODB_URI ? [] : ['MONGODB_URI is required']),
  validateJwtSecret(process.env.JWT_ACCESS_SECRET, 'JWT_ACCESS_SECRET'),
  validateJwtSecret(process.env.JWT_REFRESH_SECRET, 'JWT_REFRESH_SECRET'),
].filter(Boolean);

if (validationErrors.length > 0) {
  console.error('Configuration errors:', validationErrors.join(', '));
  process.exit(1);
}

module.exports = config;
