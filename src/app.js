const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const hpp = require('hpp');
const session = require('express-session');
const passport = require('passport');

const config = require('./config');
const routes = require('./routes');
const auditMiddleware = require('./middleware/audit');
const errorHandler = require('./middleware/errorHandler');
const securityMiddleware = require('./middleware/security');
const logger = require('./utils/logger');
const { addTranslationHelper, initializeI18n, i18next } = require('./config/i18n');
const { initializeEmailService } = require('./services/emailService');

const { getRedis } = require('./config/redis');
const RedisStore = require('connect-redis').default;

const createApp = async () => {
  const app = express();

  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  await initializeI18n();
  initializeEmailService();

  if (['SSO', 'HYBRID'].includes(config.auth.mode)) {
    let store;
    try {
      const redis = getRedis();
      if (redis && redis.isOpen) {
        store = new RedisStore({ client: redis, prefix: config.session.redis.prefix });
        console.log('Session store: Redis');
      }
    } catch (e) {
      console.warn('Redis store init failed, falling back to MemoryStore:', e?.message || e);
    }

    const sessionOptions = {
      secret: config.session.secret,
      resave: false,
      saveUninitialized: false,
      cookie: { ...config.session.cookie, maxAge: config.session.ttlMs },
    };
    if (store) sessionOptions.store = store;

    app.use(session(sessionOptions));
    app.use(passport.initialize());
    app.use(passport.session());
  }

  // Security & helpers
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors(config.cors));
  app.options('*', cors(config.cors));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));
  app.use(mongoSanitize());
  app.use(hpp({ whitelist: ['page', 'limit', 'sort'] }));
  app.use(compression());
  app.use(config.env === 'development' ? morgan('dev') : morgan('combined', { stream: logger.stream }));
  app.use(cookieParser());

  // i18n
  app.use(require('i18next-http-middleware').handle(i18next));
  app.use(addTranslationHelper);

  // Rate limit & audit
  app.use(securityMiddleware.buildGlobalRateLimiter());
  app.use(auditMiddleware.logRequest);

  // Routes
  app.use('/api/v1', routes);

  // Root → info
  app.get('/', (_req, res) => res.redirect('/api/v1/info'));

  // Errors
  app.use(errorHandler.notFound);
  app.use(errorHandler.globalErrorHandler);

  return app;
};

module.exports = createApp;
