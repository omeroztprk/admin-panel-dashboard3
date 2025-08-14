const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const hpp = require('hpp');

const config = require('./config');
const routes = require('./routes');
const auditMiddleware = require('./middleware/audit');
const errorHandler = require('./middleware/errorHandler');
const securityMiddleware = require('./middleware/security');
const logger = require('./utils/logger');
const { addTranslationHelper, initializeI18n, i18next } = require('./config/i18n');

const createApp = async () => {
  const app = express();

  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  await initializeI18n();

  app.use(helmet({
    contentSecurityPolicy: false
  }));
  app.use(cors(config.cors));
  app.options('*', cors(config.cors));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));
  app.use(mongoSanitize());
  app.use(hpp({ whitelist: ['page', 'limit', 'sort'] }));
  app.use(compression());

  if (config.env === 'development') {
    app.use(morgan('dev'));
  } else {
    app.use(morgan('combined', { stream: logger.stream }));
  }
  app.use(cookieParser());

  app.use(require('i18next-http-middleware').handle(i18next));
  app.use(addTranslationHelper);

  app.use(securityMiddleware.buildGlobalRateLimiter());

  app.use(auditMiddleware.logRequest);

  app.use('/api/v1', routes);

  app.use(errorHandler.notFound);
  app.use(errorHandler.globalErrorHandler);

  return app;
};

module.exports = createApp;
