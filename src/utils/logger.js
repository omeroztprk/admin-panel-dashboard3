const winston = require('winston');
const path = require('path');
const fs = require('fs');
const config = require('../config');

const logLevels = { error: 0, warn: 1, info: 2, http: 3, debug: 4 };
const logColors = { error: 'red', warn: 'yellow', info: 'green', http: 'magenta', debug: 'white' };

winston.addColors(logColors);

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.colorize({ all: true }),
  winston.format.printf((info) => {
    let message = info.message;
    if (typeof message === 'object') message = JSON.stringify(message, null, 2);
    return `${info.timestamp} ${info.level}: ${message}`;
  })
);

const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf((info) => JSON.stringify({
    timestamp: info.timestamp,
    level: info.level,
    message: info.message,
    ...(info.stack && { stack: info.stack }),
    ...info
  }))
);

const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const transports = [
  new winston.transports.Console({ format: logFormat, level: config.logging.level }),
  new winston.transports.File({
    filename: path.join(logsDir, 'error.log'),
    level: 'error',
    format: fileFormat,
    maxsize: 5242880,
    maxFiles: 5
  }),
  new winston.transports.File({
    filename: path.join(logsDir, 'combined.log'),
    format: fileFormat,
    maxsize: 5242880,
    maxFiles: 5
  })
];

if (config.env === 'development') {
  transports.push(
    new winston.transports.File({
      filename: path.join(logsDir, 'debug.log'),
      level: 'debug',
      format: fileFormat,
      maxsize: 5242880,
      maxFiles: 3
    })
  );
}

const logger = winston.createLogger({
  level: config.logging.level,
  levels: logLevels,
  format: fileFormat,
  transports,
  exitOnError: false,
  exceptionHandlers: [
    new winston.transports.File({ filename: path.join(logsDir, 'exceptions.log'), format: fileFormat })
  ],
  rejectionHandlers: [
    new winston.transports.File({ filename: path.join(logsDir, 'rejections.log'), format: fileFormat })
  ]
});

logger.stream = {
  write: (message) => logger.http(message.trim())
};

module.exports = logger;
