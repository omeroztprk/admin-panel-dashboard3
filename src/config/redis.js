const { createClient } = require('redis');
const config = require('./index');

let redisClient;

const connectRedis = async ({ optional = true } = {}) => {
  if (redisClient?.isOpen) return redisClient;

  const opts = {};
  if (config.redis.url) {
    opts.url = config.redis.url;
  } else {
    opts.socket = { host: config.redis.host, port: config.redis.port };
    if (config.redis.tls) opts.socket.tls = true;
    if (config.redis.password) opts.password = config.redis.password;
    if (typeof config.redis.db === 'number') opts.database = config.redis.db;
  }
  opts.socket = { ...(opts.socket || {}), reconnectStrategy: (retries) => Math.min(1000 * retries, 10000) };

  redisClient = createClient(opts);

  redisClient.on('error', (err) => console.error('Redis error:', err));
  redisClient.on('reconnecting', () => console.warn('Redis reconnecting...'));
  redisClient.on('ready', () => {
    if (config.env !== 'production') console.log('Redis ready');
  });

  try {
    await redisClient.connect();
    return redisClient;
  } catch (err) {
    if (optional) {
      console.warn('Redis connection failed; continuing with in-memory fallback.');
      return null;
    }
    throw err;
  }
};

const getRedis = () => redisClient;
const prefixKey = (key) => `${config.redis.keyPrefix}${key}`;

module.exports = { connectRedis, getRedis, prefixKey };
