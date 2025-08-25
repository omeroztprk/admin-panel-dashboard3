require('dotenv').config();
const mongoose = require('mongoose');
const config = require('./src/config');
const connectDB = require('./src/config/database');
const { connectRedis, getRedis } = require('./src/config/redis');

let server;
const { startKeycloakPeriodicSync, stopKeycloakPeriodicSync } = require('./src/services/keycloakSyncService');

async function startServer() {
  try {
    // 0) Redis (optional)
    await connectRedis({ optional: true });

    // App factory
    const createApp = require('./src/app');

    // 1) DB
    await connectDB();
    if (config.env !== 'production') console.log('Database connected');

    // 2) App
    const app = await createApp();
    if (config.env !== 'production') console.log('App initialized');

    // 3) Server
    server = app.listen(config.port, () => {
      console.log(`Server running on port ${config.port}${config.env !== 'production' ? ` (${config.env})` : ''}`);
    });

    // Keep-Alive 
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;

    // ADD: optional periodic sync
    startKeycloakPeriodicSync();
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

async function shutdown(exitCode = 0) {
  try {
    // ADD: stop sync
    stopKeycloakPeriodicSync();
    if (server) await new Promise((resolve) => server.close(resolve));
    await mongoose.connection.close().catch(() => { });
    const redis = getRedis();
    if (redis?.isOpen) await redis.quit();
  } catch (err) {
    console.error('Shutdown error:', err);
  } finally {
    process.exit(exitCode);
  }
}

process.on('SIGTERM', () => { console.log('Shutting down gracefully (SIGTERM)...'); shutdown(0); });
process.on('SIGINT', () => { console.log('Shutting down gracefully (SIGINT)...'); shutdown(0); });
process.on('unhandledRejection', (err) => { console.error('UnhandledRejection:', err); shutdown(1); });
process.on('uncaughtException', (err) => { console.error('UncaughtException:', err); shutdown(1); });

startServer();
