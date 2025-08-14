const mongoose = require('mongoose');
const config = require('./index');

const connectDB = async (retries = 3, delayMs = 2000) => {
  try {
    await mongoose.connect(config.database.uri, {
      maxPoolSize: 10,
      minPoolSize: 1,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      autoIndex: config.env !== 'production',
    });

    if (config.env !== 'production') {
      console.log(`MongoDB Connected: ${mongoose.connection.host}`);
    }

    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('MongoDB disconnected');
    });
  } catch (err) {
    if (retries > 0) {
      console.warn(`Mongo connect failed, retrying in ${delayMs}ms... (${retries})`);
      await new Promise((r) => setTimeout(r, delayMs));
      return connectDB(retries - 1, delayMs * 2);
    }
    console.error('Database connection failed:', err);
    process.exit(1);
  }
};

module.exports = connectDB;
