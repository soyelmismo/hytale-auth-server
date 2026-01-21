const Redis = require('ioredis');
const config = require('../config');

// Redis client with connection handling
const redis = new Redis(config.redisUrl, {
  retryDelayOnFailover: 100,
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});

let redisConnected = false;

redis.on('connect', () => {
  console.log('Connected to Redis/Kvrocks');
  redisConnected = true;
});

redis.on('error', (err) => {
  console.error('Redis connection error:', err.message);
  redisConnected = false;
});

redis.on('close', () => {
  console.log('Redis connection closed');
  redisConnected = false;
});

/**
 * Check if Redis is connected
 * @returns {boolean}
 */
function isConnected() {
  return redisConnected;
}

/**
 * Connect to Redis
 * @returns {Promise<void>}
 */
async function connect() {
  try {
    await redis.connect();
    console.log('Redis client connected');
  } catch (e) {
    console.error('Failed to connect to Redis:', e.message);
    console.log('Server will continue but data will not persist!');
  }
}

module.exports = {
  redis,
  isConnected,
  connect,
};
