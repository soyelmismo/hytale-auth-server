// Jest test setup
// Create a shared mock Redis instance
const mockRedis = {
  _data: new Map(),
  _ttls: new Map(),

  get: jest.fn(async (key) => mockRedis._data.get(key) || null),
  set: jest.fn(async (key, value) => {
    mockRedis._data.set(key, value);
    return 'OK';
  }),
  setex: jest.fn(async (key, ttl, value) => {
    mockRedis._data.set(key, value);
    mockRedis._ttls.set(key, ttl);
    return 'OK';
  }),
  del: jest.fn(async (key) => {
    mockRedis._data.delete(key);
    mockRedis._ttls.delete(key);
    return 1;
  }),
  exists: jest.fn(async (key) => mockRedis._data.has(key) ? 1 : 0),
  expire: jest.fn(async (key, ttl) => {
    if (mockRedis._data.has(key)) {
      mockRedis._ttls.set(key, ttl);
      return 1;
    }
    return 0;
  }),
  ttl: jest.fn(async (key) => mockRedis._ttls.get(key) || -1),
  keys: jest.fn(async (pattern) => {
    const prefix = pattern.replace('*', '');
    return Array.from(mockRedis._data.keys()).filter(k => k.startsWith(prefix));
  }),
  scan: jest.fn(async () => ['0', []]),
  sadd: jest.fn(async (key, value) => {
    if (!mockRedis._data.has(key)) {
      mockRedis._data.set(key, new Set());
    }
    mockRedis._data.get(key).add(value);
    return 1;
  }),
  srem: jest.fn(async (key, value) => {
    const set = mockRedis._data.get(key);
    if (set) {
      set.delete(value);
      return 1;
    }
    return 0;
  }),
  smembers: jest.fn(async (key) => {
    const set = mockRedis._data.get(key);
    return set ? Array.from(set) : [];
  }),
  scard: jest.fn(async (key) => {
    const set = mockRedis._data.get(key);
    return set ? set.size : 0;
  }),
  on: jest.fn(),
  connect: jest.fn(),
  disconnect: jest.fn(),
  quit: jest.fn(),

  // Helper to clear mock data between tests
  __clear: () => {
    mockRedis._data.clear();
    mockRedis._ttls.clear();
  }
};

// Mock ioredis to return the shared mock
jest.mock('ioredis', () => {
  return jest.fn(() => mockRedis);
});

// Mock the redis service module to use the shared mock
jest.mock('../src/services/redis', () => ({
  redis: mockRedis,
  isConnected: jest.fn(() => true),
  connect: jest.fn(),
}));

// Make mockRedis available globally for tests
global.mockRedis = mockRedis;

// Suppress console.log during tests unless DEBUG is set
if (!process.env.DEBUG) {
  global.console = {
    ...console,
    log: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
  };
}

// Global test utilities
global.testUtils = {
  generateUUID: () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  },
};
