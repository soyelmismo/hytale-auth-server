describe('Config', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should have default port 3000', () => {
    const config = require('../../../src/config');
    expect(config.port).toBe(3000);
  });

  it('should use PORT environment variable', () => {
    process.env.PORT = '8080';
    const config = require('../../../src/config');
    expect(config.port).toBe(8080);
  });

  it('should have default domain', () => {
    const config = require('../../../src/config');
    expect(config.domain).toBeDefined();
    expect(typeof config.domain).toBe('string');
  });

  it('should use DOMAIN environment variable', () => {
    process.env.DOMAIN = 'test.example.com';
    const config = require('../../../src/config');
    expect(config.domain).toBe('test.example.com');
  });

  it('should have Redis URL configuration', () => {
    const config = require('../../../src/config');
    expect(config.redisUrl).toBeDefined();
  });

  it('should have admin password configuration', () => {
    const config = require('../../../src/config');
    expect(config.adminPassword).toBeDefined();
  });

  it('should have session TTL configuration', () => {
    const config = require('../../../src/config');
    expect(config.sessionTtl).toBeGreaterThan(0);
  });

  it('should have Redis key prefixes', () => {
    const config = require('../../../src/config');
    expect(config.redisKeys).toBeDefined();
    expect(config.redisKeys.SESSION).toBeDefined();
    expect(config.redisKeys.AUTH_GRANT).toBeDefined();
    expect(config.redisKeys.USER).toBeDefined();
    expect(config.redisKeys.SERVER_PLAYERS).toBeDefined();
  });

  it('should have derived paths', () => {
    const config = require('../../../src/config');
    expect(config.keyFile).toBeDefined();
    expect(config.headCacheDir).toBeDefined();
  });
});
