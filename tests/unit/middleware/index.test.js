const middleware = require('../../../src/middleware');

// Mock storage module
jest.mock('../../../src/services/storage', () => ({
  setCachedUsername: jest.fn(),
  getCachedUsername: jest.fn(),
  persistUsername: jest.fn(),
  verifyAdminToken: jest.fn(),
}));

// Mock auth module
jest.mock('../../../src/services/auth', () => ({
  parseToken: jest.fn(),
}));

const storage = require('../../../src/services/storage');
const auth = require('../../../src/services/auth');

describe('Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('corsHeaders', () => {
    it('should set CORS headers on response', () => {
      const res = {
        setHeader: jest.fn(),
      };

      middleware.corsHeaders(res);

      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', '*');
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET, POST, PUT, DELETE, OPTIONS'
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization'
      );
    });
  });

  describe('handleOptions', () => {
    it('should handle OPTIONS preflight request', () => {
      const req = {};
      const res = {
        setHeader: jest.fn(),
        writeHead: jest.fn(),
        end: jest.fn(),
      };

      middleware.handleOptions(req, res);

      expect(res.writeHead).toHaveBeenCalledWith(200);
      expect(res.end).toHaveBeenCalled();
    });
  });

  describe('parseBody', () => {
    it('should parse JSON body from request', async () => {
      const body = JSON.stringify({ name: 'test', value: 123 });
      const req = {
        on: jest.fn((event, callback) => {
          if (event === 'data') callback(body);
          if (event === 'end') callback();
        }),
      };

      const result = await middleware.parseBody(req);

      expect(result).toEqual({ name: 'test', value: 123 });
    });

    it('should return empty object for empty body', async () => {
      const req = {
        on: jest.fn((event, callback) => {
          if (event === 'end') callback();
        }),
      };

      const result = await middleware.parseBody(req);

      expect(result).toEqual({});
    });

    it('should return empty object for invalid JSON', async () => {
      const req = {
        on: jest.fn((event, callback) => {
          if (event === 'data') callback('invalid json {{{');
          if (event === 'end') callback();
        }),
      };

      const result = await middleware.parseBody(req);

      expect(result).toEqual({});
    });
  });

  describe('extractUserContext', () => {
    it('should extract UUID and name from body', () => {
      const body = { uuid: 'body-uuid', name: 'BodyName' };
      const headers = {};

      const result = middleware.extractUserContext(body, headers);

      expect(result.uuid).toBe('body-uuid');
      expect(result.name).toBe('BodyName');
    });

    it('should generate UUID if not provided', () => {
      const body = { name: 'TestName' };
      const headers = {};

      const result = middleware.extractUserContext(body, headers);

      expect(result.uuid).toBeDefined();
      expect(result.uuid).toMatch(/^[0-9a-f-]{36}$/);
    });

    it('should extract from authorization header when present', () => {
      auth.parseToken.mockReturnValue({
        uuid: 'token-uuid',
        name: 'TokenName',
        scope: 'hytale:client',
      });

      const body = {};
      const headers = { authorization: 'Bearer some-token' };

      const result = middleware.extractUserContext(body, headers);

      expect(result.uuid).toBe('token-uuid');
      expect(auth.parseToken).toHaveBeenCalled();
    });

    it('should cache valid username from token', () => {
      auth.parseToken.mockReturnValue({
        uuid: 'cache-uuid',
        name: 'CacheName',
        scope: 'hytale:client',
      });

      const body = {};
      const headers = { authorization: 'Bearer token' };

      middleware.extractUserContext(body, headers);

      expect(storage.setCachedUsername).toHaveBeenCalledWith('cache-uuid', 'CacheName');
    });

    it('should not cache "Player" username from token', () => {
      auth.parseToken.mockReturnValue({
        uuid: 'no-cache-uuid',
        name: 'Player',
        scope: 'hytale:client',
      });

      const body = {};
      const headers = { authorization: 'Bearer token' };

      middleware.extractUserContext(body, headers);

      // Should not be called with 'Player'
      expect(storage.setCachedUsername).not.toHaveBeenCalledWith('no-cache-uuid', 'Player');
    });

    it('should use cached username when body name is Player', () => {
      storage.getCachedUsername.mockReturnValue('CachedName');

      const body = { uuid: 'cached-uuid', name: 'Player' };
      const headers = {};

      const result = middleware.extractUserContext(body, headers);

      expect(result.name).toBe('CachedName');
    });

    it('should default name to Player when not found', () => {
      storage.getCachedUsername.mockReturnValue(undefined);

      const body = { uuid: 'fallback-uuid' };
      const headers = {};

      const result = middleware.extractUserContext(body, headers);

      expect(result.name).toBe('Player');
    });
  });

  describe('verifyAdminAuth', () => {
    it('should return true for valid admin token', async () => {
      storage.verifyAdminToken.mockResolvedValue(true);

      const headers = { 'x-admin-token': 'valid-token' };

      const result = await middleware.verifyAdminAuth(headers);

      expect(result).toBe(true);
      expect(storage.verifyAdminToken).toHaveBeenCalledWith('valid-token');
    });

    it('should return false when no token provided', async () => {
      const headers = {};

      const result = await middleware.verifyAdminAuth(headers);

      expect(result).toBe(false);
      expect(storage.verifyAdminToken).not.toHaveBeenCalled();
    });

    it('should return false for invalid token', async () => {
      storage.verifyAdminToken.mockResolvedValue(false);

      const headers = { 'x-admin-token': 'invalid-token' };

      const result = await middleware.verifyAdminAuth(headers);

      expect(result).toBe(false);
    });
  });
});
