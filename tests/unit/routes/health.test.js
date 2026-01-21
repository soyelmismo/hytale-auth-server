// Mock dependencies
jest.mock('../../../src/services/auth');

const auth = require('../../../src/services/auth');
const healthRoutes = require('../../../src/routes/health');

describe('Health Routes', () => {
  let mockRes;

  beforeEach(() => {
    jest.clearAllMocks();
    mockRes = {
      writeHead: jest.fn(),
      end: jest.fn(),
    };

    auth.getPublicKeyJwk.mockReturnValue({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'test-key',
    });
  });

  describe('handleHealth', () => {
    it('should return health status', () => {
      const req = {};

      healthRoutes.handleHealth(req, mockRes);

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
      const response = JSON.parse(mockRes.end.mock.calls[0][0]);
      expect(response.status).toBe('ok');
      expect(response.server).toBe('hytale-auth');
      expect(response.domain).toBeDefined();
    });
  });

  describe('handleJwks', () => {
    it('should return JWKS with public key', () => {
      const req = {};

      healthRoutes.handleJwks(req, mockRes);

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
      const response = JSON.parse(mockRes.end.mock.calls[0][0]);
      expect(response.keys).toBeDefined();
      expect(response.keys).toHaveLength(1);
      expect(response.keys[0].kty).toBe('OKP');
      expect(response.keys[0].alg).toBe('EdDSA');
      expect(response.keys[0].use).toBe('sig');
    });
  });
});
