// Mock dependencies
jest.mock('../../../src/services/assets');
jest.mock('fs');

const assets = require('../../../src/services/assets');
const fs = require('fs');
const assetRoutes = require('../../../src/routes/assets');

describe('Assets Routes', () => {
  let mockRes;

  beforeEach(() => {
    jest.clearAllMocks();
    mockRes = {
      writeHead: jest.fn(),
      end: jest.fn(),
    };

    assets.loadCosmeticConfigs.mockReturnValue({
      haircut: {
        style1: { name: 'Style 1', model: 'path/to/model' },
        style2: { name: 'Style 2', model: 'path/to/model2' },
      },
      pants: {
        jeans: { name: 'Jeans' },
      },
    });
    assets.loadGradientSets.mockReturnValue([
      { id: 'gradient1', colors: ['#fff', '#000'] },
    ]);
    assets.extractAsset.mockReturnValue(null);
    fs.existsSync.mockReturnValue(false);
  });

  describe('handleCosmeticsList', () => {
    it('should return cosmetics categories and gradients', () => {
      const req = {};

      assetRoutes.handleCosmeticsList(req, mockRes);

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
      const response = JSON.parse(mockRes.end.mock.calls[0][0]);
      expect(response.categories).toBeDefined();
      expect(response.categories.haircut).toBeDefined();
      expect(response.gradientSets).toBeDefined();
    });

    it('should handle null configs', () => {
      assets.loadCosmeticConfigs.mockReturnValue(null);

      const req = {};

      assetRoutes.handleCosmeticsList(req, mockRes);

      const response = JSON.parse(mockRes.end.mock.calls[0][0]);
      expect(response.categories).toEqual({});
    });
  });

  describe('handleCosmeticItem', () => {
    it('should return specific cosmetic item', () => {
      const req = {};

      assetRoutes.handleCosmeticItem(req, mockRes, '/cosmetics/item/haircut/style1');

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
      const response = JSON.parse(mockRes.end.mock.calls[0][0]);
      expect(response.category).toBe('haircut');
      expect(response.item.name).toBe('Style 1');
    });

    it('should return 400 for invalid path', () => {
      const req = {};

      assetRoutes.handleCosmeticItem(req, mockRes, '/cosmetics/item/onlyCategory');

      expect(mockRes.writeHead).toHaveBeenCalledWith(400, expect.any(Object));
    });

    it('should return 404 for unknown category', () => {
      const req = {};

      assetRoutes.handleCosmeticItem(req, mockRes, '/cosmetics/item/unknown/item');

      expect(mockRes.writeHead).toHaveBeenCalledWith(404, expect.any(Object));
    });

    it('should return 404 for unknown item', () => {
      const req = {};

      assetRoutes.handleCosmeticItem(req, mockRes, '/cosmetics/item/haircut/unknown');

      expect(mockRes.writeHead).toHaveBeenCalledWith(404, expect.any(Object));
    });
  });

  describe('handleStaticAssets', () => {
    it('should serve static file when exists', () => {
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(Buffer.from('file content'));

      const req = {};

      assetRoutes.handleStaticAssets(req, mockRes, '/assets/script.js');

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.objectContaining({
        'Content-Type': 'application/javascript',
      }));
    });

    it('should return 404 for missing file', () => {
      fs.existsSync.mockReturnValue(false);

      const req = {};

      assetRoutes.handleStaticAssets(req, mockRes, '/assets/missing.js');

      expect(mockRes.writeHead).toHaveBeenCalledWith(404);
    });

    it('should set correct content type for CSS', () => {
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(Buffer.from('body {}'));

      const req = {};

      assetRoutes.handleStaticAssets(req, mockRes, '/assets/style.css');

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.objectContaining({
        'Content-Type': 'text/css',
      }));
    });

    it('should set correct content type for PNG', () => {
      fs.existsSync.mockReturnValue(true);
      fs.readFileSync.mockReturnValue(Buffer.from('png data'));

      const req = {};

      assetRoutes.handleStaticAssets(req, mockRes, '/assets/image.png');

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.objectContaining({
        'Content-Type': 'image/png',
      }));
    });
  });

  describe('handleAssetRoute', () => {
    it('should extract and return asset from zip', () => {
      assets.extractAsset.mockReturnValue(Buffer.from('asset data'));

      const req = {};

      assetRoutes.handleAssetRoute(req, mockRes, '/asset/path/to/model.json');

      expect(assets.extractAsset).toHaveBeenCalledWith('path/to/model.json');
      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.objectContaining({
        'Content-Type': 'application/json',
      }));
    });

    it('should return 400 for empty path', () => {
      const req = {};

      assetRoutes.handleAssetRoute(req, mockRes, '/asset/');

      expect(mockRes.writeHead).toHaveBeenCalledWith(400, expect.any(Object));
    });

    it('should return 404 when asset not found', () => {
      assets.extractAsset.mockReturnValue(null);

      const req = {};

      assetRoutes.handleAssetRoute(req, mockRes, '/asset/missing/file');

      expect(mockRes.writeHead).toHaveBeenCalledWith(404);
    });

    it('should set PNG content type for PNG files', () => {
      assets.extractAsset.mockReturnValue(Buffer.from('png'));

      const req = {};

      assetRoutes.handleAssetRoute(req, mockRes, '/asset/texture.png');

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.objectContaining({
        'Content-Type': 'image/png',
      }));
    });
  });
});
