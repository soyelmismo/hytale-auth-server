const { sendJson, sendHtml, sendBinary, sendNoContent } = require('../../../src/utils/response');

describe('Response Utils', () => {
  let mockRes;

  beforeEach(() => {
    mockRes = {
      writeHead: jest.fn(),
      setHeader: jest.fn(),
      end: jest.fn(),
    };
  });

  describe('sendJson', () => {
    it('should send JSON response with correct headers', () => {
      const data = { success: true, message: 'test' };

      sendJson(mockRes, 200, data);

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, {
        'Content-Type': 'application/json',
      });
      expect(mockRes.end).toHaveBeenCalledWith(JSON.stringify(data));
    });

    it('should handle different status codes', () => {
      sendJson(mockRes, 404, { error: 'Not found' });

      expect(mockRes.writeHead).toHaveBeenCalledWith(404, expect.any(Object));
    });

    it('should stringify complex objects', () => {
      const data = {
        users: [{ id: 1 }, { id: 2 }],
        meta: { total: 2 },
      };

      sendJson(mockRes, 200, data);

      expect(mockRes.end).toHaveBeenCalledWith(JSON.stringify(data));
    });
  });

  describe('sendHtml', () => {
    it('should send HTML response with correct headers', () => {
      const html = '<html><body>Test</body></html>';

      sendHtml(mockRes, 200, html);

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, {
        'Content-Type': 'text/html',
      });
      expect(mockRes.end).toHaveBeenCalledWith(html);
    });
  });

  describe('sendBinary', () => {
    it('should send binary data with content type', () => {
      const data = Buffer.from('binary data');

      sendBinary(mockRes, 200, data, 'image/png');

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, {
        'Content-Type': 'image/png',
      });
      expect(mockRes.end).toHaveBeenCalledWith(data);
    });

    it('should include additional headers', () => {
      const data = Buffer.from('data');
      const extraHeaders = { 'Cache-Control': 'max-age=3600' };

      sendBinary(mockRes, 200, data, 'image/jpeg', extraHeaders);

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, {
        'Content-Type': 'image/jpeg',
        'Cache-Control': 'max-age=3600',
      });
    });
  });

  describe('sendNoContent', () => {
    it('should send 204 No Content', () => {
      sendNoContent(mockRes);

      expect(mockRes.writeHead).toHaveBeenCalledWith(204);
      expect(mockRes.end).toHaveBeenCalled();
    });
  });
});
