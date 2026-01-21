const zlib = require('zlib');

/**
 * Send JSON response with optional gzip compression
 */
function sendJson(res, status, data, req = null) {
  const json = JSON.stringify(data);

  // Check if client accepts gzip and response is large enough to benefit
  const acceptEncoding = req?.headers?.['accept-encoding'] || '';
  if (acceptEncoding.includes('gzip') && json.length > 1024) {
    zlib.gzip(json, (err, compressed) => {
      if (err) {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(json);
      } else {
        res.writeHead(status, {
          'Content-Type': 'application/json',
          'Content-Encoding': 'gzip'
        });
        res.end(compressed);
      }
    });
  } else {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(json);
  }
}

/**
 * Send HTML response
 */
function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html' });
  res.end(html);
}

/**
 * Send binary response
 */
function sendBinary(res, status, data, contentType, headers = {}) {
  res.writeHead(status, { 'Content-Type': contentType, ...headers });
  res.end(data);
}

/**
 * Send no content response
 */
function sendNoContent(res) {
  res.writeHead(204);
  res.end();
}

module.exports = {
  sendJson,
  sendHtml,
  sendBinary,
  sendNoContent,
};
