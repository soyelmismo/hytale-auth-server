const assets = require('../services/assets');
const { sendJson, sendBinary } = require('../utils/response');

/**
 * Cosmetics list API endpoint
 */
function handleCosmeticsList(req, res) {
  const configs = assets.loadCosmeticConfigs();
  const gradientSets = assets.loadGradientSets();

  if (!configs) {
    sendJson(res, 200, { categories: {}, gradientSets: [] });
    return;
  }

  sendJson(res, 200, {
    categories: configs,
    gradientSets: gradientSets || []
  });
}

/**
 * Single cosmetic item data API (for 3D thumbnail rendering)
 */
function handleCosmeticItem(req, res, urlPath) {
  const parts = urlPath.replace('/cosmetics/item/', '').split('/');
  if (parts.length < 2) {
    sendJson(res, 400, { error: 'Category and item ID required' });
    return;
  }

  const category = parts[0];
  const itemId = parts[1];

  const configs = assets.loadCosmeticConfigs();
  const gradientSets = assets.loadGradientSets();

  if (!configs || !configs[category] || !configs[category][itemId]) {
    sendJson(res, 404, { error: 'Item not found' });
    return;
  }

  const item = configs[category][itemId];
  sendJson(res, 200, {
    category,
    item,
    gradientSets: gradientSets || []
  });
}

/**
 * Static assets route (for js, css, etc from assets folder)
 */
function handleStaticAssets(req, res, urlPath) {
  const fs = require('fs');
  const path = require('path');

  const relativePath = urlPath.replace('/assets/', '');
  const filePath = path.join(__dirname, '../../assets', relativePath);

  if (!fs.existsSync(filePath)) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentTypes = {
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.html': 'text/html',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
  };

  const contentType = contentTypes[ext] || 'application/octet-stream';
  const content = fs.readFileSync(filePath);

  sendBinary(res, 200, content, contentType, {
    'Cache-Control': 'public, max-age=3600'
  });
}

/**
 * Handle asset extraction route (extract from Assets.zip)
 */
function handleAssetRoute(req, res, urlPath) {
  const assetPath = urlPath.replace('/asset/', '');

  if (!assetPath) {
    sendJson(res, 400, { error: 'Asset path required' });
    return;
  }

  const content = assets.extractAsset(assetPath);

  if (!content) {
    res.writeHead(404);
    res.end('Asset not found');
    return;
  }

  // Determine content type
  let contentType = 'application/octet-stream';
  if (assetPath.endsWith('.json') || assetPath.endsWith('.blockymodel') || assetPath.endsWith('.blockyanim')) {
    contentType = 'application/json';
  } else if (assetPath.endsWith('.png')) {
    contentType = 'image/png';
  } else if (assetPath.endsWith('.jpg') || assetPath.endsWith('.jpeg')) {
    contentType = 'image/jpeg';
  }

  sendBinary(res, 200, content, contentType, {
    'Cache-Control': 'public, max-age=86400'
  });
}

module.exports = {
  handleCosmeticsList,
  handleCosmeticItem,
  handleStaticAssets,
  handleAssetRoute,
};
