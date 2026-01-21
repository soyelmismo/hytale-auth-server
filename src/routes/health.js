const config = require('../config');
const auth = require('../services/auth');
const { sendJson } = require('../utils/response');

/**
 * Health check endpoint
 */
function handleHealth(req, res) {
  sendJson(res, 200, { status: 'ok', server: 'hytale-auth', domain: config.domain });
}

/**
 * JWKS endpoint for JWT signature verification
 */
function handleJwks(req, res) {
  const publicKeyJwk = auth.getPublicKeyJwk();
  sendJson(res, 200, {
    keys: [{
      kty: publicKeyJwk.kty,
      crv: publicKeyJwk.crv,
      x: publicKeyJwk.x,
      kid: config.keyId,
      use: 'sig',
      alg: 'EdDSA'
    }]
  });
}

module.exports = {
  handleHealth,
  handleJwks,
};
