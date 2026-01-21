const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../config');

let privateKey, publicKey, publicKeyJwk;

/**
 * Load existing keys from disk or generate new ones
 */
function loadOrGenerateKeys() {
  try {
    if (fs.existsSync(config.keyFile)) {
      const keyData = JSON.parse(fs.readFileSync(config.keyFile, 'utf8'));
      privateKey = crypto.createPrivateKey({
        key: Buffer.from(keyData.privateKey, 'base64'),
        format: 'der',
        type: 'pkcs8'
      });
      publicKey = crypto.createPublicKey({
        key: Buffer.from(keyData.publicKey, 'base64'),
        format: 'der',
        type: 'spki'
      });
      publicKeyJwk = publicKey.export({ format: 'jwk' });
      console.log('Loaded existing Ed25519 key pair from disk');
      return;
    }
  } catch (e) {
    console.log('Could not load existing keys:', e.message);
  }

  // Generate new keys
  const keyPair = crypto.generateKeyPairSync('ed25519');
  privateKey = keyPair.privateKey;
  publicKey = keyPair.publicKey;
  publicKeyJwk = publicKey.export({ format: 'jwk' });

  // Save keys to disk
  try {
    const dir = path.dirname(config.keyFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const keyData = {
      privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      publicKey: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      createdAt: new Date().toISOString()
    };
    fs.writeFileSync(config.keyFile, JSON.stringify(keyData, null, 2));
    console.log('Generated and saved new Ed25519 key pair');
  } catch (e) {
    console.log('Could not save keys:', e.message);
    console.log('Generated Ed25519 key pair (not persisted)');
  }
}

/**
 * Get the public key in JWK format for JWKS endpoint
 */
function getPublicKeyJwk() {
  return publicKeyJwk;
}

/**
 * Generate a JWT token with proper Ed25519 signing
 */
function generateToken(payload) {
  const header = Buffer.from(JSON.stringify({
    alg: 'EdDSA',
    kid: config.keyId,
    typ: 'JWT'
  })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${header}.${body}`;

  const signature = crypto.sign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

/**
 * Generate identity token for the game client/server
 */
function generateIdentityToken(uuid, name, entitlements = ['game.base']) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + config.sessionTtl;

  return generateToken({
    sub: uuid,
    name: name,
    username: name,
    entitlements: entitlements,
    scope: 'hytale:server hytale:client',
    iat: now,
    exp: exp,
    iss: `https://sessions.${config.domain}`,
    jti: crypto.randomUUID()
  });
}

/**
 * Generate session token for the game server
 */
function generateSessionToken(uuid) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + config.sessionTtl;

  return generateToken({
    sub: uuid,
    scope: 'hytale:server',
    iat: now,
    exp: exp,
    iss: `https://sessions.${config.domain}`,
    jti: crypto.randomUUID()
  });
}

/**
 * Generate authorization grant token for server connection
 */
function generateAuthorizationGrant(uuid, name, audience) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + config.sessionTtl;

  return generateToken({
    sub: uuid,
    name: name,
    username: name,
    aud: audience,
    scope: 'hytale:server hytale:client',
    iat: now,
    exp: exp,
    iss: `https://sessions.${config.domain}`,
    jti: crypto.randomUUID()
  });
}

/**
 * Generate access token with audience and optional certificate binding
 */
function generateAccessToken(uuid, name, audience, certFingerprint = null) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + config.sessionTtl;

  const tokenPayload = {
    sub: uuid,
    name: name,
    username: name,
    aud: audience,
    entitlements: ['game.base'],
    scope: 'hytale:server hytale:client',
    iat: now,
    exp: exp,
    iss: `https://sessions.${config.domain}`,
    jti: crypto.randomUUID()
  };

  if (certFingerprint) {
    tokenPayload.cnf = {
      'x5t#S256': certFingerprint
    };
  }

  return generateToken(tokenPayload);
}

/**
 * Extract UUID and name from a JWT token string
 */
function parseToken(tokenString) {
  try {
    const parts = tokenString.split('.');
    if (parts.length >= 2) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      return {
        uuid: payload.sub,
        name: payload.username || payload.name,
        scope: payload.scope,
        aud: payload.aud
      };
    }
  } catch (e) {
    // Invalid token format
  }
  return null;
}

/**
 * Extract server audience from bearer token in headers
 */
function extractServerAudienceFromHeaders(headers) {
  if (!headers || !headers.authorization) return null;

  try {
    const token = headers.authorization.replace('Bearer ', '');
    const parts = token.split('.');
    if (parts.length >= 2) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      if (payload.aud) {
        return payload.aud;
      }
      if (payload.scope === 'hytale:server' && payload.sub) {
        return payload.sub;
      }
    }
  } catch (e) {
    // Silent fail - token parsing is optional
  }
  return null;
}

// Initialize keys on module load
loadOrGenerateKeys();

module.exports = {
  loadOrGenerateKeys,
  getPublicKeyJwk,
  generateToken,
  generateIdentityToken,
  generateSessionToken,
  generateAuthorizationGrant,
  generateAccessToken,
  parseToken,
  extractServerAudienceFromHeaders,
};
