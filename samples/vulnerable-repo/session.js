// Sample session module with deliberate cryptographic flaws.

const crypto = require('crypto');
const https = require('https');

// ECDAT-017: hardcoded secret
const JWT_SECRET = "7bQ9xM2vK5nR8tW1yZ4aC6eG0hJ3lP5s";

// ECDAT-001: MD5 for a security purpose
function fingerprintUser(email) {
  return crypto.createHash('md5').update(email).digest('hex');
}

// ECDAT-002: SHA-1
function legacyEtag(body) {
  return crypto.createHash('sha1').update(body).digest('hex');
}

// ECDAT-011: Math.random used for a token
function sessionKey() {
  return Math.random().toString(36).substring(2);
}

// ECDAT-014: TLS verification disabled
const agent = new https.Agent({ rejectUnauthorized: false });

// ECDAT-005: AES in ECB mode
function encryptCard(data, key) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  return cipher.update(data, 'utf8', 'hex');
}

module.exports = { fingerprintUser, legacyEtag, sessionKey, agent, encryptCard };
