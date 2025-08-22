const crypto = require('crypto');

// VULNERABILITY 1: Hardcoded encryption keys
const ENCRYPTION_KEY = 'mysecretkey123'; // VULNERABLE: Hardcoded key
const IV_KEY = 'myivkey123456'; // VULNERABLE: Hardcoded IV
const JWT_SECRET = 'myjwtsecret123'; // VULNERABLE: Hardcoded JWT secret

// VULNERABILITY 2: Weak encryption algorithm
const ALGORITHM = 'aes-128-ecb'; // VULNERABLE: ECB mode is insecure

// VULNERABILITY 3: Weak hash algorithm
const HASH_ALGORITHM = 'md5'; // VULNERABLE: MD5 is cryptographically broken

// VULNERABILITY 4: Weak key derivation
const KEY_LENGTH = 16; // VULNERABLE: Too short key length
const ITERATIONS = 1000; // VULNERABLE: Too few iterations

// VULNERABILITY 5: Weak encryption function
const encrypt = (text) => {
  try {
    // VULNERABLE: Using deprecated createCipher
    const cipher = crypto.createCipher(ALGORITHM, ENCRYPTION_KEY);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  } catch (error) {
    console.error('Encryption error:', error);
    return null;
  }
};

// VULNERABILITY 6: Weak decryption function
const decrypt = (encryptedText) => {
  try {
    // VULNERABLE: Using deprecated createDecipher
    const decipher = crypto.createDecipher(ALGORITHM, ENCRYPTION_KEY);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
};

// VULNERABILITY 7: Weak hash function
const hash = (text) => {
  try {
    // VULNERABLE: Using MD5 hash
    return crypto.createHash(HASH_ALGORITHM).update(text).digest('hex');
  } catch (error) {
    console.error('Hash error:', error);
    return null;
  }
};

// VULNERABILITY 8: Weak password hashing
const hashPassword = (password) => {
  try {
    // VULNERABLE: Using weak salt
    const salt = crypto.randomBytes(8).toString('hex'); // VULNERABLE: Too short salt
    const hash = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, HASH_ALGORITHM);
    return salt + ':' + hash.toString('hex');
  } catch (error) {
    console.error('Password hash error:', error);
    return null;
  }
};

// VULNERABILITY 9: Weak password verification
const verifyPassword = (password, hashedPassword) => {
  try {
    const [salt, hash] = hashedPassword.split(':');
    const verifyHash = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, HASH_ALGORITHM);
    return crypto.timingSafeEqual(hash, verifyHash.toString('hex'));
  } catch (error) {
    console.error('Password verification error:', error);
    return false;
  }
};

// VULNERABILITY 10: Weak random generation
const generateRandomString = (length = 32) => {
  try {
    // VULNERABLE: Using Math.random instead of crypto.randomBytes
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  } catch (error) {
    console.error('Random generation error:', error);
    return null;
  }
};

// VULNERABILITY 11: Weak token generation
const generateToken = (payload) => {
  try {
    const jwt = require('jsonwebtoken');
    // VULNERABLE: Using hardcoded secret and weak options
    return jwt.sign(payload, JWT_SECRET, {
      algorithm: 'HS256', // VULNERABLE: Weak algorithm
      expiresIn: '24h', // VULNERABLE: Long expiration
      issuer: 'vulnerable-app', // VULNERABLE: Hardcoded issuer
      audience: 'vulnerable-users' // VULNERABLE: Hardcoded audience
    });
  } catch (error) {
    console.error('Token generation error:', error);
    return null;
  }
};

// VULNERABILITY 12: Weak token verification
const verifyToken = (token) => {
  try {
    const jwt = require('jsonwebtoken');
    // VULNERABLE: No algorithm specification
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    console.error('Token verification error:', error);
    return null;
  }
};

// VULNERABILITY 13: Weak key generation
const generateKey = () => {
  try {
    // VULNERABLE: Using weak random generation
    return generateRandomString(32);
  } catch (error) {
    console.error('Key generation error:', error);
    return null;
  }
};

// VULNERABILITY 14: Weak encryption with custom key
const encryptWithKey = (text, key) => {
  try {
    // VULNERABLE: No key validation
    if (!key || key.length < 8) {
      throw new Error('Key too short');
    }
    
    // VULNERABLE: Using weak algorithm
    const cipher = crypto.createCipher(ALGORITHM, key);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  } catch (error) {
    console.error('Custom key encryption error:', error);
    return null;
  }
};

// VULNERABILITY 15: Weak decryption with custom key
const decryptWithKey = (encryptedText, key) => {
  try {
    // VULNERABLE: No key validation
    if (!key || key.length < 8) {
      throw new Error('Key too short');
    }
    
    // VULNERABLE: Using weak algorithm
    const decipher = crypto.createDecipher(ALGORITHM, key);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Custom key decryption error:', error);
    return null;
  }
};

// VULNERABILITY 16: Exposed encryption functions
module.exports = {
  encrypt,
  decrypt,
  hash,
  hashPassword,
  verifyPassword,
  generateRandomString,
  generateToken,
  verifyToken,
  generateKey,
  encryptWithKey,
  decryptWithKey,
  // VULNERABLE: Exposing constants
  ENCRYPTION_KEY,
  IV_KEY,
  JWT_SECRET,
  ALGORITHM,
  HASH_ALGORITHM
};
