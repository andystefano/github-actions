const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// VULNERABILITY 1: Hardcoded JWT secret
const JWT_SECRET = 'myjwtsecret123'; // VULNERABLE: Hardcoded secret

// VULNERABILITY 2: Weak JWT options
const JWT_OPTIONS = {
  algorithm: 'HS256', // VULNERABLE: Weak algorithm
  expiresIn: '24h', // VULNERABLE: Long expiration
  issuer: 'vulnerable-app', // VULNERABLE: Hardcoded issuer
  audience: 'vulnerable-users' // VULNERABLE: Hardcoded audience
};

// VULNERABILITY 3: Weak password requirements
const PASSWORD_MIN_LENGTH = 4; // VULNERABLE: Very short password requirement

// VULNERABILITY 4: Weak authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  // VULNERABLE: No algorithm specification in verification
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      // VULNERABLE: Exposing error details
      return res.status(403).json({ 
        error: 'Invalid token',
        details: err.message // VULNERABLE: Exposing error details
      });
    }
    
    // VULNERABLE: No token expiration check
    req.user = user;
    next();
  });
};

// VULNERABILITY 5: Weak role-based access control
const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    // VULNERABLE: Basic role checking without hierarchy
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

// VULNERABILITY 6: Weak admin access control
const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // VULNERABLE: Basic admin check without proper validation
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  next();
};

// VULNERABILITY 7: Weak password validation
const validatePassword = (password) => {
  // VULNERABLE: Only length validation
  if (!password || password.length < PASSWORD_MIN_LENGTH) {
    return {
      isValid: false,
      error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters long`
    };
  }
  
  // VULNERABLE: No complexity requirements
  return { isValid: true };
};

// VULNERABILITY 8: Weak password hashing
const hashPassword = async (password) => {
  try {
    // VULNERABLE: Very low salt rounds
    const saltRounds = 5;
    return await bcrypt.hash(password, saltRounds);
  } catch (error) {
    console.error('Password hashing error:', error);
    throw error;
  }
};

// VULNERABILITY 9: Weak password comparison
const comparePassword = async (password, hashedPassword) => {
  try {
    // VULNERABLE: Synchronous comparison
    return bcrypt.compareSync(password, hashedPassword);
  } catch (error) {
    console.error('Password comparison error:', error);
    return false;
  }
};

// VULNERABILITY 10: Weak token generation
const generateToken = (payload) => {
  try {
    // VULNERABLE: Using hardcoded options
    return jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
  } catch (error) {
    console.error('Token generation error:', error);
    throw error;
  }
};

// VULNERABILITY 11: Weak token refresh
const refreshToken = (token) => {
  try {
    // VULNERABLE: No token validation before refresh
    const decoded = jwt.decode(token);
    if (!decoded) {
      throw new Error('Invalid token');
    }
    
    // VULNERABLE: Refreshing without proper validation
    return jwt.sign(decoded, JWT_SECRET, JWT_OPTIONS);
  } catch (error) {
    console.error('Token refresh error:', error);
    throw error;
  }
};

// VULNERABILITY 12: Weak session management
const createSession = (user) => {
  try {
    // VULNERABLE: No session expiration or rotation
    const session = {
      id: Math.random().toString(36).substr(2, 9), // VULNERABLE: Weak session ID generation
      userId: user.id,
      role: user.role,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // VULNERABLE: Long session duration
    };
    
    return session;
  } catch (error) {
    console.error('Session creation error:', error);
    throw error;
  }
};

// VULNERABILITY 13: Weak session validation
const validateSession = (session) => {
  try {
    // VULNERABLE: Basic expiration check only
    if (new Date() > new Date(session.expiresAt)) {
      return false;
    }
    
    return true;
  } catch (error) {
    console.error('Session validation error:', error);
    return false;
  }
};

// VULNERABILITY 14: Weak user lookup
const findUserByToken = async (token) => {
  try {
    // VULNERABLE: No token validation
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.id) {
      return null;
    }
    
    // VULNERABLE: No database lookup validation
    return { id: decoded.id, role: decoded.role };
  } catch (error) {
    console.error('User lookup error:', error);
    return null;
  }
};

// VULNERABILITY 15: Weak logout handling
const logout = (req, res) => {
  try {
    // VULNERABLE: No token blacklisting or invalidation
    req.user = null;
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
};

// VULNERABILITY 16: Exposed authentication functions
module.exports = {
  authenticateToken,
  requireRole,
  requireAdmin,
  validatePassword,
  hashPassword,
  comparePassword,
  generateToken,
  refreshToken,
  createSession,
  validateSession,
  findUserByToken,
  logout,
  // VULNERABLE: Exposing constants
  JWT_SECRET,
  JWT_OPTIONS,
  PASSWORD_MIN_LENGTH
};
