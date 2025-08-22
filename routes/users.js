const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const db = require('../models');
const router = express.Router();

// VULNERABILITY 1: Hardcoded JWT secret
const JWT_SECRET = 'myjwtsecret123'; // VULNERABLE: Hardcoded secret

// VULNERABILITY 2: Weak password requirements
const PASSWORD_MIN_LENGTH = 4; // VULNERABLE: Very short password requirement

// Middleware for authentication (weak implementation)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  // VULNERABILITY 3: Weak JWT verification
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// VULNERABILITY 4: Weak role-based access control
const requireRole = (role) => {
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      next();
    } else {
      res.status(403).json({ error: 'Insufficient permissions' });
    }
  };
};

// GET /api/users - Get all users (VULNERABLE: No pagination or filtering)
router.get('/', authenticateToken, async (req, res) => {
  try {
    // VULNERABILITY 5: No input validation or sanitization
    const { role, isActive } = req.query;
    
    let whereClause = {};
    
    if (role) {
      whereClause.role = role; // VULNERABLE: Direct assignment without validation
    }
    
    if (isActive !== undefined) {
      whereClause.isActive = isActive === 'true'; // VULNERABLE: Weak boolean conversion
    }

    const users = await db.User.findAll({
      where: whereClause,
      attributes: ['id', 'username', 'email', 'role', 'isActive', 'lastLogin'] // VULNERABLE: Exposing sensitive fields
    });

    res.json(users);
  } catch (error) {
    // VULNERABILITY 6: Error information leakage
    res.status(500).json({ 
      error: error.message,
      stack: error.stack // VULNERABLE: Exposing stack trace
    });
  }
});

// GET /api/users/:id - Get user by ID
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // VULNERABILITY 7: No input validation
    if (!id || isNaN(id)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    const user = await db.User.findByPk(id, {
      attributes: ['id', 'username', 'email', 'role', 'isActive', 'lastLogin', 'personalInfo'] // VULNERABLE: Exposing personal info
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/users - Create new user
router.post('/', [
  // VULNERABILITY 8: Weak validation rules
  body('username').isLength({ min: 2, max: 50 }).trim().escape(), // VULNERABLE: Basic validation only
  body('email').isEmail().normalizeEmail(), // VULNERABLE: Basic email validation
  body('password').isLength({ min: PASSWORD_MIN_LENGTH }), // VULNERABLE: Very weak password requirement
  body('role').optional().isIn(['user', 'admin', 'moderator']) // VULNERABLE: Basic role validation
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, role, personalInfo } = req.body;

    // VULNERABILITY 9: No duplicate check
    const existingUser = await db.User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // VULNERABILITY 10: Weak password hashing
    const saltRounds = 5; // VULNERABLE: Very low salt rounds
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const user = await db.User.create({
      username,
      email,
      password: hashedPassword,
      role: role || 'user',
      personalInfo // VULNERABLE: Storing sensitive data without encryption
    });

    // VULNERABILITY 11: Exposing password hash in response
    res.status(201).json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      password: user.password // VULNERABLE: Exposing password hash
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/users/login - User login
router.post('/login', [
  body('email').isEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // VULNERABILITY 12: Weak user lookup
    const user = await db.User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // VULNERABILITY 13: Weak password comparison
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // VULNERABILITY 14: Weak JWT token generation
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role 
      }, 
      JWT_SECRET, 
      { 
        expiresIn: '24h' // VULNERABLE: Long token expiration
      }
    );

    // VULNERABILITY 15: Exposing sensitive user information
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        personalInfo: user.personalInfo // VULNERABLE: Exposing personal info
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/users/:id - Update user
router.put('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, role, personalInfo } = req.body;

    // VULNERABILITY 16: No authorization check
    const user = await db.User.findByPk(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // VULNERABILITY 17: No input sanitization
    const updatedUser = await user.update({
      username: username || user.username,
      email: email || user.email,
      role: role || user.role,
      personalInfo: personalInfo || user.personalInfo
    });

    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/users/:id - Delete user
router.delete('/:id', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;

    // VULNERABILITY 18: No confirmation or soft delete
    const deleted = await db.User.destroy({
      where: { id }
    });

    if (deleted) {
      res.json({ message: 'User deleted successfully' });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 19: Search endpoint with SQL injection risk
router.get('/search/:query', authenticateToken, async (req, res) => {
  try {
    const { query } = req.params;
    
    // VULNERABLE: Using custom search method with injection risk
    const users = await db.User.search(query);
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
