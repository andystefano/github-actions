const express = require('express');
const { body, validationResult } = require('express-validator');
const db = require('../models');
const router = express.Router();

// VULNERABILITY 1: Weak authentication middleware
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  // VULNERABLE: Using hardcoded JWT secret
  const JWT_SECRET = 'myjwtsecret123';
  
  const jwt = require('jsonwebtoken');
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // VULNERABILITY 2: Weak role checking
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    req.user = user;
    next();
  });
};

// VULNERABILITY 3: No rate limiting for admin endpoints

// GET /api/admin/dashboard - Admin dashboard
router.get('/dashboard', authenticateAdmin, async (req, res) => {
  try {
    // VULNERABILITY 4: Exposing sensitive system information
    const stats = {
      totalUsers: await db.User.count(),
      totalProducts: await db.Product.count(),
      totalOrders: await db.Order.count(),
      systemInfo: {
        nodeVersion: process.version,
        platform: process.platform,
        memoryUsage: process.memoryUsage(),
        uptime: process.uptime(),
        env: process.env.NODE_ENV // VULNERABLE: Exposing environment variables
      }
    };

    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/users - Get all users with sensitive data
router.get('/users', authenticateAdmin, async (req, res) => {
  try {
    // VULNERABILITY 5: No pagination or filtering limits
    const { role, isActive, limit } = req.query;
    
    let whereClause = {};
    let queryOptions = {
      attributes: ['id', 'username', 'email', 'role', 'isActive', 'lastLogin', 'personalInfo', 'apiKey'] // VULNERABLE: Exposing all sensitive fields
    };
    
    if (role) {
      whereClause.role = role; // VULNERABLE: Direct assignment without validation
    }
    
    if (isActive !== undefined) {
      whereClause.isActive = isActive === 'true'; // VULNERABLE: Weak boolean conversion
    }
    
    if (limit) {
      queryOptions.limit = parseInt(limit); // VULNERABLE: Weak number parsing
    }
    
    queryOptions.where = whereClause;

    const users = await db.User.findAll(queryOptions);
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/users - Create admin user
router.post('/users', authenticateAdmin, [
  // VULNERABILITY 6: Weak validation rules
  body('username').isLength({ min: 2, max: 50 }),
  body('email').isEmail(),
  body('password').isLength({ min: 4 }), // VULNERABLE: Very weak password requirement
  body('role').isIn(['user', 'admin', 'moderator']),
  body('personalInfo').optional()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, role, personalInfo } = req.body;

    // VULNERABILITY 7: No duplicate check
    const existingUser = await db.User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // VULNERABILITY 8: Weak password hashing
    const bcrypt = require('bcrypt');
    const saltRounds = 5; // VULNERABLE: Very low salt rounds
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const user = await db.User.create({
      username,
      email,
      password: hashedPassword,
      role,
      personalInfo // VULNERABLE: Storing sensitive data without encryption
    });

    res.status(201).json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/admin/users/:id - Update user (VULNERABLE: Can change any user's role)
router.put('/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, role, isActive, personalInfo } = req.body;

    // VULNERABILITY 9: No input validation
    if (!id || isNaN(id)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    const user = await db.User.findByPk(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // VULNERABILITY 10: No authorization check - admin can change any user's role
    const updatedUser = await user.update({
      username: username || user.username,
      email: email || user.email,
      role: role || user.role, // VULNERABLE: Can escalate privileges
      isActive: isActive !== undefined ? isActive : user.isActive,
      personalInfo: personalInfo || user.personalInfo
    });

    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/admin/users/:id - Delete user
router.delete('/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // VULNERABILITY 11: No confirmation or soft delete
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

// GET /api/admin/products - Get all products with sensitive data
router.get('/products', authenticateAdmin, async (req, res) => {
  try {
    // VULNERABILITY 12: Exposing sensitive supplier and cost information
    const products = await db.Product.findAll({
      attributes: ['id', 'name', 'description', 'price', 'category', 'stock', 'imageUrl', 'supplierInfo', 'costPrice', 'createdAt', 'updatedAt']
    });

    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/admin/products - Create product
router.post('/products', authenticateAdmin, [
  // VULNERABILITY 13: Weak validation rules
  body('name').isLength({ min: 1, max: 100 }),
  body('description').optional(),
  body('price').isFloat({ min: 0 }),
  body('category').isLength({ min: 1, max: 50 }),
  body('stock').isInt({ min: 0 }),
  body('imageUrl').optional().isURL(),
  body('supplierInfo').optional(),
  body('costPrice').optional().isFloat({ min: 0 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, description, price, category, stock, imageUrl, supplierInfo, costPrice } = req.body;

    const product = await db.Product.create({
      name,
      description,
      price,
      category,
      stock,
      imageUrl,
      supplierInfo, // VULNERABLE: Storing sensitive data without encryption
      costPrice
    });

    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/admin/orders - Get all orders
router.get('/orders', authenticateAdmin, async (req, res) => {
  try {
    // VULNERABILITY 14: Exposing sensitive payment information
    const orders = await db.Order.findAll({
      include: [
        { model: db.User, attributes: ['id', 'username', 'email'] },
        { model: db.Product, attributes: ['id', 'name', 'price'] }
      ],
      attributes: ['id', 'quantity', 'totalPrice', 'status', 'shippingAddress', 'paymentMethod', 'creditCardInfo', 'trackingNumber', 'notes', 'createdAt']
    });

    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 15: System command execution endpoint
router.post('/execute-command', authenticateAdmin, async (req, res) => {
  try {
    const { command } = req.body;

    // VULNERABLE: Direct command execution without sanitization
    const { exec } = require('child_process');
    exec(command, (error, stdout, stderr) => {
      if (error) {
        return res.status(500).json({ error: error.message });
      }
      res.json({ output: stdout, stderr });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 16: File system access endpoint
router.get('/file/:filename', authenticateAdmin, async (req, res) => {
  try {
    const { filename } = req.params;
    
    // VULNERABLE: Path traversal vulnerability
    const path = require('path');
    const fs = require('fs');
    
    const filePath = path.join(__dirname, '..', '..', filename);
    
    if (fs.existsSync(filePath)) {
      res.sendFile(filePath);
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 17: Database backup endpoint
router.post('/backup', authenticateAdmin, async (req, res) => {
  try {
    // VULNERABLE: No input validation or sanitization
    const { tables } = req.body;
    
    if (tables && Array.isArray(tables)) {
      // VULNERABLE: Direct table access without validation
      const backupData = {};
      for (const tableName of tables) {
        const model = db[tableName.charAt(0).toUpperCase() + tableName.slice(1)];
        if (model) {
          backupData[tableName] = await model.findAll();
        }
      }
      res.json(backupData);
    } else {
      res.status(400).json({ error: 'Tables parameter required' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 18: Search endpoint with SQL injection risk
router.get('/search/:query', authenticateAdmin, async (req, res) => {
  try {
    const { query } = req.params;
    
    // VULNERABLE: Using custom search methods with injection risk
    const users = await db.User.search(query);
    const products = await db.Product.search(query);
    
    res.json({ users, products });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
