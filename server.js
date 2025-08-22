const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { exec } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// Import database models and routes
const db = require('./models');
const userRoutes = require('./routes/users');
const productRoutes = require('./routes/products');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 3000;

// VULNERABILITY 1: Weak CORS configuration - allows any origin
app.use(cors({
  origin: '*', // VULNERABLE: Allows any origin
  credentials: true
}));

// VULNERABILITY 2: Disabled security headers
// app.use(helmet()); // VULNERABLE: Security headers disabled

// VULNERABILITY 3: Weak rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // VULNERABLE: Very high limit
  message: 'Too many requests from this IP'
});
app.use(limiter);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// VULNERABILITY 4: Static file serving without restrictions
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// VULNERABILITY 5: Command injection vulnerability
app.post('/execute', (req, res) => {
  const { command } = req.body;
  
  // VULNERABLE: Direct command execution without sanitization
  exec(command, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    res.json({ output: stdout, stderr });
  });
});

// VULNERABILITY 6: Path traversal vulnerability
app.get('/file', (req, res) => {
  const { filename } = req.query;
  
  // VULNERABLE: No path validation
  const filePath = path.join(__dirname, 'uploads', filename);
  
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json({ error: 'File not found' });
  }
});

// VULNERABILITY 7: Weak encryption with hardcoded key
const ENCRYPTION_KEY = 'mysecretkey123'; // VULNERABLE: Hardcoded encryption key

app.post('/encrypt', (req, res) => {
  const { data } = req.body;
  
  // VULNERABLE: Weak encryption algorithm
  const cipher = crypto.createCipher('aes-128-ecb', ENCRYPTION_KEY);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  res.json({ encrypted });
});

app.post('/decrypt', (req, res) => {
  const { encrypted } = req.body;
  
  // VULNERABLE: Weak decryption algorithm
  const decipher = crypto.createDecipher('aes-128-ecb', ENCRYPTION_KEY);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  res.json({ decrypted });
});

// VULNERABILITY 8: JWT secret hardcoded
const JWT_SECRET = 'myjwtsecret123'; // VULNERABLE: Hardcoded JWT secret

// Routes
app.use('/api/users', userRoutes);
app.use('/api/products', productRoutes);
app.use('/api/admin', adminRoutes);

// VULNERABILITY 9: Error handling that leaks sensitive information
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  // VULNERABLE: Exposing internal error details
  res.status(500).json({
    error: err.message,
    stack: err.stack, // VULNERABLE: Exposing stack trace
    sql: err.sql // VULNERABLE: Exposing SQL queries
  });
});

// Database sync and server start
db.sequelize.sync({ force: true }) // VULNERABLE: Force sync in production
  .then(() => {
    console.log('Database synced');
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Database sync error:', err);
  });

module.exports = app;
