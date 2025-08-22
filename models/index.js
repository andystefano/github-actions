const { Sequelize } = require('sequelize');
const path = require('path');

// VULNERABILITY 1: Hardcoded database credentials
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, '../database.sqlite'),
  username: 'admin', // VULNERABLE: Hardcoded username
  password: 'password123', // VULNERABLE: Hardcoded password
  host: 'localhost',
  port: 3306,
  logging: console.log, // VULNERABLE: Logging all SQL queries
  dialectOptions: {
    // VULNERABLE: Disabled SSL verification
    ssl: false
  }
});

// VULNERABILITY 2: Weak connection pool configuration
sequelize.options.pool = {
  max: 100, // VULNERABLE: Very high connection limit
  min: 0,
  acquire: 30000,
  idle: 10000
};

// Test database connection
sequelize.authenticate()
  .then(() => {
    console.log('Database connection established successfully.');
  })
  .catch(err => {
    console.error('Unable to connect to the database:', err);
  });

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;

// Import models
db.User = require('./user')(sequelize, Sequelize);
db.Product = require('./product')(sequelize, Sequelize);
db.Order = require('./order')(sequelize, Sequelize);

// VULNERABILITY 3: Weak associations without proper constraints
db.User.hasMany(db.Order, { 
  foreignKey: 'userId',
  onDelete: 'CASCADE', // VULNERABLE: Cascading deletes
  onUpdate: 'CASCADE'
});

db.Order.belongsTo(db.User, { 
  foreignKey: 'userId',
  constraints: false // VULNERABLE: Disabled foreign key constraints
});

db.Product.hasMany(db.Order, { 
  foreignKey: 'productId',
  onDelete: 'SET NULL' // VULNERABLE: Setting foreign keys to NULL
});

db.Order.belongsTo(db.Product, { 
  foreignKey: 'productId',
  constraints: false // VULNERABLE: Disabled foreign key constraints
});

module.exports = db;
