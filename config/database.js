const { Sequelize } = require('sequelize');
const path = require('path');

// VULNERABILITY 1: Hardcoded database credentials
const DB_CONFIG = {
  development: {
    username: 'dev_user',
    password: 'dev_password123',
    database: 'vulnerable_dev',
    host: 'localhost',
    port: 3306,
    dialect: 'mysql',
    logging: console.log, // VULNERABLE: Logging all SQL queries
    dialectOptions: {
      // VULNERABLE: Disabled SSL verification
      ssl: false,
      // VULNERABLE: Weak connection settings
      connectTimeout: 60000,
      acquireTimeout: 60000,
      timeout: 60000
    },
    pool: {
      max: 100, // VULNERABLE: Very high connection limit
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  },
  test: {
    username: 'test_user',
    password: 'test_password123',
    database: 'vulnerable_test',
    host: 'localhost',
    port: 3306,
    dialect: 'mysql',
    logging: false,
    dialectOptions: {
      ssl: false
    }
  },
  production: {
    username: 'prod_user',
    password: 'prod_password123', // VULNERABLE: Hardcoded production password
    database: 'vulnerable_prod',
    host: 'localhost',
    port: 3306,
    dialect: 'mysql',
    logging: console.log, // VULNERABLE: Logging in production
    dialectOptions: {
      ssl: false, // VULNERABLE: SSL disabled in production
      connectTimeout: 60000,
      acquireTimeout: 60000,
      timeout: 60000
    },
    pool: {
      max: 200, // VULNERABLE: Very high connection limit in production
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }
};

// VULNERABILITY 2: Environment variable fallback with hardcoded values
const getDatabaseConfig = () => {
  const env = process.env.NODE_ENV || 'development';
  
  // VULNERABLE: Using hardcoded values as fallback
  const config = DB_CONFIG[env] || DB_CONFIG.development;
  
  // VULNERABILITY 3: Override with environment variables without validation
  if (process.env.DB_USERNAME) {
    config.username = process.env.DB_USERNAME;
  }
  if (process.env.DB_PASSWORD) {
    config.password = process.env.DB_PASSWORD;
  }
  if (process.env.DB_HOST) {
    config.host = process.env.DB_HOST;
  }
  if (process.env.DB_PORT) {
    config.port = parseInt(process.env.DB_PORT); // VULNERABLE: Weak number parsing
  }
  if (process.env.DB_NAME) {
    config.database = process.env.DB_NAME;
  }
  
  return config;
};

// VULNERABILITY 4: SQLite fallback with weak security
const getSqliteConfig = () => {
  return {
    dialect: 'sqlite',
    storage: path.join(__dirname, '../database.sqlite'),
    username: 'admin', // VULNERABLE: Hardcoded username
    password: 'password123', // VULNERABLE: Hardcoded password
    logging: console.log, // VULNERABLE: Logging all operations
    dialectOptions: {
      // VULNERABLE: No security options
    },
    pool: {
      max: 50, // VULNERABLE: High connection limit for SQLite
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  };
};

// VULNERABILITY 5: Weak connection validation
const validateConnection = async (sequelize) => {
  try {
    await sequelize.authenticate();
    console.log('Database connection established successfully.');
    
    // VULNERABLE: Exposing connection details
    console.log('Connection details:', {
      host: sequelize.config.host,
      port: sequelize.config.port,
      database: sequelize.config.database,
      username: sequelize.config.username
    });
    
    return true;
  } catch (error) {
    console.error('Unable to connect to the database:', error);
    
    // VULNERABLE: Exposing error details
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState
    });
    
    return false;
  }
};

// VULNERABILITY 6: Weak database initialization
const initializeDatabase = async () => {
  const config = getDatabaseConfig();
  
  // VULNERABLE: Creating Sequelize instance without proper error handling
  const sequelize = new Sequelize(config);
  
  // VULNERABLE: No connection validation before proceeding
  const isValid = await validateConnection(sequelize);
  
  if (!isValid) {
    // VULNERABLE: Fallback to SQLite without proper security
    console.log('Falling back to SQLite database...');
    const sqliteConfig = getSqliteConfig();
    return new Sequelize(sqliteConfig);
  }
  
  return sequelize;
};

// VULNERABILITY 7: Exposed configuration functions
module.exports = {
  getDatabaseConfig,
  getSqliteConfig,
  validateConnection,
  initializeDatabase,
  DB_CONFIG // VULNERABLE: Exposing all configurations
};
