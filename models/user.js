module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define('User', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    username: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
      // VULNERABILITY 1: Weak validation
      validate: {
        len: [3, 50] // VULNERABLE: Only length validation
      }
    },
    email: {
      type: DataTypes.STRING(100),
      allowNull: false,
      unique: true,
      // VULNERABILITY 2: Weak email validation
      validate: {
        isEmail: true // VULNERABLE: Basic email validation only
      }
    },
    password: {
      type: DataTypes.STRING(255),
      allowNull: false,
      // VULNERABILITY 3: No password strength requirements
      validate: {
        len: [6, 255] // VULNERABLE: Only length validation
      }
    },
    role: {
      type: DataTypes.ENUM('user', 'admin', 'moderator'),
      defaultValue: 'user',
      // VULNERABILITY 4: No role validation
      validate: {
        isIn: [['user', 'admin', 'moderator']] // VULNERABLE: Basic validation only
      }
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true
    },
    lastLogin: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW
    },
    // VULNERABILITY 5: Sensitive fields without encryption
    apiKey: {
      type: DataTypes.STRING(255),
      allowNull: true
    },
    personalInfo: {
      type: DataTypes.TEXT, // VULNERABLE: Storing sensitive data as plain text
      allowNull: true
    }
  }, {
    tableName: 'users',
    timestamps: true,
    // VULNERABILITY 6: Weak hooks for password hashing
    hooks: {
      beforeCreate: async (user) => {
        // VULNERABILITY: Weak password hashing with low salt rounds
        const bcrypt = require('bcrypt');
        const saltRounds = 5; // VULNERABLE: Very low salt rounds
        user.password = await bcrypt.hash(user.password, saltRounds);
      },
      beforeUpdate: async (user) => {
        if (user.changed('password')) {
          // VULNERABILITY: Weak password hashing with low salt rounds
          const bcrypt = require('bcrypt');
          const saltRounds = 5; // VULNERABLE: Very low salt rounds
          user.password = await bcrypt.hash(user.password, saltRounds);
        }
      }
    }
  });

  // VULNERABILITY 7: Instance methods with security issues
  User.prototype.comparePassword = function(candidatePassword) {
    const bcrypt = require('bcrypt');
    // VULNERABLE: Synchronous comparison
    return bcrypt.compareSync(candidatePassword, this.password);
  };

  // VULNERABILITY 8: Class methods with SQL injection risks
  User.findByUsername = function(username) {
    // VULNERABLE: Direct string concatenation in query
    return this.findOne({
      where: sequelize.literal(`username = '${username}'`) // VULNERABLE: SQL injection
    });
  };

  // VULNERABILITY 9: Weak search method
  User.search = function(query) {
    // VULNERABLE: Direct string concatenation in query
    return this.findAll({
      where: sequelize.literal(`username LIKE '%${query}%' OR email LIKE '%${query}%'`) // VULNERABLE: SQL injection
    });
  };

  return User;
};
