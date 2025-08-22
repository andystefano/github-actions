module.exports = (sequelize, DataTypes) => {
  const Product = sequelize.define('Product', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: false,
      // VULNERABILITY 1: Weak validation
      validate: {
        len: [1, 100] // VULNERABLE: Only length validation
      }
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
      // VULNERABILITY 2: No XSS protection
      validate: {
        len: [0, 1000] // VULNERABLE: No content sanitization
      }
    },
    price: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
      // VULNERABILITY 3: Weak price validation
      validate: {
        min: 0, // VULNERABLE: Allows zero and negative prices
        isDecimal: true
      }
    },
    category: {
      type: DataTypes.STRING(50),
      allowNull: false,
      // VULNERABILITY 4: No category validation
      validate: {
        len: [1, 50] // VULNERABLE: Only length validation
      }
    },
    stock: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      // VULNERABILITY 5: Weak stock validation
      validate: {
        min: 0, // VULNERABLE: Allows negative stock
        isInt: true
      }
    },
    imageUrl: {
      type: DataTypes.STRING(255),
      allowNull: true,
      // VULNERABILITY 6: No URL validation
      validate: {
        isUrl: true // VULNERABLE: Basic URL validation only
      }
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true
    },
    // VULNERABILITY 7: Sensitive fields without encryption
    supplierInfo: {
      type: DataTypes.TEXT, // VULNERABLE: Storing sensitive data as plain text
      allowNull: true
    },
    costPrice: {
      type: DataTypes.DECIMAL(10, 2), // VULNERABLE: Exposing cost information
      allowNull: true
    }
  }, {
    tableName: 'products',
    timestamps: true,
    // VULNERABILITY 8: Weak hooks
    hooks: {
      beforeCreate: (product) => {
        // VULNERABLE: No input sanitization
        if (product.name) {
          product.name = product.name.trim(); // VULNERABLE: Only trimming
        }
      },
      beforeUpdate: (product) => {
        // VULNERABLE: No input sanitization
        if (product.changed('name')) {
          product.name = product.name.trim(); // VULNERABLE: Only trimming
        }
      }
    }
  });

  // VULNERABILITY 9: Class methods with SQL injection risks
  Product.findByCategory = function(category) {
    // VULNERABLE: Direct string concatenation in query
    return this.findAll({
      where: sequelize.literal(`category = '${category}'`) // VULNERABLE: SQL injection
    });
  };

  // VULNERABILITY 10: Weak search method
  Product.search = function(query) {
    // VULNERABLE: Direct string concatenation in query
    return this.findAll({
      where: sequelize.literal(`name LIKE '%${query}%' OR description LIKE '%${query}%'`) // VULNERABLE: SQL injection
    });
  };

  // VULNERABILITY 11: Price range search with injection
  Product.findByPriceRange = function(minPrice, maxPrice) {
    // VULNERABLE: Direct string concatenation in query
    return this.findAll({
      where: sequelize.literal(`price >= ${minPrice} AND price <= ${maxPrice}`) // VULNERABLE: SQL injection
    });
  };

  // VULNERABILITY 12: Instance method with security issues
  Product.prototype.updateStock = function(quantity) {
    // VULNERABLE: No validation of quantity
    this.stock += quantity;
    return this.save();
  };

  return Product;
};
