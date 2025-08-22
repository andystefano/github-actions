module.exports = (sequelize, DataTypes) => {
  const Order = sequelize.define('Order', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      // VULNERABILITY 1: No foreign key constraint validation
      references: {
        model: 'users',
        key: 'id'
      }
    },
    productId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      // VULNERABILITY 2: No foreign key constraint validation
      references: {
        model: 'products',
        key: 'id'
      }
    },
    quantity: {
      type: DataTypes.INTEGER,
      allowNull: false,
      // VULNERABILITY 3: Weak quantity validation
      validate: {
        min: 1, // VULNERABLE: Allows very large quantities
        isInt: true
      }
    },
    totalPrice: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
      // VULNERABILITY 4: No price validation
      validate: {
        min: 0, // VULNERABLE: Allows zero and negative prices
        isDecimal: true
      }
    },
    status: {
      type: DataTypes.ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled'),
      defaultValue: 'pending',
      // VULNERABILITY 5: No status validation
      validate: {
        isIn: [['pending', 'confirmed', 'shipped', 'delivered', 'cancelled']] // VULNERABLE: Basic validation only
      }
    },
    shippingAddress: {
      type: DataTypes.TEXT,
      allowNull: false,
      // VULNERABILITY 6: No address validation
      validate: {
        len: [10, 500] // VULNERABLE: Only length validation
      }
    },
    paymentMethod: {
      type: DataTypes.STRING(50),
      allowNull: false,
      // VULNERABILITY 7: No payment method validation
      validate: {
        len: [1, 50] // VULNERABLE: Only length validation
      }
    },
    // VULNERABILITY 8: Sensitive fields without encryption
    creditCardInfo: {
      type: DataTypes.TEXT, // VULNERABLE: Storing sensitive data as plain text
      allowNull: true
    },
    trackingNumber: {
      type: DataTypes.STRING(100),
      allowNull: true
    },
    notes: {
      type: DataTypes.TEXT,
      allowNull: true,
      // VULNERABILITY 9: No XSS protection
      validate: {
        len: [0, 1000] // VULNERABLE: No content sanitization
      }
    }
  }, {
    tableName: 'orders',
    timestamps: true,
    // VULNERABILITY 10: Weak hooks
    hooks: {
      beforeCreate: (order) => {
        // VULNERABLE: No input sanitization
        if (order.shippingAddress) {
          order.shippingAddress = order.shippingAddress.trim(); // VULNERABLE: Only trimming
        }
      },
      beforeUpdate: (order) => {
        // VULNERABLE: No input sanitization
        if (order.changed('shippingAddress')) {
          order.shippingAddress = order.shippingAddress.trim(); // VULNERABLE: Only trimming
        }
      }
    }
  });

  // VULNERABILITY 11: Class methods with SQL injection risks
  Order.findByStatus = function(status) {
    // VULNERABLE: Direct string concatenation in query
    return this.findAll({
      where: sequelize.literal(`status = '${status}'`) // VULNERABLE: SQL injection
    });
  };

  // VULNERABILITY 12: Weak search method
  Order.search = function(query) {
    // VULNERABLE: Direct string concatenation in query
    return this.findAll({
      where: sequelize.literal(`shippingAddress LIKE '%${query}%' OR notes LIKE '%${query}%'`) // VULNERABLE: SQL injection
    });
  };

  // VULNERABILITY 13: Price range search with injection
  Order.findByPriceRange = function(minPrice, maxPrice) {
    // VULNERABLE: Direct string concatenation in query
    return this.findAll({
      where: sequelize.literal(`totalPrice >= ${minPrice} AND totalPrice <= ${maxPrice}`) // VULNERABLE: SQL injection
    });
  };

  // VULNERABILITY 14: Instance method with security issues
  Order.prototype.updateStatus = function(newStatus) {
    // VULNERABLE: No validation of new status
    this.status = newStatus;
    return this.save();
  };

  // VULNERABILITY 15: Weak calculation method
  Order.prototype.calculateTotal = function() {
    // VULNERABLE: No validation of quantity and price
    this.totalPrice = this.quantity * this.product.price;
    return this.save();
  };

  return Order;
};
