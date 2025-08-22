#!/usr/bin/env node

/**
 * Startup Script for Vulnerable Backend
 * 
 * This script initializes the database and starts the server.
 * Use only for testing purposes.
 */

const db = require('./models');
const app = require('./server');

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    console.log('🚀 Starting Vulnerable Backend Server...');
    console.log('⚠️  WARNING: This application contains intentional security vulnerabilities');
    console.log('📚 Use only for educational and testing purposes');
    
    // Initialize database
    console.log('🗄️  Initializing database...');
    await db.sequelize.sync({ force: true });
    console.log('✅ Database initialized successfully');
    
    // Create some sample data for testing
    console.log('📝 Creating sample data...');
    await createSampleData();
    console.log('✅ Sample data created');
    
    // Start server
    app.listen(PORT, () => {
      console.log(`🌐 Server running on http://localhost:${PORT}`);
      console.log(`📖 API Documentation: http://localhost:${PORT}/api`);
      console.log(`🧪 Test vulnerabilities with: node test-vulnerabilities.js`);
      console.log('\n⚠️  REMEMBER: This is a vulnerable application for testing only!');
    });
    
  } catch (error) {
    console.error('💥 Failed to start server:', error);
    process.exit(1);
  }
}

async function createSampleData() {
  try {
    // Create admin user
    const adminUser = await db.User.create({
      username: 'admin',
      email: 'admin@vulnerable.com',
      password: 'admin123', // Weak password
      role: 'admin',
      personalInfo: 'This is admin personal information',
      apiKey: 'admin-api-key-123'
    });
    
    // Create regular user
    const regularUser = await db.User.create({
      username: 'user',
      email: 'user@vulnerable.com',
      password: 'user123', // Weak password
      role: 'user',
      personalInfo: 'This is user personal information',
      apiKey: 'user-api-key-456'
    });
    
    // Create sample products
    const product1 = await db.Product.create({
      name: 'Vulnerable Product 1',
      description: '<script>alert("XSS")</script>', // XSS payload
      price: 19.99,
      category: 'electronics',
      stock: 100,
      supplierInfo: 'Supplier: Test Supplier Inc.\nContact: supplier@test.com\nPhone: 555-0123',
      costPrice: 10.00
    });
    
    const product2 = await db.Product.create({
      name: 'Vulnerable Product 2',
      description: 'Another product with potential vulnerabilities',
      price: 29.99,
      category: 'books',
      stock: 50,
      supplierInfo: 'Supplier: Book Supplier Ltd.\nContact: books@test.com\nPhone: 555-0456',
      costPrice: 15.00
    });
    
    // Create sample orders
    await db.Order.create({
      userId: regularUser.id,
      productId: product1.id,
      quantity: 2,
      totalPrice: 39.98,
      status: 'pending',
      shippingAddress: '123 Test Street, Test City, TC 12345',
      paymentMethod: 'credit_card',
      creditCardInfo: 'Card: 4111-1111-1111-1111\nExp: 12/25\nCVV: 123', // Sensitive data
      notes: 'Test order for vulnerability testing'
    });
    
    await db.Order.create({
      userId: regularUser.id,
      productId: product2.id,
      quantity: 1,
      totalPrice: 29.99,
      status: 'confirmed',
      shippingAddress: '456 Test Avenue, Test Town, TT 67890',
      paymentMethod: 'paypal',
      notes: 'Another test order'
    });
    
    console.log('👥 Created users: admin, user');
    console.log('📦 Created products: 2');
    console.log('📋 Created orders: 2');
    
  } catch (error) {
    console.error('❌ Error creating sample data:', error);
    throw error;
  }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down server...');
  try {
    await db.sequelize.close();
    console.log('✅ Database connection closed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Received SIGTERM, shutting down...');
  try {
    await db.sequelize.close();
    console.log('✅ Database connection closed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
});

// Start the server
if (require.main === module) {
  startServer();
}

module.exports = { startServer };
