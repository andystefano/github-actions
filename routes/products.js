const express = require('express');
const { body, validationResult } = require('express-validator');
const db = require('../models');
const router = express.Router();

// VULNERABILITY 1: No authentication middleware for public endpoints

// GET /api/products - Get all products (VULNERABLE: No pagination or rate limiting)
router.get('/', async (req, res) => {
  try {
    // VULNERABILITY 2: No input validation or sanitization
    const { category, minPrice, maxPrice, inStock } = req.query;
    
    let whereClause = {};
    
    if (category) {
      whereClause.category = category; // VULNERABLE: Direct assignment without validation
    }
    
    if (minPrice || maxPrice) {
      whereClause.price = {};
      if (minPrice) {
        whereClause.price.$gte = parseFloat(minPrice); // VULNERABLE: Weak number parsing
      }
      if (maxPrice) {
        whereClause.price.$lte = parseFloat(maxPrice); // VULNERABLE: Weak number parsing
      }
    }
    
    if (inStock !== undefined) {
      whereClause.stock = inStock === 'true' ? { $gt: 0 } : { $eq: 0 }; // VULNERABLE: Weak boolean conversion
    }

    const products = await db.Product.findAll({
      where: whereClause,
      attributes: ['id', 'name', 'description', 'price', 'category', 'stock', 'imageUrl', 'supplierInfo', 'costPrice'] // VULNERABLE: Exposing sensitive fields
    });

    res.json(products);
  } catch (error) {
    // VULNERABILITY 3: Error information leakage
    res.status(500).json({ 
      error: error.message,
      stack: error.stack, // VULNERABLE: Exposing stack trace
      sql: error.sql // VULNERABLE: Exposing SQL queries
    });
  }
});

// GET /api/products/:id - Get product by ID
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // VULNERABILITY 4: No input validation
    if (!id || isNaN(id)) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }

    const product = await db.Product.findByPk(id, {
      attributes: ['id', 'name', 'description', 'price', 'category', 'stock', 'imageUrl', 'supplierInfo', 'costPrice'] // VULNERABLE: Exposing sensitive fields
    });

    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/products - Create new product (VULNERABLE: No authentication required)
router.post('/', [
  // VULNERABILITY 5: Weak validation rules
  body('name').isLength({ min: 1, max: 100 }).trim(), // VULNERABLE: Basic validation only
  body('description').optional().isLength({ max: 1000 }), // VULNERABLE: No content sanitization
  body('price').isFloat({ min: 0 }), // VULNERABLE: Allows zero price
  body('category').isLength({ min: 1, max: 50 }), // VULNERABLE: Basic validation only
  body('stock').isInt({ min: 0 }), // VULNERABLE: Allows zero stock
  body('imageUrl').optional().isURL(), // VULNERABLE: Basic URL validation
  body('supplierInfo').optional().isLength({ max: 1000 }), // VULNERABLE: No content sanitization
  body('costPrice').optional().isFloat({ min: 0 }) // VULNERABLE: Exposing cost information
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, description, price, category, stock, imageUrl, supplierInfo, costPrice } = req.body;

    // VULNERABILITY 6: No duplicate check
    const existingProduct = await db.Product.findOne({ where: { name } });
    if (existingProduct) {
      return res.status(400).json({ error: 'Product name already exists' });
    }

    const product = await db.Product.create({
      name,
      description, // VULNERABLE: Storing unsanitized content
      price,
      category,
      stock,
      imageUrl,
      supplierInfo, // VULNERABLE: Storing sensitive data without encryption
      costPrice // VULNERABLE: Exposing cost information
    });

    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/products/:id - Update product (VULNERABLE: No authentication required)
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, category, stock, imageUrl, supplierInfo, costPrice } = req.body;

    // VULNERABILITY 7: No input validation
    if (!id || isNaN(id)) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }

    const product = await db.Product.findByPk(id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // VULNERABILITY 8: No input sanitization
    const updatedProduct = await product.update({
      name: name || product.name,
      description: description || product.description,
      price: price || product.price,
      category: category || product.category,
      stock: stock || product.stock,
      imageUrl: imageUrl || product.imageUrl,
      supplierInfo: supplierInfo || product.supplierInfo,
      costPrice: costPrice || product.costPrice
    });

    res.json(updatedProduct);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/products/:id - Delete product (VULNERABLE: No authentication required)
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // VULNERABILITY 9: No confirmation or soft delete
    const deleted = await db.Product.destroy({
      where: { id }
    });

    if (deleted) {
      res.json({ message: 'Product deleted successfully' });
    } else {
      res.status(404).json({ error: 'Product not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 10: Search endpoint with SQL injection risk
router.get('/search/:query', async (req, res) => {
  try {
    const { query } = req.params;
    
    // VULNERABLE: Using custom search method with injection risk
    const products = await db.Product.search(query);
    
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 11: Category search with SQL injection risk
router.get('/category/:category', async (req, res) => {
  try {
    const { category } = req.params;
    
    // VULNERABLE: Using custom category method with injection risk
    const products = await db.Product.findByCategory(category);
    
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 12: Price range search with SQL injection risk
router.get('/price-range/:min/:max', async (req, res) => {
  try {
    const { min, max } = req.params;
    
    // VULNERABLE: Using custom price range method with injection risk
    const products = await db.Product.findByPriceRange(min, max);
    
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 13: Stock update endpoint (VULNERABLE: No authentication required)
router.patch('/:id/stock', async (req, res) => {
  try {
    const { id } = req.params;
    const { quantity } = req.body;

    // VULNERABILITY: No input validation
    if (!id || isNaN(id)) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }

    if (!quantity || isNaN(quantity)) {
      return res.status(400).json({ error: 'Invalid quantity' });
    }

    const product = await db.Product.findByPk(id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // VULNERABLE: Using custom update method without validation
    await product.updateStock(parseInt(quantity));

    res.json({ message: 'Stock updated successfully', newStock: product.stock });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABILITY 14: Bulk operations endpoint (VULNERABLE: No authentication required)
router.post('/bulk', async (req, res) => {
  try {
    const { products } = req.body;

    // VULNERABILITY: No input validation or sanitization
    if (!Array.isArray(products)) {
      return res.status(400).json({ error: 'Products must be an array' });
    }

    const createdProducts = [];
    for (const productData of products) {
      // VULNERABLE: No validation of individual product data
      const product = await db.Product.create(productData);
      createdProducts.push(product);
    }

    res.status(201).json(createdProducts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
