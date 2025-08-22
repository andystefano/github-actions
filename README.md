# Vulnerable Backend - Node.js Project

⚠️ **WARNING: This project contains INTENTIONAL security vulnerabilities for testing purposes only. DO NOT use in production environments.**

## Overview

This is a Node.js backend application built with Express.js and Sequelize ORM that contains multiple intentional security vulnerabilities. The project is designed specifically for testing CodeQL security analysis tools and should only be used in controlled testing environments.

## Features

- **User Management**: User registration, authentication, and role-based access control
- **Product Management**: CRUD operations for products with inventory tracking
- **Order Management**: Order processing and tracking system
- **Admin Panel**: Administrative functions for system management
- **Database Integration**: SQLite database with Sequelize ORM
- **API Endpoints**: RESTful API with Express.js

## Security Vulnerabilities (Intentional)

### 1. Authentication & Authorization
- Hardcoded JWT secrets
- Weak password requirements (minimum 4 characters)
- Weak password hashing (only 5 salt rounds)
- No proper session management
- Weak role-based access control

### 2. SQL Injection
- Direct string concatenation in database queries
- Use of `sequelize.literal()` with user input
- Custom search methods vulnerable to injection
- No input sanitization or parameterized queries

### 3. Command Injection
- Direct execution of user input commands
- No command sanitization or validation
- System command execution endpoints

### 4. Path Traversal
- File access without proper path validation
- Directory traversal vulnerabilities
- Unrestricted file serving

### 5. Weak Encryption
- Use of deprecated crypto methods
- Weak encryption algorithms (AES-128-ECB)
- Hardcoded encryption keys
- MD5 hashing (cryptographically broken)

### 6. Information Disclosure
- Error messages exposing stack traces
- SQL query logging in production
- Exposing sensitive system information
- Environment variable leakage

### 7. Input Validation
- Weak input sanitization
- No XSS protection
- Insufficient validation rules
- No rate limiting on critical endpoints

### 8. Database Security
- Hardcoded database credentials
- Weak connection pool configuration
- Disabled SSL verification
- Force database sync in production

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd vulnerable-backend

# Install dependencies
npm install

# Start the application
npm start

# For development with auto-restart
npm run dev
```

## Environment Variables

Create a `.env` file in the root directory:

```env
NODE_ENV=development
PORT=3000
DB_USERNAME=your_username
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=3306
DB_NAME=your_database
```

## API Endpoints

### Public Endpoints
- `GET /api/products` - List all products
- `GET /api/products/:id` - Get product by ID
- `POST /api/products` - Create new product (no auth required)
- `PUT /api/products/:id` - Update product (no auth required)
- `DELETE /api/products/:id` - Delete product (no auth required)

### Protected Endpoints
- `POST /api/users/login` - User authentication
- `GET /api/users` - List users (requires auth)
- `POST /api/users` - Create user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user (admin only)

### Admin Endpoints
- `GET /api/admin/dashboard` - Admin dashboard
- `GET /api/admin/users` - List all users with sensitive data
- `POST /api/admin/execute-command` - Execute system commands
- `GET /api/admin/file/:filename` - Access files (path traversal vulnerable)

## Database Schema

The application uses three main models:

1. **User**: Authentication and user management
2. **Product**: Product catalog and inventory
3. **Order**: Order processing and tracking

## CodeQL Analysis

This project is specifically designed to trigger CodeQL security alerts:

- **SQL Injection**: Multiple endpoints use unsafe database queries
- **Command Injection**: Direct command execution without sanitization
- **Path Traversal**: File access without proper validation
- **Weak Cryptography**: Deprecated and insecure encryption methods
- **Information Disclosure**: Error messages and logging vulnerabilities
- **Authentication Bypass**: Weak JWT and session handling

### Important Note About CodeQL

**CodeQL analiza código; no revisa archivos por nombre directamente.**

Para que archivos como `.env` aparezcan en Code Scanning, puedes crear una query personalizada que detecte archivos `.env` en la estructura de proyecto, usando la clase `File` de CodeQL.

#### Ejemplo de Query Personalizada para Detectar Archivos .env

```ql
/**
 * @name Environment Files Detected
 * @description Detects .env files in the project structure
 * @kind problem
 * @id js/environment-files
 * @problem.severity warning
 * @precision medium
 */

import javascript
import File

from File f
where f.getBaseName() = ".env"
select f, "Environment file detected: " + f.getRelativePath()
```

#### Configuración en GitHub Actions

Para incluir queries personalizadas en tu análisis de CodeQL, puedes modificar el workflow de GitHub Actions:

```yaml
- name: Perform CodeQL Analysis
  uses: github/codeql-action/analyze@v2
  with:
    queries: security-extended,security-and-quality,./custom-queries
    config-file: ./.github/codeql/codeql-config.yml
```

## Testing Vulnerabilities

### SQL Injection Test
```bash
# Test user search endpoint
curl "http://localhost:3000/api/users/search/'%20OR%20'1'='1"
```

### Command Injection Test
```bash
# Test command execution endpoint
curl -X POST http://localhost:3000/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "ls -la"}'
```

### Path Traversal Test
```bash
# Test file access endpoint
curl "http://localhost:3000/file/../../../etc/passwd"
```

## Security Recommendations

If this were a production application, the following security measures should be implemented:

1. **Input Validation**: Implement proper input sanitization and validation
2. **Parameterized Queries**: Use Sequelize's built-in protection against SQL injection
3. **Authentication**: Implement proper JWT handling with secure secrets
4. **Authorization**: Implement proper role-based access control
5. **Encryption**: Use modern, secure encryption algorithms
6. **Error Handling**: Implement secure error handling without information disclosure
7. **Rate Limiting**: Implement proper rate limiting on all endpoints
8. **Security Headers**: Enable security headers with Helmet.js
9. **HTTPS**: Use HTTPS in production environments
10. **Regular Updates**: Keep dependencies updated and patched

## Disclaimer

This project is created solely for educational and testing purposes. The vulnerabilities are intentionally implemented to demonstrate common security mistakes and to test security analysis tools like CodeQL. 

**DO NOT:**
- Deploy this application in production
- Use this code as a reference for secure applications
- Expose this application to the internet
- Use the hardcoded credentials in any real system

**DO:**
- Use this project only in controlled testing environments
- Use it to learn about security vulnerabilities
- Test security analysis tools and scanners
- Practice security testing and penetration testing

## License

This project is provided as-is for educational purposes. Use at your own risk.
