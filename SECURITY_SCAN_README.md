# Security Scanning Workflow

This repository includes a comprehensive security scanning workflow that checks for leaked secrets, environment files, and other security vulnerabilities.

## What the Workflow Checks

### 1. Gitleaks Security Scan
- **Secret Detection**: Scans for API keys, passwords, tokens, and other sensitive information
- **Pattern Matching**: Uses custom rules to detect various types of secrets
- **Comprehensive Coverage**: Checks all file types and commit history

### 2. Environment File Check
- **`.env` Files**: Detects any environment files that might contain secrets
- **Key Files**: Identifies private keys, certificates, and SSH keys
- **Hardcoded Secrets**: Scans code for potential hardcoded credentials

### 3. CodeQL Analysis
- **Static Analysis**: Performs security-focused static code analysis
- **Vulnerability Detection**: Identifies common security vulnerabilities in JavaScript code

## Workflow Triggers

The security scan runs automatically on:
- **Push** to `develop` branch
- **Pull Request** to `develop` branch
- **Manual trigger** via workflow dispatch

## Configuration Files

### `.github/gitleaks-config.toml`
Custom Gitleaks configuration with enhanced rules for:
- Environment variables
- API keys
- Database connection strings
- JWT tokens
- AWS credentials
- Private keys

### `.github/workflows/codeql-analysis.yml`
GitHub Actions workflow configuration

## What to Do If Secrets Are Found

1. **Immediate Action**: Remove the secret from the code
2. **Revoke**: If it's a real secret, revoke and regenerate it
3. **History Cleanup**: Use `git filter-branch` or BFG Repo-Cleaner to remove from git history
4. **Prevention**: Add the file pattern to `.gitignore`

## Best Practices

### Before Committing
- Never commit `.env` files
- Use environment variables or secure secret management
- Check for hardcoded credentials
- Validate with `git status` and `git diff --cached`

### Secret Management
- Use GitHub Secrets for CI/CD
- Use environment variables for local development
- Consider using tools like HashiCorp Vault or AWS Secrets Manager
- Rotate secrets regularly

## Local Testing

You can test the security scan locally:

```bash
# Install Gitleaks
go install github.com/gitleaks/gitleaks/v8@latest

# Run scan
gitleaks detect --source . --config .github/gitleaks-config.toml

# Check for .env files
find . -name "*.env*" -type f

# Check for key files
find . -name "*.key" -o -name "*.pem" -o -name "*.p12"
```

## Troubleshooting

### Workflow Failures
- Check the Actions tab for detailed error messages
- Review the Gitleaks report artifact
- Ensure the repository has proper permissions

### False Positives
- Add exclusion patterns to `gitleaks-config.toml`
- Use `# nosec` comments for intentional test data
- Update custom rules as needed

## Security Contacts

If you discover a security vulnerability, please:
1. **DO NOT** create a public issue
2. Contact the security team privately
3. Follow responsible disclosure practices

## Additional Resources

- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security/security-advisories)
- [OWASP Security Guidelines](https://owasp.org/www-project-top-ten/)
