# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Trajan, please report it responsibly.

### How to Report

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities via one of these methods:

1. **Email**: Send details to security@praetorian.com
2. **Private Disclosure**: Use GitHub's [private vulnerability reporting](https://github.com/praetorian-inc/trajan/security/advisories/new)

### What to Include

When reporting a vulnerability, please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Based on severity (Critical: 7 days, High: 30 days, Medium: 90 days)

### Scope

This security policy applies to:

- The Trajan CLI tool
- Detection plugins
- Attack simulation modules
- Documentation and examples

### Recognition

We appreciate responsible disclosure and will acknowledge security researchers who help improve Trajan's security (with your permission) in our release notes.

## Security Best Practices

When using Trajan:

1. **Token Security**: Use fine-grained GitHub tokens with minimal required permissions
2. **CI/CD Integration**: Run Trajan in isolated environments
3. **Attack Mode**: Only use the `attack` subcommands against repositories you own or have explicit authorization to test. `attack run` is dry-run until you pass `--execute`
4. **Output Handling**: Treat scan results as sensitive (may contain workflow paths and configurations)
