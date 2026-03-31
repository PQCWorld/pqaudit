# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in pqaudit itself, please report it responsibly:

**Email:** security@pqcworld.com

Do not open a public GitHub issue for security vulnerabilities.

We will acknowledge your report within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

pqaudit is a static analysis tool that reads files and produces reports. It does not:
- Execute scanned code
- Make network connections (unless explicitly using network scanning features)
- Modify any files in the scanned target
- Store or transmit scan results externally

## Responsible disclosure of scan results

If you use pqaudit to scan third-party open-source projects, please follow responsible disclosure practices:
- Report quantum-vulnerable findings to the project maintainers privately first
- Allow reasonable time for migration planning before publishing results
- Focus on inventory and awareness, not exploit potential
