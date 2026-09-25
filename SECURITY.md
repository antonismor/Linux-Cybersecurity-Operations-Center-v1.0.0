# Security Policy

Linux Cybersecurity Operations Center is a privileged defensive-security platform. Protect the controller, PostgreSQL database, TLS private keys, bootstrap token, and endpoint credentials as security-sensitive assets.

## Reporting a vulnerability

Please report security issues privately to:

**antonios.mortos@outlook.com**

Include the affected version, reproduction steps, expected impact, operating system, and sanitized logs. Never include production passwords, private keys, endpoint tokens, or customer data.

## Production recommendations

- Restrict access to the controller network interface.
- Replace temporary Basic Auth with centralized identity/RBAC before large deployments.
- Protect /etc/cybersecurity-ops/credentials.txt.
- Rotate initial bootstrap credentials after enrollment setup.
- Use one-time enrollment tokens per endpoint.
- Back up PostgreSQL securely.
- Use organizational/public PKI where appropriate.
- Test agent releases before fleet-wide deployment.
- Keep response actions narrow, explicit, authenticated, and audited.

**Powered and Development by antonios.mortos@outlook.com**
