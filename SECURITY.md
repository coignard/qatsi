# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Qatsi, please email: `contact@renecoignard.com`

**Do not** open a public issue.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response time

- Initial response: 48 hours
- Fix timeline: 7-14 days (depending on severity)

## Security Considerations

### Cryptographic Assumptions

Qatsi's security relies on:

1. **Argon2id**: Memory-hard KDF resists GPU/ASIC attacks
2. **ChaCha20**: Cryptographically secure PRNG
3. **Rejection sampling**: Eliminates modulo bias

### Known Limitations

- **Side-channel attacks**: No specific mitigations (constant-time operations not guaranteed)
- **Terminal history**: Master secret may appear in shell history if piped

## Audit Status

No formal security audit has been conducted. Community review welcome.
