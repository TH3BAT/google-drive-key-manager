# SECURITY.md

## Overview
This document outlines the security practices and design considerations for the GitTea repository, including guidance on handling cryptographic operations like those in the Google Drive Key Manager script.

## Security Practices

### 1. High-Entropy Passphrases
- Use a passphrase of at least 12 words generated from a trusted high-entropy source such as VaultWarden.
- Combined with salts, nonces, and encryption keys, this ensures robust protection for sensitive data.

### 2. Cryptographic Algorithms
- **AES-256 Encryption**: Used for protecting data with industry-standard strength.
- **Salts and Nonces**: Prevent replay and rainbow table attacks.

### 3. Hashing with Bcrypt
- Bcrypt is employed for securely hashing sensitive data, adding computational cost to brute-force attacks.

### 4. Quantum Readiness
- The project is designed to be resilient to classical and near-term quantum computing threats.
- Monitoring advancements in post-quantum cryptography for future implementation.

## Recommendations for Users
- Update your local environment and dependencies regularly to maintain compatibility with the latest cryptographic standards.
- Avoid sharing passphrases or sensitive keys in plaintext.
- Follow cryptographic best practices when contributing to this repository.

## Future Plans
- Transition to post-quantum cryptographic algorithms as they become standardized.
- Regular security audits to ensure compliance and protection against emerging threats.

## Reporting Vulnerabilities
If you discover a security issue, please report it responsibly by emailing **[secure-contact@example.com](mailto:secure-contact@example.com)**.


