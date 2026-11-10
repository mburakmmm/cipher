# Security Policy — Cipher

## Supported Versions

Cipher adheres to Semantic Versioning (`SemVer`). Security updates and vulnerability fixes are released for the active development and supported minor branches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability or critical cryptographic flaw in Cipher, please do **not** open a public issue. Report it responsibly:

- **Email**: Send detailed vulnerability reports to [burakmemis@gmail.com](mailto:burakmemis@gmail.com).
- **GitHub Private Vulnerability Reporting**: Open a private advisory under the **Security** tab of the Cipher repository: https://github.com/mburakmmm/cipher/security/advisories

Please include:
1. Detailed description of the vulnerability and attack vector.
2. Minimal reproducible example or PoC in NOX.
3. Affected versions and target platforms (macOS, Linux, Windows).
4. Potential impact (e.g. signature forgery, timing side-channel, algorithm confusion, key disclosure).

Maintainers will acknowledge receipt within **48 hours** and provide regular progress updates toward a patched release.

## Cryptographic Security Invariants

Cipher enforces non-negotiable security invariants derived from RFC 7515, RFC 7519, and RFC 8725 (JWT Best Current Practices):

1. **Fail-Closed by Design**:
   Any malformed token, invalid encoding, unknown algorithm, unverified claim, or signature mismatch fails immediately by raising a strongly-typed `CipherError`.

2. **Verifier-Controlled Algorithms**:
   The `alg` header in untrusted tokens is never allowed to dictate the trust path or downgrade cryptographic requirements. Verifiers enforce an explicit allowlist and key profile.

3. **`alg=none` Unconditional Rejection**:
   Tokens specifying `alg=none` or missing the algorithm identifier are unconditionally rejected.

4. **Algorithm Confusion Immunity**:
   HMAC symmetric secrets and RSA/EC asymmetric public keys are strictly typed and cannot be substituted or cross-used.

5. **Constant-Time Verification**:
   Cryptographic MAC comparisons use `nox.crypto.constant_time_eq` to mitigate timing side-channel attacks.

6. **Exact Signing Input Byte Verification**:
   Signatures are verified directly against the original ASCII bytes `base64url(protected_header) + "." + base64url(payload)`. Re-serialization before verification is forbidden.

7. **Zero Leakage**:
   Secrets, private keys, bearer tokens, and unverified credentials are never logged, traced, or included in error messages.
