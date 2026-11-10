# Cipher

<div align="center">

[![CI](https://github.com/mburakmmm/cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/mburakmmm/cipher/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mburakmmm/cipher?color=blue)](https://github.com/mburakmmm/cipher/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NOX](https://img.shields.io/badge/NOX-2.1.0-orange)](https://noxlang.com)
[![Security Policy](https://img.shields.io/badge/Security-RFC%208725%20BCP-red)](SECURITY.md)

**Cryptographic Token & Key Management Mechanism Layer for the NOX Ecosystem**

*Standards-compliant compact JWS, JWT claims validation, purpose-bound signed tokens, and key rotation.*

[Architecture](docs/architecture.md) • [Threat Model](docs/threat-model.md) • [Sentinel Boundary](docs/sentinel-boundary.md) • [Roadmap (todo.md)](todo.md)

</div>

---

## Mission and Architecture

**Cipher** provides a pure, framework-independent **cryptographic mechanism layer** for token issuance, verification, and key management across NOX applications, services, and libraries (Nyx, Aether, Aura, and Sentinel).

```
Consumers: Nyx / Aether / Aura / Sentinel / Standalone NOX Applications
                           │
       Public API (Typed Results, Explicit Config, Fail-Closed)
                           │
       ┌───────────────────┴───────────────────────┐
       │ Compact JWS (RFC 7515)                    │
       │ JWT Claims Profile Validation (RFC 7519)  │
       │ Purpose-Bound Signed Tokens               │
       └───────────────────┬───────────────────────┘
                           │
       ┌───────────────────┴───────────────────────┐
       │ KeyRing & Rotation State Machine          │
       │ Local Key Material / Configured JWKS      │
       └───────────────────┬───────────────────────┘
                           │
       ┌───────────────────┴───────────────────────┐
       │ CryptoProvider Abstraction                │
       │ Verified OS Entropy & Audited Primitives  │
       └───────────────────────────────────────────┘
```

---

## Non-Negotiable Boundary: Cipher vs. Sentinel

Cipher enforces a strict separation of concerns between cryptographic verification and authorization policy:

```
Incoming Token
     │
     ▼
[ Sentinel ] ── Selects tenant, issuer, audience, accepted type & trust context
     │
     ▼
[ Cipher ] ── Verifies signature over exact ASCII bytes + validates claims profile
     │
     ▼
[ Verified Evidence ] ── Returns VerifiedJwt (Cryptographic evidence only)
     │
     ▼
[ Sentinel ] ── Evaluates permissions, roles, sessions & authorizes resource access
```

> **Separation Invariant:** A token with a valid cryptographic signature is **not** automatically authenticated or authorized. Cipher proves cryptographic facts; **Sentinel** makes identity, trust, and access decisions.

---

## Key Features

- **Strict Compact JWS (RFC 7515):** Exactly 3 dot-separated segments, strict Base64URL parsing, strict duplicate JSON key rejection, bounded token sizes.
- **Fail-Closed Security:** Unconditional rejection of `alg=none`, unknown algorithms, ambiguous `kid` matches, and expired or future-issued tokens.
- **Verifier-Controlled Algorithms:** Verifiers dictate the permitted algorithm allowlist; untrusted headers cannot trigger algorithm downgrades or confuse HMAC secrets with public keys.
- **Claims Profile Validation (RFC 7519 & RFC 8725):** Strict temporal (`exp`, `nbf`, `iat`), issuer (`iss`), and audience (`aud`) checks with configurable clock leeway.
- **Purpose-Bound Signed Tokens:** Domain-separated, lightweight opaque tokens for application workflows (email verification, password resets) preventing token substitution.
- **Key Lifecycle & Safe Rotation:** Five-stage state machine (`PREPARED` → `ACTIVE_SIGNING` → `VERIFY_ONLY` → `RETIRED` → `REVOKED`) with zero downtime and atomic transitions.
- **Opt-in Remote JWKS:** Secure HTTPS discovery with SSRF defenses, TTL-bounded caching, negative caching, and fetch-storm mitigations.
- **Zero Information Leakage:** Tokens, secrets, private keys, and sensitive payload data are strictly protected against logging and tracing.

---

## Standards and RFC Profile

| Specification | Scope & Profile in Cipher |
|---|---|
| **RFC 7515 (JWS)** | Compact JWS signing and verification, strict ASCII input validation |
| **RFC 7517 (JWK)** | JSON Web Key parsing, safe public key export (zero private leakage) |
| **RFC 7518 (JWA)** | HS256, RS256, PS256, ES256 algorithm support matrix |
| **RFC 7519 (JWT)** | Registered claims (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`) verification |
| **RFC 7638 (Thumbprint)** | Deterministic SHA-256 JWK thumbprint generation |
| **RFC 8725 (JWT BCP)** | Best Current Practices: duplicate key rejection, fail-closed profiles |

---

## Security Invariants

1. **Fail-Closed:** Any malformed structure, missing header, untrusted key, or invalid signature immediately raises a typed `CipherError`.
2. **Exact Byte Verification:** Verification is computed strictly over `base64url(protected_header) + "." + base64url(payload)` ASCII bytes without re-serialization.
3. **Constant-Time Operations:** Cryptographic MAC checks utilize `nox.crypto.constant_time_eq` to eliminate timing attacks.
4. **No Algorithm Guessing:** Neither `alg` nor `kid` can force key downloading, path traversal, or dynamic trust paths.
5. **No Secret In Test Artefacts:** Production credentials and raw secrets are never committed; test fixtures use synthetic, explicitly marked keys.

---

## Quick Example (HS256 Compact JWS)

```python
import nox.crypto
from cipher import JwsSigner, JwsVerifier, VerificationProfile

secret: str = "your-256-bit-minimum-secret-key-material-here"
payload: str = '{"sub":"user_42","scope":"read"}'

# 1. Sign
token: str = JwsSigner.sign_hs256(payload, secret, kid="key-2026")

# 2. Verify with explicit policy
profile: VerificationProfile = VerificationProfile(allowed_algs=["HS256"], expected_kid="key-2026")
verified = JwsVerifier.verify(token, secret, profile)

print("Verified Payload: " + verified.payload)
```

---

## Development & Phased Roadmap

Track implementation progress and verification evidence in [todo.md](todo.md):

- [x] **Phase 0:** Platform Validation & Toolchain Gates (`v0.0.x`)
- [ ] **Phase 1:** Strict Core, Typed Errors & HS256 Compact JWS (`v0.1.x`)
- [ ] **Phase 2:** JWT Claims Validation & Purpose-Bound Signed Tokens (`v0.2.x`)
- [ ] **Phase 3:** Asymmetric JOSE (RS256) & JWK/JWKS (`v0.3.x`)
- [ ] **Phase 4:** KeyRing & Safe Key Rotation Lifecycle (`v0.4.x`)
- [ ] **Phase 5:** Remote JWKS & Outage Resilience (`v0.5.x`)
- [ ] **Phase 6:** Sentinel Boundary Adapter & `v1.0.0` Release Gate

---

## Contributing & Security

- **Security Vulnerabilities:** Follow instructions in [SECURITY.md](SECURITY.md).
- **Versioning Policy:** SemVer details are documented in [VERSIONING.md](VERSIONING.md).
- **Contributing Guidelines:** Ensure all changes maintain static typing, zero ownership keywords, and full test matrix coverage.

---

## License

Licensed under the [MIT License](LICENSE). Copyright © 2026 Cipher contributors.
