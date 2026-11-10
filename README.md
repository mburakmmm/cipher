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

| Specification | Scope & Profile in Cipher | Status |
|---|---|---|
| **RFC 7515 (JWS)** | Compact JWS signing and verification, strict ASCII input validation | **Production (HS256)** |
| **RFC 7517 (JWK)** | JSON Web Key parsing, safe public key export (zero private leakage) | **Production (RSA >= 2048-bit, oct)** |
| **RFC 7518 (JWA)** | HS256 HMAC-SHA256 active; RS256/asymmetric parsing supported | **HS256 Active** *(RS256 verify gated by ADR-0001 FFI)* |
| **RFC 7519 (JWT)** | Registered claims (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`) verification | **Production** |
| **RFC 7638 (Thumbprint)** | Deterministic SHA-256 JWK thumbprint generation | **Production** |
| **RFC 8725 (JWT BCP)** | Best Current Practices: duplicate key rejection, explicit typ enforcement | **Production** |

---

## Security Invariants

1. **Fail-Closed:** Any malformed structure, missing header, untrusted key, or invalid signature immediately raises a typed `CipherError`.
2. **Exact Byte Verification:** Verification is computed strictly over `base64url(protected_header) + "." + base64url(payload)` ASCII bytes without re-serialization.
3. **Constant-Time Operations:** Cryptographic MAC checks utilize `nox.crypto.constant_time_eq` to eliminate timing attacks.
4. **No Algorithm Guessing:** Neither `alg` nor `kid` can force key downloading, path traversal, or dynamic trust paths.
5. **No Secret In Test Artefacts:** Production credentials and raw secrets are never committed; test fixtures use synthetic, explicitly marked keys.
6. **KeyRing Atomic Rollback:** Key rotation validates new keys before mutating active signers, guaranteeing continuous signing availability.

---

## Quick Example (HS256 Compact JWS)

```python
from cipher import VerificationProfile, VerifiedJws, sign_hs256, verify_hs256

secret: str = "your-256-bit-minimum-secret-key-material-here"
payload: str = '{"sub":"user_42","scope":"read"}'

# 1. Sign
token: str = sign_hs256(payload, secret, kid="key-2026")

# 2. Verify with explicit policy
algs: list[str] = ["HS256"]
profile: VerificationProfile = VerificationProfile(algs, expected_kid="key-2026")
verified: VerifiedJws = verify_hs256(token, secret, profile)

print("Verified Payload: " + verified.payload)
```

---

## Phased Roadmap

Track implementation progress and verification evidence in [todo.md](todo.md):

- [x] **Phase 0:** Platform Validation & Toolchain Gates (`v0.0.x`)
- [x] **Phase 1:** Strict Core, Typed Errors & HS256 Compact JWS (`v0.1.x`)
- [x] **Phase 2:** JWT Claims Validation & Purpose-Bound Signed Tokens (`v0.2.x`)
- [x] **Phase 3:** JWK / RFC 7638 Thumbprints & Algorithm Confusion Defense (`v0.3.x`)
- [x] **Phase 4:** KeyRing & Safe Key Rotation Lifecycle (`v0.4.x`)
- [x] **Phase 5:** Remote JWKS, Outage Resilience & SSRF Defenses (`v0.5.x`)
- [x] **Phase 6:** Sentinel Boundary Adapter & `v1.0.0` Release Gate
- [x] **Phase 7:** Production Hardening, Atomic Rollback & `v1.0.1` Gate (SOL Analysis)

---

## Contributing & Security

- **Security Vulnerabilities:** Follow instructions in [SECURITY.md](SECURITY.md).
- **Versioning Policy:** SemVer details are documented in [VERSIONING.md](VERSIONING.md).
- **Contributing Guidelines:** Ensure all changes maintain static typing, zero ownership keywords, and full test matrix coverage.

---

## License

Licensed under the [MIT License](LICENSE). Copyright © 2026 Cipher contributors.
