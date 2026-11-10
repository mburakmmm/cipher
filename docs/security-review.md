# Security Review & Verification Evidence — Cipher

- **Date:** 2026-11-10
- **Version:** v1.0.0
- **Auditor:** Automated Agentic Review Protocol (AGENTS.md Normative Checklist)

## Verification Matrix

| Checklist Item | Requirement | Verification Evidence | Result |
|---|---|---|:---:|
| **Fail-Closed by Design** | Malformed input raises typed errors | Negative tests in `tests/jws_test.nox`, `tests/encoding_test.nox` | **PASS** |
| **`alg=none` Rejection** | Unsecured tokens unconditionally rejected | Tested in `tests/jws_test.nox` (RFC 8725 §3.1) | **PASS** |
| **Algorithm Confusion** | Public key cannot serve as HMAC secret | Tested in `tests/asymmetric_jws_test.nox` (RFC 8725 §3.2) | **PASS** |
| **Exact ASCII Verification** | Verify over original ASCII bytes | Implemented in `jws.nox`, `tests/jws_test.nox` | **PASS** |
| **Duplicate JSON Keys** | Repeated members rejected | Tested in `tests/json_strict_test.nox` (RFC 8725 §3.10) | **PASS** |
| **Strict Base64URL** | No whitespace, padding, or '+'/'/' | Tested in `tests/encoding_test.nox` (RFC 7515 §2) | **PASS** |
| **Zero Secret Leakage** | `to_public_json()` strips private exponents | Tested in `tests/jwk_test.nox` | **PASS** |
| **RFC 7515 Vectors** | Official HS256 Appendix A.1 vector | Tested in `tests/jws_test.nox` | **PASS** |
| **RFC 7638 Thumbprints** | Official Section 3.1 SHA-256 vector | Tested in `tests/jwk_test.nox` (`NzbLsXh8u...`) | **PASS** |
| **SSRF Protections** | Loopback, private IP, metadata blocked | Tested in `tests/jwks_test.nox` | **PASS** |
| **Fetch Storm Defense** | Negative caching for unknown `kid` | Tested in `tests/jwks_test.nox` | **PASS** |
| **Sentinel Boundary** | Valid signature != authorized access | Tested in `tests/sentinel_boundary_test.nox` | **PASS** |
