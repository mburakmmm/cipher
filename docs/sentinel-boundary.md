# Sentinel Boundary & Architecture Contract

> **Normative Boundary Specification**  
> *Target:* Sentinel (Authentication & Authorization Policy) vs. Cipher (Cryptographic Verification Mechanism)

---

## 1. Fundamental Division of Responsibility

| Capability | Cipher (Mechanism Layer) | Sentinel (Policy Layer) |
|---|:---:|:---:|
| Compact JWS / JWT Parsing | :white_check_mark: | :x: |
| Signature Verification over ASCII bytes | :white_check_mark: | :x: |
| Constant-time MAC Validation | :white_check_mark: | :x: |
| Strict Base64URL & JSON duplicate check | :white_check_mark: | :x: |
| Key Lifecycle & Keyring state machine | :white_check_mark: | :x: |
| JWK Parsing & JWK Thumbprint (RFC 7638) | :white_check_mark: | :x: |
| Purpose-bound Signed Tokens (opaque) | :white_check_mark: | :x: |
| User Authentication & Login Flow | :x: | :white_check_mark: |
| Password Hashing & Credential Validation | :x: | :white_check_mark: |
| MFA & WebAuthn / Passkeys | :x: | :white_check_mark: |
| OAuth2 / OIDC Protocol Flows & PKCE | :x: | :white_check_mark: |
| Session Management & Replay Nonces | :x: | :white_check_mark: |
| RBAC / ABAC & Permission Evaluation | :x: | :white_check_mark: |
| Access Control (`allow` / `deny`) | :x: | :white_check_mark: |
| Endpoint & Middleware Protection | :x: | :white_check_mark: |

---

## 2. Invariant: Valid Signature != Authorized Access

A cryptographic signature verifies only two facts:
1. The message was created by a party possessing the signing key.
2. The message has not been altered since it was signed.

**It does not imply:**
- That the caller is genuine or authenticated.
- That the caller has permission to access the requested resource.
- That the token has not been revoked or replayed (unless verified by an application-level nonce store).
- That the claims inside the token are true or acceptable for the current tenant.

### Flow of Execution

```
[ Incoming HTTP Request ]
          │
          ▼
    [ Sentinel ] ── Selects application profile, tenant context, trusted keys & audience
          │
          ▼
     [ Cipher ] ── JwsVerifier.verify(token, profile)
          │
          ├── (Invalid Signature / Expired / Corrupt) ──> Raises CipherError ──> Sentinel returns 401
          │
          └── (Valid) ──> Returns VerifiedJwt
                                │
                                ▼
                          [ Sentinel ] ── Evaluates user roles, scopes, tenant match, permissions
                                │
                                ├── (Insufficient Roles) ──> Denies request (403 Forbidden)
                                └── (Authorized) ──> Dispatches to handler
```

---

## 3. Explicit Prohibition

Cipher code shall **never**:
1. Return boolean flags indicating authorization (`is_admin`, `is_allowed`, `can_read`).
2. Make decisions regarding user sessions or database persistence.
3. Automatically authenticate a principal simply because a token signature is valid.
4. Interpret `scope` or `roles` claim strings as business permissions.
