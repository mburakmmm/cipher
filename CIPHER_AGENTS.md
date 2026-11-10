# AGENTS.md — Cipher: NOX Cryptographic Tokens & Contracts

> **Status:** Normative implementation specification for coding agents. **Language:** Turkish documentation, English API identifiers. **Target:** NOX ecosystem; standalone, framework-independent library. **Scope:** JWT/JWS verification, signed tokens, key lifecycle/rotation, cryptographic contracts. **Explicit exclusion:** authentication/authorization policy belongs to **Sentinel**.
>
> This file describes the **target design**, not claims that any functionality is already implemented. Agents must validate current NOX compiler, standard library, package system, FFI, and existing Cipher code before implementing.

## 0. Agent operating protocol (MANDATORY)

1. Read this document completely, the current `nox-lang` `AGENTS.md`, language reference, standard library documentation, compiler changelog, and repository code before changes. Respect upstream language invariants: static typing, no hidden dynamic typing, no user-visible ownership, explicit errors, no assumed reflection.
2. Inspect `noxc --version`, `noxc --help`, supported `noxc test`/package commands and actual working examples. **Do not invent NOX syntax, packages, crypto APIs, runtime facilities, or FFI contracts.** Example signatures below are **design pseudocode**, not guaranteed compilable NOX.
3. Inspect Nyx/Aether's existing JWT integration and any Sentinel repository/contracts; design adapters that avoid duplicating their authentication policy. Never modify their behavior silently.
4. At each phase, write a short compatibility report in `docs/compatibility.md` with exact NOX revision, platform, crypto backend, working APIs, gaps, and verified commands.
5. Implement a thin vertical slice with tests before broadening scope. Every API must have deterministic error semantics and negative tests. No TODO, stub, fallback, or mock implementation may be presented as secure production functionality.
6. Any security-relevant change needs threat-model update, tests, and review notes. If a required primitive cannot be implemented safely, stop that feature, mark unsupported, and explain rather than ship custom cryptography.
7. Before declaring a task complete, run all available format, build, unit, integration, vector, fuzz/property, and platform checks; document tests not run.

## 1. Product mission and boundaries

Cipher provides a **cryptographic mechanism layer** for token creation/verification and key management:

- Standards-compliant **compact JWS** signing and verification, **JWT** claims parsing and validation, and purpose-bound signed opaque tokens.
- Trusted key material import, public key discovery from JWKS, safe rotation, key selection, algorithm allowlists, and predictable error types.
- Reusable primitives/contracts that Nyx, Aether, Aura, and Sentinel can call without binding Cipher to a web framework.
- Cryptographic correctness and interoperability prioritized over API breadth.

**Sentinel owns policy**: login/session lifecycle, credential verification, MFA, OAuth2/OIDC flows and PKCE, tenant policy, RBAC/ABAC, resource authorization, token issuance *policy*, required roles/scopes, acceptable issuers/audiences per application, authentication challenges, cookies/CSRF, and endpoint protection. Cipher may accept an explicit caller-supplied claims-validation profile; it must **not decide who may access a resource**.

**Separation invariant:** A token with a valid signature is **not automatically authenticated or authorized**. Verification returns cryptographic/claims evidence; Sentinel makes trust and access decisions. JWT payload fields are untrusted until verification and applicable validation finish.

### Out of scope for initial stable release

- Full OAuth2/OIDC provider or relying-party implementation; session management; password hashing; login routes; RBAC/ABAC; web middleware; user database.
- JWE encryption/decryption, nested JWT, DPoP, SD-JWT, PASETO, COSE, XML signatures, arbitrary certificate PKI validation, HSM/KMS providers unless separately specified and tested.
- `alg=none` unsecured JWTs, accepting attacker-selected algorithms, unsafe key guessing, private keys from untrusted JWKS, or custom cryptographic primitives.

## 2. Non-negotiable security invariants

1. **Fail closed** on malformed encoding, unsupported algorithms/headers, key mismatch, signature failure, invalid claims, key ambiguity, revoked/retired keys, or untrusted remote sources.
2. **Algorithm selection is verifier-controlled.** `alg` in token header is parsed only to compare against an explicit allowlist and the selected key's fixed algorithm/type; it must never select a new trust path.
3. Reject `alg=none` unconditionally. Never confuse HMAC secret with RSA/EC/EdDSA public key (algorithm confusion).
4. Validate signature over the **exact ASCII bytes** `base64url(protected-header) + '.' + base64url(payload)`; do not reserialize before verification.
5. Enforce strict base64url decoding, JSON parsing, duplicate security-sensitive members rejection, limits on token/header/payload sizes and JSON nesting. Reject malformed Unicode/UTF-8 and ambiguous encodings.
6. Reject duplicate protected-header names and duplicate registered claims (prefer rejecting *all* duplicate JSON object keys). Do not silently use first/last occurrence.
7. Header `kid` is an **untrusted selector**, not a file path, SQL fragment, URL, authority, or reason to download a key. Reject duplicate/ambiguous `kid` matches.
8. Ignore/reject remote key directives `jku`, `x5u` and embedded `jwk` by default; reject `crit` unless every indicated extension is explicitly implemented, understood, and permitted. Never follow URLs from untrusted token headers.
9. Reject `b64=false`/RFC 7797 unless a separately reviewed extension is implemented; initial compact JWT profile requires encoded payload. Restrict `typ`/`cty` based on caller profile, not as proof of authorization.
10. **Never log** bearer tokens, private keys, HMAC secrets, complete JWTs, or sensitive claim values. Use redaction and bounded, low-cardinality metrics.
11. Secret comparisons use constant-time operations where relevant; do not claim end-to-end constant-time properties without evidence. No homegrown RSA/ECDSA/EdDSA/HMAC implementations.
12. Cryptographic randomness comes exclusively from OS CSPRNG/verified provider; never `random`, timestamp, counters alone, or deterministic seeds in production.
13. Every verification call is bound to an explicit **trust context**: permitted algorithms, trusted keys/key source, required claims, clock/leeway, and optionally expected issuer/audience/token type. No permissive global defaults.
14. Never automatically accept expired, future-not-valid, unknown issuer/audience, or untrusted-key tokens to improve availability.
15. Cross-tenant key namespaces and trust domains must not mix. Cache keys include trust-domain identity and source configuration.
16. Key rotation and refresh must not convert a known-bad signature into a valid token by falling back to an unrelated key or widening policy.
17. A successful `verify_jws` proves signature integrity with a trusted key, **not** identity, permission, replay prevention, or business intent.

## 3. Standards and interoperability

Normative references to consult and test against (versions/errata must be checked during implementation):

- RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7519 (JWT), RFC 7638 (JWK thumbprints), RFC 8725 (JWT BCP), RFC 9864 (updated JWT BCP if applicable; verify status before relying on it).
- RFC 8037 (OKP/EdDSA JWA), RFC 7797 (unencoded payload; **unsupported by default**), RFC 7516 (JWE; **out of scope**), RFC 4648 (base64url).
- RFC 8414 / OIDC Discovery are **Sentinel's** protocol concerns; Cipher may consume an explicitly configured JWKS URL but must not discover authority from token content.

Implement only vetted algorithm families actually supported by the chosen provider. Initial candidate profile:

| Family | Target | Constraints |
|---|---|---|
| HS256 | Initial | Secret length >= 256 bits; only trusted symmetric contexts; no public JWKS export |
| RS256 | Initial | RSA >= 2048 bits; verify padding/hash correctly; validate key type |
| PS256 | Optional stable | RSA-PSS correct salt/hash parameters; vetted provider |
| ES256 | Optional stable | P-256 only; JOSE fixed-width raw `R || S` format, not DER; canonical checks |
| EdDSA (Ed25519) | Optional stable | Only if provider and JOSE compatibility verified; fixed key constraints |

No algorithm becomes supported merely because it is listed here. Explicitly reject unknown algorithms and disabled algorithms. Avoid SHA-1 and weak key sizes. Algorithm profiles and defaults require a documented security review. Any support for legacy RS*/HS* beyond the table requires a new ADR.

## 4. Architecture and dependencies

```text
Consumers: Nyx / Aether / Aura / Sentinel / standalone NOX apps
                     |
         public API (typed results, explicit config)
                     |
  +------------------+---------------------+
  | compact JWS      | JWT claims profile  |
  | signed token     | canonical errors    |
  +------------------+---------------------+
  | keyring + key lifecycle + rotation     |
  | local key sources / configured JWKS    |
  +----------------------------------------+
  | crypto provider interface              |
  | audited OS/native library adapter      |
  +----------------------------------------+
```

- **NOX-first** public API and core state machines; small native FFI shim only if required for mature crypto primitives, TLS, or secure memory.
- Provider choice must be documented with version/license, support matrix, error mapping, ABI safety, thread safety, and packaging. Prefer a maintained audited library over bespoke primitives.
- No hard dependency on Sentinel, Nyx, Aether, Redis, PostgreSQL, network stack, or specific logger.
- Vault can supply secrets via a **caller-owned adapter**, not an automatic import. Obsidian/Pulse integrations are optional adapters, never mandatory for crypto correctness.
- Platform targets: macOS arm64/x86_64, Linux x86_64/arm64, Windows x86_64 as available in current NOX. Other targets gated by validated provider support. Freestanding/WASM cannot claim crypto support without secure entropy/provider capability.
- Avoid process-global mutable keyrings. Each `CipherContext` owns configuration, caches, resource lifecycle, and provider handles. If FFI needs handles, document ownership and safe release.

## 5. Repository layout (proposed; adapt to verified NOX tooling)

```text
cipher/
  AGENTS.md
  README.md
  LICENSE
  CHANGELOG.md
  SECURITY.md
  VERSIONING.md
  docs/
    architecture.md
    threat-model.md
    compatibility.md
    algorithms.md
    key-management.md
    sentinel-boundary.md
    security-review.md
    adr/
  src/
    cipher.nox                 # public exports
    errors.nox
    encoding.nox
    json_strict.nox
    jws.nox
    jwt.nox
    signed_token.nox
    claims.nox
    keys.nox
    keyring.nox
    rotation.nox
    jwk.nox
    jwks.nox
    provider.nox
    providers/
  native/                      # only audited necessary shims
  tests/
    unit/
    vectors/
    negative/
    integration/
    property/
    fuzz/
    concurrency/
    interoperability/
  examples/
    sign_and_verify.nox
    rotate_keys.nox
    verify_jwks.nox
    sentinel_adapter.nox
  tools/
    test-vectors/
```

Document any structural changes. Do not add empty directories/files just to match the diagram.

## 6. Public API contracts (illustrative, not verified NOX syntax)

Required logical interfaces; translate to actual compilable statically typed NOX constructs after compatibility inspection:

```text
CipherContext(config: CipherConfig, provider: CryptoProvider)
KeyRef(kid, algorithm, use, state, trust_domain, public_material/private_handle)
KeyRing(keys, active_signing_kid, verification_policy)
JwsSigner.sign(payload_bytes, signing_key, protected_headers) -> Result[CompactJws, CipherError]
JwsVerifier.verify(compact_jws, VerificationProfile) -> Result[VerifiedJws, CipherError]
JwtIssuer.encode(claims, signing_profile) -> Result[CompactJwt, CipherError]
JwtVerifier.verify(compact_jwt, ClaimsProfile) -> Result[VerifiedJwt, CipherError]
SignedToken.issue(payload_bytes, purpose, ttl, key_ref) -> Result[Token, CipherError]
SignedToken.verify(token, purpose, verification_profile) -> Result[VerifiedBytes, CipherError]
KeyRing.rotate(new_key, activate_at, retire_policy) -> Result[RotationReceipt, CipherError]
JwksSource.refresh() -> Result[RefreshStatus, CipherError]
```

### Result and evidence types

- `VerifiedJws`: verified payload bytes, protected header (sanitized), `kid`, algorithm, trust domain, verification timestamp, trusted key identifier. Construction restricted to successful verification.
- `VerifiedJwt`: above plus **validated** claims and validation profile identifier; never implicitly convertible to Sentinel `AuthenticatedPrincipal`.
- `UnverifiedJwt`: explicitly unsafe inspection-only type for debugging/diagnostics, no shared interface with verified types; do not expose it as a valid identity.
- `ClaimsProfile`: `expected_issuer`, `accepted_audiences`, `required_claims`, `leeway`, `max_age`, `require_exp`, optional `expected_typ`, explicit clock provider. Application chooses values; Cipher enforces them mechanically.
- `KeyRef`: key usage (`sign`/`verify`), allowed algorithm, stable `kid`, tenant/trust domain, validity window, state; prevent signing with verify-only keys.
- `CipherError`: stable typed categories `MalformedToken`, `UnsupportedAlgorithm`, `DisallowedAlgorithm`, `UnknownKey`, `AmbiguousKey`, `KeyUnavailable`, `InvalidSignature`, `InvalidClaims`, `Expired`, `NotYetValid`, `InvalidAudience`, `InvalidIssuer`, `InvalidKey`, `ProviderFailure`, `ConfigurationError`, `RemoteSourceError`, `RateLimited`, `ResourceLimitExceeded`. External adapters may map sensitive errors to generic 401 without leaking key state.
- Error behavior and whether detailed categories are returned externally must be explicit; no panic/crash on attacker-controlled input.

### Compatibility requirements

- API versioning follows semantic versioning; security fixes may tighten validation with clear release notes.
- Serialization formats and algorithm names follow JOSE exactly; do not invent incompatible compact formats.
- Public API never requires framework request/response types.
- Avoid ambiguous `verify(token)` without a policy/profile: verifier configuration must be explicit at construction or call time.

## 7. Compact JWS implementation

1. Accept **exactly three** compact segments for the supported profile; enforce maximum token bytes, header bytes, payload bytes, nesting depth, and bounded key candidate count.
2. Strictly decode protected header as UTF-8 JSON object, with duplicate member rejection; `alg` required and must be a string; validate `kid`, `typ`, `cty`, `crit`, `b64` types and extension rules.
3. Parse base64url without whitespace, padding, non-alphabet chars, or noncanonical representations (document exact canonicalization policy). Signature decoding has algorithm-specific expected size checks.
4. Select trusted key only within configured trust domain and fixed algorithm; no fallback across unrelated keys or key types. Do not use `kid` alone as proof of trust.
5. Verify over original signing input. For ES256 convert JOSE raw signature to provider format safely and reject malformed lengths; verify correct curve and digest.
6. Only after successful signature verification expose trusted payload to claims validation. If parsing payload is necessary earlier for resource checks, it remains untrusted and must not drive network requests or key selection.
7. Signing: protected headers generated from trusted config, algorithm matches key; reserved header fields cannot be overridden by caller. Encode payload exactly once. Return immutable compact representation.
8. Document support matrix for `crit`, detached payloads, `b64=false`, JWS JSON serialization: **reject unless explicitly supported**.

## 8. JWT claims validation

- Validate `exp`, `nbf`, `iat` as NumericDate with strict type/range/overflow handling. Define clock skew/leeway; reject negative or nonsensical values per documented profile. `exp` comparison uses configured clock and leeway consistently.
- `iss` exact match against configured trusted issuer; `aud` supports string or array of strings and must match at least one configured audience when required. Reject empty/invalid arrays, wrong types, and mismatched audiences.
- Require `exp` by default in recommended JWT verification profile; optional omission only via explicit profile for tightly scoped non-expiring use cases with documented risk.
- Enforce `iat <= now + leeway` when required, optional `max_age` and max token lifetime (`exp - iat`) checks. Do not infer issuance trust solely from `iat`.
- `sub`, `jti`, `azp`, `scope`, `roles`, and custom claims are **data**, not authorization decisions. `scope`/`roles` parsing or checking belongs to Sentinel unless a caller-supplied purely structural schema is used.
- Prevent cross-JWT confusion: distinguish access tokens, ID tokens, email verification, password reset, service tokens, and signed opaque tokens with purpose/type/audience separation. Sentinel defines accepted token classes and flows.
- No automatic replay prevention claim: `jti` alone does not prevent replay. Sentinel/application must implement nonce/replay store when required.
- Strict JSON duplicate-member rejection and limits apply to claims as well as headers.

## 9. Signed opaque tokens (itsdangerous-style)

- Provide versioned, purpose-bound tokens for application-defined byte payloads, not authentication policy.
- Domain-separated signing input includes immutable version, purpose, issue time, expiration, key identifier, and payload length/bytes with unambiguous encoding; use a vetted MAC/signature primitive.
- Require explicit purpose on verification and constant-time MAC verification where applicable; refuse purpose mismatch and expired token.
- Do not assume signed means encrypted: contents may be readable; document no confidentiality guarantee. Do not put secrets in unencrypted payloads.
- Format versioning, maximum sizes, backward-compatible rotation window, and migration tests are mandatory.
- This format is **not JWT/JWS**; keep APIs and token prefixes distinct to avoid substitution.

## 10. Key material and trust management

### Key classes and import

- Support symmetric HMAC secrets and provider-supported asymmetric keys; strictly validate JWK `kty`, `alg`, `use`, `key_ops`, `kid`, curve, modulus/exponent, key length, and encoding. Reject conflicting metadata.
- Public JWKS export must contain **public material only**. Never publish `d`, symmetric `k`, private CRT fields, or secret provider handles.
- Private key import only from explicit trusted configuration or secure provider; never from remote JWKS. Prefer non-exportable handles when supported.
- Restrict filesystem key loading permissions, validate paths through caller-configured sources, avoid plaintext key logging and secret copies. Document memory-zeroization limitations for NOX/GC and native provider.
- Generate keys using vetted provider + OS CSPRNG. Deterministic test fixtures are test-only and must not leak into release builds.

### Rotation state machine

```text
PREPARED -> ACTIVE_SIGNING -> VERIFY_ONLY -> RETIRED -> REVOKED/DESTROYED
```

- A newly prepared key is published to verifiers **before** use for signing; rollout requires propagation readiness checks.
- At most one active signing key per `(trust_domain, token_purpose, algorithm profile)` unless explicit documented multi-signer mode.
- Old key enters `VERIFY_ONLY` for bounded overlap at least as long as max accepted token lifetime + clock leeway + cache propagation delay, unless compromised.
- On compromise, **revoke immediately**; do not preserve overlap for convenience. Revocation policy must override cache and cause fail-closed behavior; document distributed propagation and operational limitations.
- Stable, unique `kid`; never reuse a retired `kid` for different material. Duplicate `kid` in same trust scope fails configuration.
- Rotation is atomic with compare-and-swap/version check on keyring state; concurrent rotations cannot create split-brain active signing state. Persistent multi-instance coordination is **external** unless a storage adapter with transactional guarantees is explicitly provided.
- In-memory keyring snapshots are immutable/read-copy-update or lock-protected; in-flight verification uses a consistent snapshot.
- Provide operator actions: prepare, activate, list (metadata only), retire, revoke, audit, and optionally publish JWKS. **No default CLI action prints private key material.**
- Define rollback behavior and an emergency key-compromise runbook in docs.

### Remote JWKS (opt-in)

- Only explicit allowlisted HTTPS endpoints from trusted configuration; no token-header URLs, redirects to untrusted origins, localhost/private/link-local metadata endpoints, or arbitrary proxy escape.
- Validate TLS certificates and hostnames; enforce redirect policy, DNS/IP SSRF controls (including DNS rebinding), response size/time limits, JSON depth, max keys, and accepted key types/algorithms.
- Implement cache TTL bounds, conditional requests (ETag/Last-Modified if available), request coalescing, rate limiting, bounded retries, and negative caching for unknown `kid` to avoid attacker-driven fetch storms.
- A cache refresh may be attempted for an unknown `kid` under strict throttling; never refresh repeatedly per token and never accept a token merely because refresh fails.
- On source outage: use **only** still-trusted keys within explicitly configured, bounded stale window; never extend revoked-key validity. Define and test outage behavior and rotation overlap.
- Remote JWKS is a source of public verification keys only; its configured issuer/trust domain binding is fixed and cannot be inferred from claims.

## 11. Cryptographic contracts and provider abstraction

- `CryptoProvider` capabilities: `secure_random`, `hmac_sign/verify`, `asymmetric_sign/verify`, `import_public_key`, `import_private_key`, `generate_key` (if supported), `public_jwk`, `destroy_handle`.
- All operations return typed success/error results; provider errors cannot leak secret bytes or raw key material. Avoid undefined behavior crossing FFI.
- Fixed algorithm/key binding at handle creation; validate key sizes and provider capabilities before use.
- Signing must never silently downgrade algorithm or switch provider. Verification must never try all algorithms opportunistically.
- Explicit thread-safety and reentrancy contracts; parallel signing/verifying cannot corrupt handles or caches.
- Test native provider against official vectors and an independent JOSE implementation; require negative vectors for modified headers, payloads, signatures, and key confusion.
- Define `CryptoContract` test suite that **every** provider must pass; no provider may advertise an algorithm until the suite passes on supported platforms.
- Zeroization best effort where feasible, with documented GC/allocator limitations; never promise perfect memory erasure in a managed runtime.
- Keep cryptographic source dependencies pinned, vulnerability-reviewed, license-compatible, and included in SBOM.

## 12. Sentinel integration contract (hard boundary)

```text
Incoming token
    -> Sentinel selects tenant, issuer, audience, accepted type, trust context
    -> Cipher verifies signature + caller-specified claims constraints
    -> Cipher returns VerifiedJwt / structured error
    -> Sentinel maps validated claims to principal/session and evaluates policy
    -> Nyx/Aether middleware enforces Sentinel decision
```

- Cipher never returns `is_admin`, `authorized`, `allow`, `deny`, `roles_granted`, or an authenticated session. It returns verified evidence only.
- Sentinel owns OAuth2/OIDC/PKCE, JWKS trust configuration **policy**, RBAC/ABAC, authorization, user provisioning, session/replay protections, and mapping claims to principals.
- Cipher owns JWS/JWT mechanics, crypto algorithm validation, key import, key rotation mechanics, and claims checks requested by Sentinel.
- Existing Nyx/Aether JWT implementations may be migrated behind adapters after compatibility/security tests; **do not silently replace their auth flows**.
- A `SentinelCipherAdapter` example must demonstrate explicit trust context and separation of verification from authorization, including a token with valid signature but insufficient permission being denied **by Sentinel**, not Cipher.
- Never treat a JWT `roles` claim as sufficient authority without Sentinel's configured issuer, audience, tenant, token class, and permission policy.

## 13. Threat model and abuse cases

Threat actors: unauthenticated internet clients, malicious tenant users, compromised signing keys, malicious JWKS responses, compromised worker/service, misconfigured integrators, and dependency supply-chain attackers.

Required adversarial scenarios:

1. `alg=none` and HS256/RS256 confusion.
2. `kid` path traversal, SQL injection, duplicate `kid`, huge `kid`, Unicode confusables.
3. `jku`/`x5u` SSRF, DNS rebinding, redirect attacks, private IP/metadata access.
4. Duplicate `alg`, duplicate `exp`, duplicate `aud`, malformed UTF-8, deeply nested JSON, oversized payload.
5. Wrong issuer, audience, token type, tenant, purpose, and key use.
6. Expired, not-yet-valid, future-issued, replayed tokens; skew boundary tests.
7. Revoked key retained in cache, stale JWKS, unknown-`kid` refresh storm, outage during rotation.
8. Public/private JWK leakage, short HMAC secrets, weak RSA keys, wrong EC curve, malformed ECDSA signatures.
9. Race between key activation, retirement, revocation, and parallel verification.
10. Sensitive data in logs, exceptions, traces, metrics, crash dumps, or sample code.
11. Signed-token format confusion and JWT access-token/ID-token confusion.
12. FFI memory corruption, resource leaks, provider thread safety, RNG failure.

Maintain `docs/threat-model.md` with assets, trust boundaries, attacks, mitigations, residual risks, and test IDs. Security-critical issues block release.

## 14. Testing strategy and required matrix

### Unit and standards tests

- Valid and invalid official JOSE vectors per supported algorithm; independent library interoperability in both directions.
- Base64url canonical/noncanonical, duplicate JSON keys, `crit`, `b64`, `typ`, invalid segment count, unsupported `alg`.
- Every registered claim type and temporal boundary (`now-1`, `now`, `now+1`, leeway), clock injection, overflow/NaN/fraction policy.
- Key mismatch and algorithm confusion; `kid` ambiguity; asymmetric signature encodings; purpose separation.

### Property and fuzz testing

- Parser and verifier fuzzing with arbitrary bytes; no crash, panic, unbounded allocation, infinite loop, or sensitive error leak.
- Mutation tests for signed header/payload/signature; changes must invalidate verification except explicitly permitted equivalence.
- Property tests for roundtrip, rotation state invariants, cache isolation, and keyring consistency.
- Stress/concurrency tests for parallel verify/sign, rotate/verify, JWKS refresh coalescing, and shutdown.

### Integration and chaos

- Real HTTPS JWKS fixture with TLS, redirects, DNS/SSRF controls, 304 responses, timeout, malformed JSON, large response, 429/5xx.
- Simulate key publication lag, activation races, provider outage, network partition, compromise/revocation, and restart.
- Nyx/Aether adapter and Sentinel boundary test: **valid cryptographic signature but unauthorized action remains denied**.
- Cross-platform CI for supported targets; ASan/UBSan or equivalent for native shims where feasible.

### Acceptance gates

- **100%** pass rate for required official/negative vectors and security regressions.
- No known critical/high security vulnerabilities in shipping dependencies without documented mitigation and approval.
- All public APIs documented with examples and explicit trust assumptions.
- Reproducible build, pinned dependencies, license/SBOM, `SECURITY.md`, threat model, and tested rotation runbook.
- Performance benchmarks reported with hardware/compiler/provider; performance cannot justify weakening validation.

## 15. Phased roadmap with exit criteria

### Phase 0 — Feasibility and contracts

- Inspect current NOX toolchain, standard library, FFI, package manager, existing framework JWT code, and Sentinel interfaces.
- Select crypto provider and record ADR; define security profile, supported algorithms/platforms, threat model, typed API.
- **Exit:** verified minimal NOX-to-provider sign/verify spike, compilation instructions, test harness, no invented APIs.

### Phase 1 — Strict core and HS256

- Strict compact parser, strict JSON/base64url, typed errors, HMAC provider, fixed algorithm allowlist, basic JWS sign/verify.
- **Exit:** full positive/negative HS256 vectors, algorithm confusion rejection, size limits, fuzz smoke suite.

### Phase 2 — JWT and signed tokens

- Claims profiles, temporal/issuer/audience checks, immutable verified types, purpose-bound signed tokens.
- **Exit:** complete temporal and purpose-crossing tests; verified vs unverified type separation.

### Phase 3 — Asymmetric JOSE and JWK

- RS256 first; PS256/ES256/Ed25519 only when vetted provider and vectors are ready; public/private JWK parsing and public JWKS export.
- **Exit:** independent interoperability, key-size/curve/signature-format negatives, no secret export.

### Phase 4 — Keyring and rotation

- Key state machine, atomic activation, immutable snapshots, revocation, overlap, concurrency tests, audit metadata.
- **Exit:** repeatable rotation/rollback/compromise simulations, no dual active signer in defined scope.

### Phase 5 — Remote JWKS and resilience

- Configured HTTPS JWKS fetch, bounded caching, refresh, negative caching, SSRF controls, outage behavior.
- **Exit:** TLS/SSRF/fetch storm tests, stale-key and revoked-key scenarios pass.

### Phase 6 — Ecosystem adapters and release

- Sentinel integration example, optional Nyx/Aether adapters, Vault secret-provider adapter, Obsidian/Pulse hooks, documentation, benchmark, CI matrix, security review.
- **Exit:** stable API and security signoff; all release gates met. No claim of production readiness before this phase.

### Future candidates (not implied by v1)

- External KMS/HSM providers, JWE, detached JWS, additional algorithms, stronger hardware-backed key isolation, advanced OIDC token profiles through Sentinel integration. Each requires separate threat model and ADR.

## 16. Engineering conventions

- Prefer small modules and immutable value types; no global mutable keyring or implicit singleton verifier.
- Strong static types for `TrustedKey`, `UntrustedHeader`, `VerifiedJwt`, `Purpose`, `TrustDomain`, and `AlgorithmId`; prevent mixing token and key classes.
- Use explicit `Result`/error patterns supported by actual NOX; avoid exceptions that hide security failures.
- Configuration is validated eagerly. Defaults must be secure; unsafe toggles require explicit opt-in, warnings, and tests; never silently downgrade.
- Public functions have doc comments with security contract, accepted input, limits, failure behavior, and thread safety.
- No secret in fixtures checked into repo. Synthetic public keys may be committed; test-only private keys must be unmistakably marked and never used in production examples.
- Each security fix adds regression test and changelog note. Each architectural deviation adds an ADR.
- No blanket `catch` that turns verification failure into success. No fallback to unchecked JWT decode.
- All CI commands must be verified against current `noxc` and checked into workflow docs; no fictitious green tests.

## 17. Observability and operations

- Emit optional structured events: verification success/failure **category**, key activation/retirement/revocation, JWKS refresh outcome, provider error, and cache status. Do not include token, full claims, private key, or raw secret.
- Metrics use bounded labels (`algorithm`, `outcome`, `source_kind`); never user ID, token, `kid` if high cardinality, or raw issuer URL.
- Traces must avoid bearer token propagation into attributes/baggage. Integrate Pulse/OpenTelemetry through optional adapter.
- Audit key changes with actor supplied by host application, operation, key fingerprint/metadata, timestamp, and outcome. Cipher records cryptographic operations; Sentinel owns user/security policy audit semantics.
- Operational runbooks: routine rotation, emergency compromise, JWKS outage, algorithm deprecation, incident triage, key backup/recovery (host-controlled).

## 18. Definition of Done — agent checklist

- [ ] Current NOX compiler/stdlib/FFI capabilities checked and documented.
- [ ] Code compiles with real `noxc` and all claimed platforms are verified.
- [ ] API is typed, framework-independent, and cannot accidentally equate verification with authorization.
- [ ] No `alg=none`, algorithm confusion, remote-header key fetch, duplicate JSON ambiguity, or permissive verification fallback.
- [ ] Supported algorithms pass official vectors and independent interoperability tests.
- [ ] JWT claims validation handles types, overflow, skew, issuer, audience, and purpose separation.
- [ ] Key import/export cannot leak secret material; keyring rotation and revocation tests pass.
- [ ] JWKS SSRF/caching/outage behavior passes if remote JWKS feature is enabled.
- [ ] Fuzz, concurrency, negative, integration, and regression tests executed and recorded.
- [ ] Threat model, docs, SECURITY.md, dependency audit, changelog, and runbooks updated.
- [ ] Sentinel boundary demonstrated: valid token can still be denied by policy.
- [ ] No stubs, mocks, skipped tests, or unsupported algorithms are misrepresented as production-ready.

## 19. Decision protocol

When requirements conflict: (1) protect secrets and reject insecure tokens; (2) preserve cryptographic correctness and explicit trust boundaries; (3) follow current NOX capabilities; (4) preserve stable API compatibility when safe; (5) optimize performance. For unresolved security or protocol ambiguity, write an ADR and request review; **never improvise a cryptographic shortcut**.

**North star:** *Cipher proves cryptographic facts. Sentinel decides identity, trust policy, and access.*
