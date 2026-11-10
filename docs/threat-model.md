# Threat Model — Cipher

> **Target:** NOX Cryptographic Tokens & Contracts  
> **Status:** Active Normative Document  
> **Standard References:** RFC 7515, RFC 7519, RFC 8725 (JWT BCP)

---

## 1. Threat Actors & Attack Vectors

| Threat Actor | Capabilities | Objective |
|---|---|---|
| **Unauthenticated Network Attacker** | Sends arbitrary tokens, manipulates headers, forged signatures | Bypass authentication, elevate privileges, forge tokens |
| **Malicious Tenant User** | Possesses valid token for Tenant A | Access Tenant B's keys/resources (cross-tenant confusion) |
| **Compromised Key Holder** | Controls a revoked or expired private key | Continue issuing valid tokens post-revocation |
| **Malicious JWKS Provider** | Controls untrusted external HTTP endpoints | SSRF, internal network scan, denial of service (DoS) |
| **Eavesdropper / Network Observer** | Inspects token traffic | Steal bearer tokens or infer secrets via timing attacks |

---

## 2. Adversarial Scenarios & Mitigations

### 2.1 Algorithm Manipulation (`alg=none` and Algorithm Confusion)
- **Threat:** Attacker modifies `{"alg":"HS256"}` to `{"alg":"none"}` or signs an RSA token with an HMAC secret (confusing public key with secret).
- **Mitigation:**
  - `alg=none` is unconditionally rejected at the parser level.
  - Verification algorithm is strictly verifier-controlled through an explicit allowlist.
  - Symmetric secrets and asymmetric keys use incompatible static types in NOX.

### 2.2 Untrusted Header Parameter Abuse (`kid`, `jku`, `x5u`)
- **Threat:** Attacker provides SQL injection, path traversal (`../../etc/passwd`), or malicious URL in `kid` or `jku` to force arbitrary file read or SSRF.
- **Mitigation:**
  - `kid` is treated strictly as an opaque lookup identifier (exact equality match in memory).
  - Remote key directives (`jku`, `x5u`, embedded `jwk`) are ignored or rejected by default.
  - Untrusted header URLs are never fetched over the network.

### 2.3 Timing Side-Channel Attacks
- **Threat:** Byte-by-byte string comparison (`==`) stops on the first mismatch, allowing an attacker to deduce the valid signature by observing response times.
- **Mitigation:**
  - All signature and MAC checks use `nox.crypto.constant_time_eq`.

### 2.4 Duplicate JSON Keys & Ambiguity
- **Threat:** Attacker crafts JSON with duplicate keys (e.g. `{"alg":"HS256", "alg":"none"}`) hoping parser will verify one and use the other.
- **Mitigation:**
  - Strict duplicate key detection in `json_strict.nox` rejects any JSON containing repeated object keys.

### 2.5 Re-serialization & ASCII Input Mismatch
- **Threat:** Verifier decodes header/payload, modifies formatting or whitespace, and re-encodes, verifying an altered payload.
- **Mitigation:**
  - The signing input is preserved as the exact original ASCII substring `base64url(header) + "." + base64url(payload)`.

### 2.6 Fetch Storms and DoS via Unknown `kid`
- **Threat:** Attacker sends thousands of requests with random `kid`s to trigger an outgoing JWKS HTTP request for every token.
- **Mitigation:**
  - Rate limiting, request coalescing, and negative caching for non-existent `kid`s (bounded at 256 entries).

### 2.7 DNS Rebinding, Redirect Chains, and DNS Pinning in Real HTTP Transport
- **Threat:** Attacker registers a domain (e.g. `evil-jwks.org`) that resolves to a public IP on pre-check, but returns a private IP (`127.0.0.1` or `169.254.169.254`) upon actual HTTP connection (DNS Rebinding / TOCTOU SSRF). Alternatively, the server responds with a 302 redirect pointing to an internal service.
- **Mitigation & Normative Requirements:**
  - **Programmatic Post-Resolution Verification:** Cipher exports `verify_resolved_ip(ip_str: str) -> bool`, backed by decoupled syntactic parsers (`parse_ipv4`, `parse_ipv6`) and SSRF policy evaluators (`is_restricted_ipv4_addr`, `is_restricted_ipv6_addr`). Any malformed IP syntax is immediately rejected (`false`). Any HTTP transport layer integrated with Cipher must resolve DNS, pass the resulting socket IP string directly to `verify_resolved_ip()`, and abort connection if it returns `false`.
  - **DNS Pinning:** Production HTTP clients must connect strictly to the validated numeric IP address and pass the original hostname via TLS SNI (Server Name Indication) and `Host` header. Re-resolution during the HTTP session is forbidden.
  - **Strict Redirect Handling:** The HTTP transport client must either disable redirects completely or re-run `is_safe_jwks_url()` on every redirect target in the chain prior to following it.
  - **Decoupled Structural CIDR & IPv6 Bitmask Filtering:** Cipher parses embedded IPv4 addresses in IPv6 (`::ffff:w.x.y.z`) as two 16-bit hextets per RFC 4291, rejects all 14 non-routable IPv4 CIDR blocks (including RFC 6598 CGNAT `100.64.0.0/10` and RFC 2544 Benchmark `198.18.0.0/15`), and evaluates 16-bit hextet bitmasks for IPv4-mapped/compatible, NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`), Teredo (`2001::/23`), RFC 4193 ULA (`fc00::/7`), RFC 4291 Link-Local (`fe80::/10`), Site-Local (`fec0::/10`), Multicast (`ff00::/8`), Discard (`100::/64`), and Documentation prefixes (`2001:db8::/32`, `3fff::/20`).



---

## 3. Residual Risks, Trust Boundaries & Exclusions

- **In-Process Tamper-Evident Sealing vs. Hardware/Process Isolation:**
  - Because NOX 2.1 does not provide a language-level `private` or `readonly` access modifier on class fields, Cipher protects `KeyRingState` and `KeyRing` with a two-layer **tamper-evident integrity check**:
    1. `KeyRingState._integrity_hash`: A SHA-256 digest computed over an unambiguous, prefix-free UTF-8 byte-length-prefixed canonical serialization (`_serialize_state_canonical` using `<decimal_utf8_byte_len>#<exact_utf8_bytes>` via `nox.strings.byte_len`, `nox.strings.byte_at`, and `nox.strings.char_from_byte`, immune to `:`, `|`, `#` delimiter injection and multi-byte UTF-8 length skew).
    2. `KeyRing._state_mac`: A per-instance HMAC-SHA256 authentication tag (`nox.crypto.hmac_sha256(self._seal_key, st.get_seal_hash())`) verified in constant time (`nox.crypto.constant_time_eq`) on state reads.
  - **Explicit Security Boundary:** This mechanism guarantees immediate fail-closed detection (`ConfigurationError`) of accidental or partial direct field mutations (e.g., `ring._state.version = 99`, `ring._state._keys[0].state = STATE_REVOKED`, or replacing `ring._state` with an externally constructed `KeyRingState`). However, it is a **tamper-evident integrity check**, *not* a cryptographic access-control boundary against arbitrary malicious code executing within the same OS process and address space (which could read `ring._seal_key` and overwrite both `ring._state` and `ring._state_mac`). True isolation against untrusted code requires OS process separation, WASM capability sandboxes (`--deny-capability`), or external HSM/KMS key custody.
- **Cross-Thread Shared Handle Security Contract (`export_shared_handle` / `attach_shared_handle`):**
  - **Zero Plaintext Secrets in Handle Strings & No Raw Cell Reader APIs:** `export_shared_handle(max_words: int = 512) -> str` never serializes `self._seal_key` or key material into the returned string. Instead, `_seal_key` is stored inside 11 dedicated process-wide `nox.atomic.AtomicInt` cells (`_shared_key_cells`), and the handle string contains **only numeric atomic handle IDs** (`lock_h|seq_h|ver_h|len_h|alive_h|readers_h|key_cell_handles|data_cell_handles`). Furthermore, the public `KeyRing` API exposes no raw cell or key-cell reader methods; callers verify zeroization exclusively via the boolean predicate `is_shared_zeroized() -> bool`.
  - **In-Process Capability Token Semantics:** Although the handle string contains only integer cell IDs, any code within the same OS process that possesses the handle string can call `attach_shared_handle()` to read and rotate the shared `KeyRing`. Therefore, a shared handle string must be treated as an **in-process capability token**: never log raw handle strings (use `redact_shared_handle(handle_str)` which returns `"KeyRingSharedHandle([REDACTED])"`), never serialize them to external storage or network responses, and pass them only to trusted worker threads spawned by the owning component.
  - **Single-Word CAS Gate (`_shared_gate`), Explicit Lifecycle States (`UNSHARED → ALIVE → CLOSING → DRAINING → DESTROYED`), Owner-Only Teardown & Exception-Safe Zeroization:** Calling `zeroize_shared_state()` strictly requires acquiring the hardware writer lock (`_write_lock`) and being the owning `KeyRing` instance (`is_shared_owner() == True`). Inside an exception-safe `try/except` block (which guarantees Seqlock even-counter restoration and `_write_lock.store(False)` release on any error), it atomically sets `SHARED_CLOSING_BIT` (`1 << 30`) on `_shared_gate` (`nox.atomic.AtomicInt`) via hardware `compare_and_swap`. Because `_try_acquire_reader_gate()` and `attach_shared_handle()` compete on the exact same 64-bit `_shared_gate` word via CAS (`bits 0..29` = active readers, `bit 30` = `SHARED_CLOSING_BIT`, `bits 32..61` = attached workers), no reader or worker can ever register once `SHARED_CLOSING_BIT` is set (closing the `T1..T5` race). `free_shared_handle(require_zero_workers=...)` enforces owner-only teardown, optionally requires all workers to have called `detach_shared_handle()`, drains all in-flight readers (`(_shared_gate & SHARED_READER_MASK) == 0`), frees the underlying `nox.atomic` cells, and transitions `get_shared_lifecycle_state()` to `DESTROYED`.
- **Bearer Token Theft in Transit:** Cipher cannot prevent token interception if TLS is broken or terminated insecurely by the host application.
- **Replay Attacks:** Cipher validates time (`exp`, `nbf`), but replay prevention requires an application-level nonce store managed by Sentinel.
