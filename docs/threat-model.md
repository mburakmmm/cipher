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

## 3. Residual Risks & Exclusions

- **Bearer Token Theft in Transit:** Cipher cannot prevent token interception if TLS is broken or terminated insecurely by the host application.
- **Replay Attacks:** Cipher validates time (`exp`, `nbf`), but replay prevention requires an application-level nonce store managed by Sentinel.
