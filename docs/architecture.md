# Architecture & Design — Cipher

## 1. System Overview

Cipher is a framework-independent, pure NOX cryptographic token and contract library. It provides high-performance, strictly verified implementations of JWS (RFC 7515), JWT claims validation (RFC 7519), JWK (RFC 7517 / RFC 7638), purpose-bound signed tokens, and key lifecycle management.

```
       Consumers: Nyx / Aether / Aura / Sentinel / Applications
                                  │
               cipher.nox (Unified Public Interface)
                                  │
     ┌────────────────────────────┼────────────────────────────┐
     │                            │                            │
     ▼                            ▼                            ▼
[ Compact JWS ]            [ JWT Claims ]              [ Signed Tokens ]
  RFC 7515                   RFC 7519                    itsdangerous
  Strict ASCII verify        Temporal boundaries         Purpose-bound
  ProtectedHeader            Audience / Issuer           Domain separation
     │                            │                            │
     └────────────────────────────┼────────────────────────────┘
                                  │
                                  ▼
                     [ KeyRing & Key Lifecycle ]
                       PREPARED -> ACTIVE_SIGNING -> VERIFY_ONLY -> RETIRED / REVOKED
                       Atomic rotation with bounded overlap
                       Trust domain isolation
                                  │
                                  ▼
                     [ CryptoProvider Abstraction ]
                       OS CSPRNG (@capability.requires("entropy"))
                       Verified HMAC-SHA256 & Constant-time MAC checks
```

## 2. Component Structure

- **`errors.nox`**: Comprehensive strongly-typed exception hierarchy rooted in `CipherError`. No sensitive parameters or secrets in exception strings.
- **`encoding.nox`**: RFC 4648 §5 URL-safe base64 encoding/decoding rejecting padding (`=`), whitespace, and non-alphabet characters. Hex conversion utilities.
- **`json_strict.nox`**: RFC 8725 §3.10 duplicate key rejection, bounded sizes, and strongly-typed value accessors.
- **`provider.nox`**: Pluggable provider abstraction with `DefaultCryptoProvider` backed by OS CSPRNG.
- **`jws.nox`**: Compact JWS parsing, signing, and verification over original ASCII bytes with verifier-controlled algorithm allowlists.
- **`claims.nox`**: Numerical date verification (`exp`, `nbf`, `iat`), clock leeway, issuer exact match, audience string/array match.
- **`jwt.nox`**: Two-stage validation returning `VerifiedJwt` evidence. Separate `UnverifiedJwt` for diagnostic inspection.
- **`signed_token.nox`**: Domain-separated, purpose-bound tokens (`cip_opk_v1`) preventing cross-purpose token substitution.
- **`jwk.nox`**: RFC 7517 JWK model, private key leakage protection, and RFC 7638 SHA-256 thumbprints.
- **`keys.nox` & `rotation.nox`**: Key lifecycle state machine and audit rotation receipts.
- **`keyring.nox`**: Multi-tenant keyring with single-active-signer invariants and validate-before-commit atomic rollback.
- **`jwks.nox`**: Resilient remote JWKS discovery with SSRF defenses, bounded negative caching, and stale tolerance.

## 3. Resilience, SSRF & Atomic Rollback Invariants

### KeyRing Unified State, Hardware Seqlock Ordering, Commit Linearization & Shared Atomic State
`KeyRing` manages key lifecycle and rotation through a deeply immutable `KeyRingState` model backed by `nox.atomic` hardware primitives and a Seqlock reader/writer protocol:
1. **Prefix-Free Canonical Serialization & Tamper-Evident Sealing (`_serialize_state_canonical`):**
   - Internal keys are stored in `_keys: list[KeyRef]` with defensive cloning on both construction and inspection (`get_keys()`).
   - State serialization uses an unambiguous length-prefixed format (`CIPHER-KR-CANON-V2#<byte_len>#<val>...`) that is mathematically prefix-free and immune to delimiter injection (`:`, `|`, `#`).
   - `KeyRingState` verifies its SHA-256 `_integrity_hash` in constant time (`nox.crypto.constant_time_eq`), and `KeyRing` additionally verifies a per-instance HMAC-SHA256 tag (`_state_mac` keyed with `_seal_key`). This provides an in-process tamper-evident integrity check against unauthorized direct field or object mutation.
2. **Hardware Acquire-Release Seqlock Memory Ordering (`_read_consistent_state`):**
   - In `noxrt.o`, `nox_atomic_cas` (`casal` on ARM64, `lock cmpxchg` on x86_64) and `nox_atomic_add` (`ldaddal` on ARM64, `lock xadd` on x86_64) issue full hardware **Acquire-Release (`AL` / `seq_cst`) RMW barriers**, whereas `nox_atomic_load` (`ldar`) and `nox_atomic_store` (`stlr`) are one-way barriers.
   - To prevent weakly-ordered CPUs (ARM64) from reordering normal loads (`st = self._state`) past the second sequence read `s2`, `_read_consistent_state()` uses `self._seq.add(0)` (`ldaddal 0` / `lock xadd 0`) for both `s1` and `s2`:
     - The **Acquire** half of `s1 = self._seq.add(0)` prevents subsequent reads of `_state` or `_shared_cells` from floating above `s1`.
     - The **Release** half of `s2 = self._seq.add(0)` prevents prior reads of `_state` or `_shared_cells` from sinking below `s2`.
   - **Single-Call Snapshot Rule:** While `get_version()` and `get_state()` each execute a coherent Seqlock read, two separate calls (`v = ring.get_version()` followed by `s = ring.get_state()`) may legitimately observe an intervening writer commit. Callers requiring a paired `(version, keys)` view must call `st = ring.get_state()` once and read `st.version` and `st.get_keys()` from the same `KeyRingState` instance.
3. **Two-Phase Commit & Explicit Linearization Point (`_commit_state`):**
   - **Phase A (Pre-Linearization Validation & Staging — Rollback Permitted):** Under the hardware writer mutex (`_write_lock.compare_and_swap(False, True)`), `_commit_state` verifies `prev_state` and `new_state` seals, pre-serializes canonical state bytes, checks shared-memory capacity, advances `_atomic_version.compare_and_swap(base_ver, base_ver + 1)`, enters the odd Seqlock state via `_seq.compare_and_swap(base_ver * 2, base_ver * 2 + 1)` (`casal` Acquire-Release barrier), and stages `_state`, `_state_mac`, and `_shared_cells`. While `_seq` is odd, no Seqlock reader can complete a read; if any error occurs in Phase A (`committed == False`), state and sequence are rolled back cleanly before releasing `_write_lock`.
   - **Phase B (The Linearization Point — Irreversible):** The single atomic instruction `self._seq.compare_and_swap(odd_seq, even_next_seq)` (`casal` / `lock cmpxchg`) is the **exact Linearization Point** of the commit. Once `committed = True`, rollback is strictly forbidden (`if not committed:`), guaranteeing that no committed state observed by a reader can ever be rolled back.
4. **Cross-OS-Thread Shared Atomic State (`export_shared_handle` / `attach_shared_handle`):**
   - Because NOX's default QBE `nox.thread.start` uses shared-nothing per-worker heaps, `KeyRing` provides `export_shared_handle() -> str` and `attach_shared_handle(handle_str: str)` backed by 512 process-wide `nox.atomic.AtomicInt` cells (`SHARED_ATOMIC_WORDS = 512`, 3,072 bytes capacity).
   - Writers pack the length-prefixed canonical `KeyRingState` into the shared atomic cells during Phase A (before the Linearization Point), and readers across any OS thread automatically deserialize and verify the latest `KeyRingState` whenever `st.version != (s1 >> 1)`.

### Decoupled IP Syntax Parsing, SSRF Policy & Negative Cache Boundaries
`jwks.nox` strictly separates syntactic IP parsing from SSRF security policy evaluation:
- **Syntactic Layer (`parse_ipv4` -> `IPv4Address`, `parse_ipv6` -> `IPv6Address`):** Enforces exact 4-octet decimal IPv4 syntax (rejecting octal leading zeros, hex, and out-of-range octets) and RFC 4291 8-hextet IPv6 expansion (correctly accounting for embedded 32-bit IPv4 suffixes such as `::ffff:8.8.8.8` as two 16-bit hextets, and rejecting multiple `::`, zone IDs `%`, or malformed segments with `EncodingError`).
- **SSRF Policy Layer (`is_restricted_ipv4_addr`, `is_restricted_ipv6_addr`):** Evaluates validated address structures against all 14 non-routable IPv4 CIDR blocks (`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` CGNAT, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15` Benchmark, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4+`) and IPv6 special/transition ranges (Loopback `::1`, Unspecified `::`, IPv4-mapped `::ffff:0:0/96`, IPv4-compatible, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/23`, ULA `fc00::/7`, Link-Local `fe80::/10`, Site-Local `fec0::/10`, Multicast `ff00::/8`, Discard `100::/64`, Documentation `2001:db8::/32` & `3fff::/20`).
- **Post-Resolution Verification (`verify_resolved_ip`):** Requires syntactic validity first (`parse_ipv4` / `parse_ipv6`), returning `false` on any malformed IP string before evaluating `!is_restricted_ipv4_addr` / `!is_restricted_ipv6_addr`.


- Rejects all RFC 1918 private IPv4 ranges (`10.0.0.0/8`, `192.168.0.0/16`, and all 16 subnets of `172.16.0.0/12`).
- Negative cache is bounded by `MAX_NEGATIVE_CACHE_ENTRIES` (256) with FIFO eviction, preventing memory exhaustion attacks under random `kid` floods.
- Note on transport: Full socket pinning and DNS rebinding protections belong to NOX's common HTTP transport layer when remote HTTP fetching is integrated.
