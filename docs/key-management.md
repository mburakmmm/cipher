# Key Management & Safe Rotation Lifecycle — Cipher

## 1. Key Lifecycle State Machine

Each cryptographic key managed in Cipher transitions through a strict five-stage lifecycle:

```
    [ PREPARED ]
         │
         ▼
[ ACTIVE_SIGNING ] ──> (Rotated) ──> [ VERIFY_ONLY ] ──> (Expired) ──> [ RETIRED ]
         │                                  │
         │ (Compromised)                    │ (Compromised)
         ▼                                  ▼
    [ REVOKED ] <───────────────────────────┘
```

- **`PREPARED`**: Distributed to verification nodes in advance; does not sign tokens yet.
- **`ACTIVE_SIGNING`**: Currently authorized signing key. Invariant: At most one active signing key per algorithm within a `trust_domain`.
- **`VERIFY_ONLY`**: Former signing key retained during the bounded overlap window (`retire_at = now + overlap_seconds`).
- **`RETIRED`**: Overlap window has elapsed; key is disabled and rejected for verification.
- **`REVOKED`**: Compromised key immediately terminated. Terminal state: cannot transition to any other state.

## 2. Rotation & Overlap Protocol

When rotating keys via `KeyRing.rotate(new_key, overlap_seconds)`:
1. The new key transitions from `PREPARED` to `ACTIVE_SIGNING`.
2. The former signing key transitions to `VERIFY_ONLY` with an expiration timestamp (`retire_at = now + overlap_seconds`).
3. An immutable `RotationReceipt` is generated recording `old_kid`, `new_kid`, `overlap_seconds`, and rotation timestamp.
4. Outstanding tokens issued under the old key remain valid until the overlap window closes.

## 3. Expired Key Compaction (`purge_expired_keys`)

Long-running services that rotate keys frequently can compact their `KeyRing` state atomically using `KeyRing.purge_expired_keys(current_time_sec: int, expected_version: int = -1) -> int`:
- Removes all keys in `STATE_RETIRED` or `STATE_REVOKED`, as well as `STATE_VERIFY_ONLY` keys whose overlap window has elapsed (`retire_at > 0 and current_time_sec >= retire_at`).
- Preserves all `STATE_ACTIVE_SIGNING`, `STATE_PREPARED`, and non-expired `STATE_VERIFY_ONLY` keys.
- Executes under the hardware writer mutex, Seqlock, and version CAS, immediately propagating the compacted state to all attached shared OS threads and returning the number of purged keys.

## 4. Cross-OS-Thread Shared Handle Lifecycle & Security Contract

To share a `KeyRing` across NOX's shared-nothing OS threads (`nox.thread.start`):
1. **Export (`export_shared_handle(max_words: int = 512) -> str`):** Allocates process-wide `nox.atomic` cells (`max_words` between `64` and `8192`, default `512` words = `3,072` bytes; up to `8192` words = `49,152` bytes). The returned string contains **only numeric atomic handle IDs** (`lock_h|seq_h|ver_h|len_h|alive_h|readers_h|key_cells|data_cells`); no plaintext key material or `_seal_key` is ever present in the string.
2. **Capacity Telemetry (`shared_capacity_bytes()`, `shared_used_bytes()`, `shared_usage_permille()`):** Long-running Nyx and Aether services can monitor shared memory utilization in bytes and permille (`0..1000`) to trigger `purge_expired_keys()` proactively before reaching capacity limits.
3. **Capability Protection (`redact_shared_handle`):** Treat the handle string as an in-process capability token. Never log raw handle strings; use `redact_shared_handle(handle_str)` (`"KeyRingSharedHandle([REDACTED])"`) in diagnostic logs. Raw key and data cell values are never exposed on the public `KeyRing` API; use `is_shared_zeroized() -> bool` for boolean-only zeroization verification.
4. **Worker Attachment (`attach_shared_handle(handle_str)`):** Worker threads attach to the shared atomic cells and read/rotate keys under the hardware Acquire-Release Seqlock (`ldaddal`/`casal` on ARM64, `lock xadd`/`lock cmpxchg` on x86_64). All canonical field lengths and word packing operate on exact UTF-8 bytes (`nox.strings.byte_len`, `nox.strings.byte_at`, `nox.strings.char_from_byte`).
5. **Strict Lock-Guarded Zeroization & Active Reader Drain (`zeroize_shared_state()` / `free_shared_handle()`):**
   - `zeroize_shared_state()` **strictly requires** acquiring the hardware writer lock (`_write_lock`). If another writer holds the lock and it cannot be acquired within the bounded spin window, `zeroize_shared_state()` fails closed with `ConfigurationError` without modifying a single shared cell.
   - Once the writer lock is acquired, `zeroize_shared_state()` enters the odd Seqlock write phase, sets `_shared_alive = False`, overwrites all shared data cells and shared HMAC key cells with `0`, seals the even Seqlock counter, and releases `_write_lock`.
   - Active readers inside `_read_consistent_state()` are tracked via `_shared_readers` (`nox.atomic.AtomicInt`, inspected via `active_shared_readers()`). `free_shared_handle()` invokes `zeroize_shared_state()` and waits for all active readers (`_shared_readers == 0`) to drain before freeing the underlying `nox.atomic` cells (or raises `ConfigurationError` if a reader fails to drain), preventing use-after-free races.
