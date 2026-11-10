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
