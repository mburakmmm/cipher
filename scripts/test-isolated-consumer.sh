#!/usr/bin/env bash
# ==============================================================================
# Cipher — Isolated External Consumer Integration Test
# Validates that an independent application outside the repository can consume
# Cipher public APIs cleanly without depending on the development repo state.
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d /tmp/cipher_isolated_consumer_XXXXXX)"

cleanup() {
    echo "==> Cleaning up isolated consumer test directory: ${TMP_DIR}"
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "==> Setting up isolated consumer project in: ${TMP_DIR}"
mkdir -p "${TMP_DIR}"

# 1. Vendor / copy cipher library modules and package hierarchy to isolated environment
cp "${REPO_ROOT}"/*.nox "${TMP_DIR}/"
cp -r "${REPO_ROOT}/cipher" "${TMP_DIR}/"

# 2. Write consumer application nox.json
cat << 'EOF' > "${TMP_DIR}/nox.json"
{
  "name": "isolated_consumer_app",
  "entry": "main.nox"
}
EOF

# 3. Write consumer application code
cat << 'EOF' > "${TMP_DIR}/main.nox"
from cipher import ClaimsProfile, JwkKey, KeyRef, KeyRing, STATE_ACTIVE_SIGNING, VerificationProfile, VerifiedJwt, encode_jwt_hs256, issue_signed_token, parse_jwk, verify_jwt_hs256, verify_signed_token

print("==> [Isolated Consumer] Starting integration test...")

secret: str = "isolated-consumer-production-secret-at-least-32-bytes"

# 1. JWT Encoding & Strict Verification
payload_json: str = "{\"sub\":\"usr_isolated_99\",\"iss\":\"https://id.enterprise.org\",\"aud\":\"https://api.enterprise.org\",\"exp\":1700003600,\"typ\":\"JWT\"}"
token: str = encode_jwt_hs256(payload_json, secret, kid="k-iso-1")
print("[Isolated Consumer] Encoded Token successfully")

c_prof: ClaimsProfile = ClaimsProfile(
    expected_issuer="https://id.enterprise.org",
    clock_time_sec=1700000000
)
c_prof.with_audience("https://api.enterprise.org")

v_prof: VerificationProfile = VerificationProfile(["HS256"], expected_kid="k-iso-1", expected_typ="JWT")
verified: VerifiedJwt = verify_jwt_hs256(token, secret, v_prof, c_prof)

if verified.claims.sub != "usr_isolated_99":
    raise Exception("Subject claim mismatch in isolated consumer!")
print("[Isolated Consumer] Verified JWT sub: " + verified.claims.sub)

# 2. Signed Opaque Token
raw_data: str = "secure_session_payload_42"
sig_tok: str = issue_signed_token(raw_data, "web_session", secret, ttl_seconds=300)
v_data: str = verify_signed_token(sig_tok, "web_session", secret)
if v_data != raw_data:
    raise Exception("Payload mismatch in signed token!")
print("[Isolated Consumer] Verified Signed Token payload: " + v_data)

# 3. KeyRing & Rotation
ring: KeyRing = KeyRing(trust_domain="enterprise-prod")
k_ref: KeyRef = KeyRef("k-iso-1", "HS256", secret, trust_domain="enterprise-prod", state=STATE_ACTIVE_SIGNING)
ring.add_key(k_ref)
active_k: KeyRef = ring.get_signing_key("HS256")
if active_k.kid != "k-iso-1":
    raise Exception("KeyRing active signer mismatch!")
print("[Isolated Consumer] KeyRing active signer: " + active_k.kid)

print("Isolated Consumer verification SUCCESS!")
EOF

# 4. Compile and execute isolated consumer app
echo "==> Compiling and running isolated consumer via noxc run..."
cd "${TMP_DIR}"
OUTPUT="$(noxc run main.nox)"
echo "${OUTPUT}"

if ! echo "${OUTPUT}" | grep -q "Isolated Consumer verification SUCCESS!"; then
    echo "ERROR: Isolated consumer verification output did not contain expected success message!"
    exit 1
fi

echo "==> Isolated consumer integration test PASSED successfully!"
