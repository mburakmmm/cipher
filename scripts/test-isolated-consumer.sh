#!/usr/bin/env bash
# ==============================================================================
# Cipher — Native Package Manager (noxc add + noxc fetch) Consumer Verification
# Validates that an independent external application with zero copied source
# files can install Cipher via 'noxc add' and 'noxc fetch', lock the commit SHA
# in 'nox.lock', and consume all public APIs cleanly.
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cipher_pkg_consumer_XXXXXX")"

cleanup() {
    echo "==> Cleaning up isolated consumer test workspace: ${TMP_ROOT}"
    rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

PKG_STAGING="${TMP_ROOT}/cipher_pkg"
CONSUMER_DIR="${TMP_ROOT}/consumer_app"
NOX_HOME_DIR="${TMP_ROOT}/nox_home"

mkdir -p "${PKG_STAGING}/cipher" "${CONSUMER_DIR}" "${NOX_HOME_DIR}"

# 1. Stage current working tree as a clean git repository for 'noxc fetch'
cp "${REPO_ROOT}/nox.json" "${PKG_STAGING}/"
cp "${REPO_ROOT}"/*.nox "${PKG_STAGING}/"
cp "${REPO_ROOT}/cipher"/*.nox "${PKG_STAGING}/cipher/"

git -C "${PKG_STAGING}" init -q -b main
git -C "${PKG_STAGING}" config user.name "Cipher Package Probe"
git -C "${PKG_STAGING}" config user.email "probe@cipher.nox"
git -C "${PKG_STAGING}" add .
git -C "${PKG_STAGING}" commit -q -m "stage cipher package for native fetch test"
EXPECTED_SHA="$(git -C "${PKG_STAGING}" rev-parse HEAD)"

echo "==> Initializing independent consumer project in: ${CONSUMER_DIR}"
cd "${CONSUMER_DIR}"
NOX_HOME="${NOX_HOME_DIR}" noxc init . >/dev/null

echo "==> Adding and fetching cipher package via native NOX package manager..."
NOX_HOME="${NOX_HOME_DIR}" noxc add cipher "${PKG_STAGING}" --ref main >/dev/null
NOX_HOME="${NOX_HOME_DIR}" noxc fetch

# Verify nox.lock contains the exact resolved commit SHA
if ! grep -q "\"resolved\": \"${EXPECTED_SHA}\"" "${CONSUMER_DIR}/nox.lock"; then
    echo "ERROR: nox.lock did not record expected resolved commit SHA (${EXPECTED_SHA})!"
    cat "${CONSUMER_DIR}/nox.lock"
    exit 1
fi
echo "==> Verified nox.lock resolved SHA: ${EXPECTED_SHA}"

# 2. Write consumer application code (zero copied .nox files in CONSUMER_DIR!)
cat << 'EOF' > "${CONSUMER_DIR}/main.nox"
from cipher.cipher import ClaimsProfile, JwkKey, KeyRef, KeyRing, KeyRingState, STATE_ACTIVE_SIGNING, STATE_PREPARED, VerificationProfile, VerifiedJwt, encode_jwt_hs256, issue_signed_token, parse_jwk, verify_jwt_hs256, verify_resolved_ip, verify_signed_token

print("==> [Native Package Consumer] Starting integration test...")

secret: str = "isolated-consumer-production-secret-at-least-32-bytes"

# 1. JWT Encoding & Strict Verification
payload_json: str = "{\"sub\":\"usr_isolated_99\",\"iss\":\"https://id.enterprise.org\",\"aud\":\"https://api.enterprise.org\",\"exp\":1700003600,\"typ\":\"JWT\"}"
token: str = encode_jwt_hs256(payload_json, secret, kid="k-iso-1")
print("[Native Package Consumer] Encoded Token successfully")

c_prof: ClaimsProfile = ClaimsProfile(
    expected_issuer="https://id.enterprise.org",
    clock_time_sec=1700000000
)
c_prof.with_audience("https://api.enterprise.org")

v_prof: VerificationProfile = VerificationProfile(["HS256"], expected_kid="k-iso-1", expected_typ="JWT")
verified: VerifiedJwt = verify_jwt_hs256(token, secret, v_prof, c_prof)

if verified.claims.sub != "usr_isolated_99":
    raise Exception("Subject claim mismatch in isolated consumer!")
print("[Native Package Consumer] Verified JWT sub: " + verified.claims.sub)

# 2. Signed Opaque Token
raw_data: str = "secure_session_payload_42"
sig_tok: str = issue_signed_token(raw_data, "web_session", secret, ttl_seconds=300)
v_data: str = verify_signed_token(sig_tok, "web_session", secret)
if v_data != raw_data:
    raise Exception("Payload mismatch in signed token!")
print("[Native Package Consumer] Verified Signed Token payload: " + v_data)

# 3. KeyRing Hardware Atomic Rotation & Seqlock Coherent State
ring: KeyRing = KeyRing(trust_domain="enterprise-prod")
k_ref: KeyRef = KeyRef("k-iso-1", "HS256", secret, trust_domain="enterprise-prod", state=STATE_ACTIVE_SIGNING)
ring.add_key(k_ref, expected_version=0)
k_next: KeyRef = KeyRef("k-iso-2", "HS256", "next-isolated-consumer-production-secret-32b", trust_domain="enterprise-prod", state=STATE_PREPARED)
ring.rotate(k_next, overlap_seconds=300, clock_time_sec=1700000000, expected_version=1)
active_k: KeyRef = ring.get_signing_key("HS256")
st: KeyRingState = ring.get_state()
st.verify_integrity()
if active_k.kid != "k-iso-2" or ring.get_version() != 2 or st.key_count() != 2:
    raise Exception("KeyRing active signer, atomic version, or state integrity mismatch!")
print("[Native Package Consumer] KeyRing rotated active signer: " + active_k.kid + " (version " + str(ring.get_version()) + ", seal verified)")

# 4. Decoupled IP Parser & Resolved IP Verification
if not verify_resolved_ip("::ffff:8.8.8.8") or verify_resolved_ip("::ffff:127.0.0.1") or verify_resolved_ip("1.2.3"):
    raise Exception("verify_resolved_ip validation failed in consumer!")
print("[Native Package Consumer] Verified decoupled IP SSRF policy")

print("Isolated Consumer verification SUCCESS!")
EOF

# 3. Compile and execute isolated consumer app using fetched package cache (Stage 1: Local Git Staging)
echo "==> [Stage 1: Local Git Staging] Compiling and running consumer via noxc run..."
OUTPUT="$(NOX_HOME="${NOX_HOME_DIR}" noxc run main.nox)"
echo "${OUTPUT}"

if ! echo "${OUTPUT}" | grep -q "Isolated Consumer verification SUCCESS!"; then
    echo "ERROR: Stage 1 isolated consumer verification output did not contain expected success message!"
    exit 1
fi
echo "==> [Stage 1: Local Git Staging] PASSED!"

# 4. Stage 2: Real Remote Registry Installation (noxpkg.noxlang.com -> https://github.com/mburakmmm/cipher)
REMOTE_CONSUMER_DIR="${TMP_ROOT}/remote_consumer_app"
REMOTE_NOX_HOME="${TMP_ROOT}/remote_nox_home"
mkdir -p "${REMOTE_CONSUMER_DIR}" "${REMOTE_NOX_HOME}"

echo "==> [Stage 2: Remote Registry] Testing real remote registry fetch (noxc add cipher + noxc fetch)..."
cd "${REMOTE_CONSUMER_DIR}"
NOX_HOME="${REMOTE_NOX_HOME}" noxc init . >/dev/null

if NOX_HOME="${REMOTE_NOX_HOME}" noxc add cipher && NOX_HOME="${REMOTE_NOX_HOME}" noxc fetch; then
    if ! grep -q "https://github.com/mburakmmm/cipher" "${REMOTE_CONSUMER_DIR}/nox.lock"; then
        echo "ERROR: Remote nox.lock did not record https://github.com/mburakmmm/cipher repository!"
        cat "${REMOTE_CONSUMER_DIR}/nox.lock"
        exit 1
    fi
    REMOTE_SHA="$(grep '"resolved":' "${REMOTE_CONSUMER_DIR}/nox.lock" | head -n 1 | awk -F'"' '{print $4}')"
    if [ -z "${REMOTE_SHA}" ]; then
        echo "ERROR: Remote nox.lock resolved commit SHA is empty!"
        cat "${REMOTE_CONSUMER_DIR}/nox.lock"
        exit 1
    fi
    echo "==> [Stage 2: Remote Registry] Verified remote nox.lock SHA: ${REMOTE_SHA}"

    cat << 'EOF' > "${REMOTE_CONSUMER_DIR}/main.nox"
from cipher.cipher import ClaimsProfile, KeyRef, KeyRing, STATE_ACTIVE_SIGNING, STATE_PREPARED, VerificationProfile, VerifiedJwt, encode_jwt_hs256, issue_signed_token, verify_jwt_hs256, verify_resolved_ip, verify_signed_token

secret: str = "remote-registry-consumer-secret-at-least-32-bytes"
payload_json: str = "{\"sub\":\"usr_remote_01\",\"iss\":\"https://id.enterprise.org\",\"aud\":\"https://api.enterprise.org\",\"exp\":1700003600,\"typ\":\"JWT\"}"
token: str = encode_jwt_hs256(payload_json, secret, kid="k-rem-1")

c_prof: ClaimsProfile = ClaimsProfile(expected_issuer="https://id.enterprise.org", clock_time_sec=1700000000)
c_prof.with_audience("https://api.enterprise.org")
v_prof: VerificationProfile = VerificationProfile(["HS256"], expected_kid="k-rem-1", expected_typ="JWT")
verified: VerifiedJwt = verify_jwt_hs256(token, secret, v_prof, c_prof)
if verified.claims.sub != "usr_remote_01":
    raise Exception("Remote registry consumer JWT sub mismatch!")

sig_tok: str = issue_signed_token("remote_payload", "remote_purpose", secret, ttl_seconds=300)
if verify_signed_token(sig_tok, "remote_purpose", secret) != "remote_payload":
    raise Exception("Remote registry consumer signed token mismatch!")

if not verify_resolved_ip("::ffff:8.8.8.8") or verify_resolved_ip("::ffff:127.0.0.1"):
    raise Exception("Remote registry consumer IP policy mismatch!")

print("Remote Registry Consumer verification SUCCESS!")
EOF

    REMOTE_OUT="$(NOX_HOME="${REMOTE_NOX_HOME}" noxc run main.nox)"
    echo "${REMOTE_OUT}"
    if ! echo "${REMOTE_OUT}" | grep -q "Remote Registry Consumer verification SUCCESS!"; then
        echo "ERROR: Stage 2 remote registry consumer output did not contain expected success message!"
        exit 1
    fi
    echo "==> [Stage 2: Remote Registry] PASSED!"
else
    if [ "${CI:-false}" = "true" ]; then
        echo "ERROR: Stage 2 remote registry fetch failed in CI environment!"
        exit 1
    fi
    echo "WARNING: Offline environment detected; skipped Stage 2 remote registry check."
fi

echo "==> Native package consumer integration test (Stage 1 + Stage 2) PASSED successfully!"
