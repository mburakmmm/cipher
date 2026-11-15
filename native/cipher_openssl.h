#ifndef CIPHER_OPENSSL_H
#define CIPHER_OPENSSL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status & Error Codes */
#define CIPHER_OSSL_OK               0
#define CIPHER_OSSL_VERIFY_VALID     1
#define CIPHER_OSSL_VERIFY_INVALID   0
#define CIPHER_OSSL_ERR_UNAVAILABLE -1
#define CIPHER_OSSL_ERR_UNSUPPORTED -2
#define CIPHER_OSSL_ERR_BAD_INPUT   -3
#define CIPHER_OSSL_ERR_BAD_KEY     -4
#define CIPHER_OSSL_ERR_BUF_SMALL   -5
#define CIPHER_OSSL_ERR_CRYPTO      -6

/* Probe dynamic OpenSSL libcrypto availability (1 = ready, 0 = unavailable). */
int64_t cipher_ossl_is_available(void);

/* HMAC-SHA384 / HMAC-SHA512 / HMAC-SHA256 using hex-encoded symmetric secret.
 * Minimum secret length: 32 bytes for HS256, 48 bytes for HS384, 64 bytes for HS512 (RFC 7518).
 * Writes lowercase hex digest into out_hex; returns CIPHER_OSSL_OK or negative error. */
int64_t cipher_ossl_hmac_hex(const char *alg, const char *key_hex, const char *msg,
                             char *out_hex, int64_t out_cap);

/* Constant-time hex equality check (returns 1 if equal, 0 otherwise). */
int64_t cipher_ossl_const_time_hex_eq(const char *a_hex, const char *b_hex);

/* Ed25519 sign & verify (32-byte seed hex / 32-byte pub hex -> 64-byte sig hex). */
int64_t cipher_ossl_ed25519_sign_hex(const char *priv_seed_hex, const char *msg,
                                     char *out_hex, int64_t out_cap);
int64_t cipher_ossl_ed25519_verify_hex(const char *pub_hex, const char *msg,
                                       const char *sig_hex);

/* RSA RS256 (PKCS#1 v1.5 SHA-256) and PS256 (RSA-PSS SHA-256, MGF1-SHA256, saltlen=32).
 * Enforces minimum 2048-bit modulus unconditionally. */
int64_t cipher_ossl_rsa_verify_jwk_hex(const char *alg, const char *n_hex, const char *e_hex,
                                       const char *msg, const char *sig_hex);
int64_t cipher_ossl_rsa_verify_pem_hex(const char *alg, const char *pem,
                                       const char *msg, const char *sig_hex);
int64_t cipher_ossl_rsa_sign_pem_hex(const char *alg, const char *priv_pem,
                                     const char *msg, char *out_hex, int64_t out_cap);

/* ECDSA P-256 ES256 (SHA-256, JOSE fixed-width 64-byte raw R || S signature). */
int64_t cipher_ossl_es256_verify_jwk_hex(const char *x_hex, const char *y_hex,
                                         const char *msg, const char *sig_hex);
int64_t cipher_ossl_es256_verify_pem_hex(const char *pem, const char *msg,
                                         const char *sig_hex);
int64_t cipher_ossl_es256_sign_pem_hex(const char *priv_pem, const char *msg,
                                       char *out_hex, int64_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* CIPHER_OPENSSL_H */
