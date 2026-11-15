#include "cipher_openssl.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#endif

/* Opaque OpenSSL forward types (ABI-compatible across OpenSSL 1.1, 3.x, 4.x) */
typedef struct ossl_evp_md_st EVP_MD;
typedef struct ossl_evp_md_ctx_st EVP_MD_CTX;
typedef struct ossl_evp_pkey_st EVP_PKEY;
typedef struct ossl_evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct ossl_bio_st BIO;
typedef struct ossl_bignum_st BIGNUM;
typedef struct ossl_ecdsa_sig_st ECDSA_SIG;
typedef struct ossl_engine_st ENGINE;

#define CIPHER_EVP_PKEY_RSA     6
#define CIPHER_EVP_PKEY_EC      408
#define CIPHER_EVP_PKEY_ED25519 1087
#define CIPHER_RSA_PKCS1_PADDING     1
#define CIPHER_RSA_PKCS1_PSS_PADDING 6

typedef struct {
    int initialized;
    int available;
#ifdef _WIN32
    HMODULE lib;
#else
    void *lib;
#endif
    const EVP_MD *(*EVP_sha256)(void);
    const EVP_MD *(*EVP_sha384)(void);
    const EVP_MD *(*EVP_sha512)(void);
    EVP_MD_CTX *(*EVP_MD_CTX_new)(void);
    void (*EVP_MD_CTX_free)(EVP_MD_CTX *);
    int (*EVP_DigestSignInit)(EVP_MD_CTX *, EVP_PKEY_CTX **, const EVP_MD *, ENGINE *, EVP_PKEY *);
    int (*EVP_DigestSign)(EVP_MD_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
    int (*EVP_DigestVerifyInit)(EVP_MD_CTX *, EVP_PKEY_CTX **, const EVP_MD *, ENGINE *, EVP_PKEY *);
    int (*EVP_DigestVerify)(EVP_MD_CTX *, const unsigned char *, size_t, const unsigned char *, size_t);
    void (*EVP_PKEY_free)(EVP_PKEY *);
    int (*EVP_PKEY_get_bits_fn)(const EVP_PKEY *);
    int (*EVP_PKEY_get_id_fn)(const EVP_PKEY *);
    EVP_PKEY *(*EVP_PKEY_new_raw_public_key)(int, ENGINE *, const unsigned char *, size_t);
    EVP_PKEY *(*EVP_PKEY_new_raw_private_key)(int, ENGINE *, const unsigned char *, size_t);
    int (*EVP_PKEY_CTX_set_rsa_padding)(EVP_PKEY_CTX *, int);
    int (*EVP_PKEY_CTX_set_rsa_pss_saltlen)(EVP_PKEY_CTX *, int);
    int (*EVP_PKEY_CTX_set_rsa_mgf1_md)(EVP_PKEY_CTX *, const EVP_MD *);
    BIO *(*BIO_new_mem_buf)(const void *, int);
    int (*BIO_free)(BIO *);
    EVP_PKEY *(*PEM_read_bio_PUBKEY)(BIO *, EVP_PKEY **, void *, void *);
    EVP_PKEY *(*PEM_read_bio_PrivateKey)(BIO *, EVP_PKEY **, void *, void *);
    EVP_PKEY *(*d2i_PUBKEY)(EVP_PKEY **, const unsigned char **, long);
    ECDSA_SIG *(*ECDSA_SIG_new)(void);
    void (*ECDSA_SIG_free)(ECDSA_SIG *);
    int (*ECDSA_SIG_set0)(ECDSA_SIG *, BIGNUM *, BIGNUM *);
    void (*ECDSA_SIG_get0)(const ECDSA_SIG *, const BIGNUM **, const BIGNUM **);
    int (*i2d_ECDSA_SIG)(const ECDSA_SIG *, unsigned char **);
    ECDSA_SIG *(*d2i_ECDSA_SIG)(ECDSA_SIG **, const unsigned char **, long);
    BIGNUM *(*BN_bin2bn)(const unsigned char *, int, BIGNUM *);
    void (*BN_free)(BIGNUM *);
    int (*BN_bn2binpad)(const BIGNUM *, unsigned char *, int);
    unsigned char *(*HMAC)(const EVP_MD *, const void *, int, const unsigned char *, size_t,
                           unsigned char *, unsigned int *);
} CipherOsslApi;

static CipherOsslApi g_ossl = {0};

#ifdef _WIN32
static volatile LONG g_ossl_lock = 0;
#else
static pthread_mutex_t g_ossl_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static void cipher_memzero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static void *cipher_sym(const char *name) {
#ifdef _WIN32
    return (void *)GetProcAddress(g_ossl.lib, name);
#else
    return dlsym(g_ossl.lib, name);
#endif
}

static int cipher_load_once_locked(void) {
    if (g_ossl.initialized) {
        return g_ossl.available;
    }
    g_ossl.initialized = 1;
    g_ossl.available = 0;

#ifdef _WIN32
    const char *candidates[] = {
        "libcrypto-3-x64.dll",
        "libcrypto-3-arm64.dll",
        "libcrypto-3.dll",
        "libcrypto-1_1-x64.dll",
        "libcrypto.dll",
        NULL
    };
    for (int i = 0; candidates[i] != NULL; i++) {
        g_ossl.lib = LoadLibraryA(candidates[i]);
        if (g_ossl.lib != NULL) break;
    }
#elif defined(__APPLE__)
    /* Avoid unversioned /usr/lib/libcrypto.dylib (macOS SIP terminates process with SIGABRT). */
    const char *candidates[] = {
        "/opt/homebrew/opt/openssl@4/lib/libcrypto.dylib",
        "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
        "/opt/homebrew/lib/libcrypto.dylib",
        "/usr/local/opt/openssl@4/lib/libcrypto.dylib",
        "/usr/local/opt/openssl@3/lib/libcrypto.dylib",
        "/usr/local/lib/libcrypto.dylib",
        "/usr/lib/libcrypto.46.dylib",
        "/usr/lib/libcrypto.44.dylib",
        "libcrypto.3.dylib",
        NULL
    };
    for (int i = 0; candidates[i] != NULL; i++) {
        g_ossl.lib = dlopen(candidates[i], RTLD_LAZY | RTLD_LOCAL);
        if (g_ossl.lib != NULL) break;
    }
#else
    const char *candidates[] = {
        "libcrypto.so.3",
        "libcrypto.so.1.1",
        "libcrypto.so",
        NULL
    };
    for (int i = 0; candidates[i] != NULL; i++) {
        g_ossl.lib = dlopen(candidates[i], RTLD_LAZY | RTLD_LOCAL);
        if (g_ossl.lib != NULL) break;
    }
#endif

    if (g_ossl.lib == NULL) {
        return 0;
    }

#define LOAD_REQ(field, sym)                                \
    do {                                                    \
        void *fp = cipher_sym(sym);                         \
        if (!fp) return 0;                                  \
        memcpy(&g_ossl.field, &fp, sizeof(void *));          \
    } while (0)

    LOAD_REQ(EVP_sha256, "EVP_sha256");
    LOAD_REQ(EVP_sha384, "EVP_sha384");
    LOAD_REQ(EVP_sha512, "EVP_sha512");
    LOAD_REQ(EVP_MD_CTX_new, "EVP_MD_CTX_new");
    LOAD_REQ(EVP_MD_CTX_free, "EVP_MD_CTX_free");
    LOAD_REQ(EVP_DigestSignInit, "EVP_DigestSignInit");
    LOAD_REQ(EVP_DigestSign, "EVP_DigestSign");
    LOAD_REQ(EVP_DigestVerifyInit, "EVP_DigestVerifyInit");
    LOAD_REQ(EVP_DigestVerify, "EVP_DigestVerify");
    LOAD_REQ(EVP_PKEY_free, "EVP_PKEY_free");
    LOAD_REQ(EVP_PKEY_new_raw_public_key, "EVP_PKEY_new_raw_public_key");
    LOAD_REQ(EVP_PKEY_new_raw_private_key, "EVP_PKEY_new_raw_private_key");
    LOAD_REQ(EVP_PKEY_CTX_set_rsa_padding, "EVP_PKEY_CTX_set_rsa_padding");
    LOAD_REQ(EVP_PKEY_CTX_set_rsa_pss_saltlen, "EVP_PKEY_CTX_set_rsa_pss_saltlen");
    LOAD_REQ(EVP_PKEY_CTX_set_rsa_mgf1_md, "EVP_PKEY_CTX_set_rsa_mgf1_md");
    LOAD_REQ(BIO_new_mem_buf, "BIO_new_mem_buf");
    LOAD_REQ(BIO_free, "BIO_free");
    LOAD_REQ(PEM_read_bio_PUBKEY, "PEM_read_bio_PUBKEY");
    LOAD_REQ(PEM_read_bio_PrivateKey, "PEM_read_bio_PrivateKey");
    LOAD_REQ(d2i_PUBKEY, "d2i_PUBKEY");
    LOAD_REQ(ECDSA_SIG_new, "ECDSA_SIG_new");
    LOAD_REQ(ECDSA_SIG_free, "ECDSA_SIG_free");
    LOAD_REQ(ECDSA_SIG_set0, "ECDSA_SIG_set0");
    LOAD_REQ(ECDSA_SIG_get0, "ECDSA_SIG_get0");
    LOAD_REQ(i2d_ECDSA_SIG, "i2d_ECDSA_SIG");
    LOAD_REQ(d2i_ECDSA_SIG, "d2i_ECDSA_SIG");
    LOAD_REQ(BN_bin2bn, "BN_bin2bn");
    LOAD_REQ(BN_free, "BN_free");
    LOAD_REQ(BN_bn2binpad, "BN_bn2binpad");
    LOAD_REQ(HMAC, "HMAC");
#undef LOAD_REQ

    void *bits_fp = cipher_sym("EVP_PKEY_get_bits");
    if (!bits_fp) bits_fp = cipher_sym("EVP_PKEY_bits");
    if (!bits_fp) return 0;
    memcpy(&g_ossl.EVP_PKEY_get_bits_fn, &bits_fp, sizeof(void *));

    void *id_fp = cipher_sym("EVP_PKEY_get_id");
    if (!id_fp) id_fp = cipher_sym("EVP_PKEY_id");
    if (!id_fp) return 0;
    memcpy(&g_ossl.EVP_PKEY_get_id_fn, &id_fp, sizeof(void *));

    g_ossl.available = 1;
    return 1;
}

static int cipher_ensure_loaded(void) {
    if (g_ossl.initialized) {
        return g_ossl.available;
    }
#ifdef _WIN32
    while (InterlockedCompareExchange(&g_ossl_lock, 1, 0) != 0) {
        Sleep(0);
    }
    int ok = cipher_load_once_locked();
    InterlockedExchange(&g_ossl_lock, 0);
    return ok;
#else
    pthread_mutex_lock(&g_ossl_mutex);
    int ok = cipher_load_once_locked();
    pthread_mutex_unlock(&g_ossl_mutex);
    return ok;
#endif
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t **out_buf, size_t *out_len) {
    if (!hex) return -1;
    size_t slen = strlen(hex);
    if (slen == 0 || (slen % 2) != 0 || slen > 131072) return -1;
    size_t blen = slen / 2;
    uint8_t *buf = (uint8_t *)malloc(blen);
    if (!buf) return -1;
    for (size_t i = 0; i < blen; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            cipher_memzero(buf, blen);
            free(buf);
            return -1;
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_buf = buf;
    *out_len = blen;
    return 0;
}

static int hex_encode(const uint8_t *buf, size_t len, char *out_hex, int64_t out_cap) {
    static const char digits[] = "0123456789abcdef";
    if (!buf || !out_hex || out_cap <= 0) return CIPHER_OSSL_ERR_BAD_INPUT;
    if ((int64_t)(len * 2 + 1) > out_cap) return CIPHER_OSSL_ERR_BUF_SMALL;
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2] = digits[(buf[i] >> 4) & 0x0f];
        out_hex[i * 2 + 1] = digits[buf[i] & 0x0f];
    }
    out_hex[len * 2] = '\0';
    return CIPHER_OSSL_OK;
}

static size_t der_len_size(size_t len) {
    if (len < 128) return 1;
    if (len < 256) return 2;
    return 3;
}

static size_t der_write_len(uint8_t *p, size_t len) {
    if (len < 128) {
        p[0] = (uint8_t)len;
        return 1;
    }
    if (len < 256) {
        p[0] = 0x81;
        p[1] = (uint8_t)len;
        return 2;
    }
    p[0] = 0x82;
    p[1] = (uint8_t)((len >> 8) & 0xff);
    p[2] = (uint8_t)(len & 0xff);
    return 3;
}

static EVP_PKEY *build_rsa_spki_from_bytes(const uint8_t *n, size_t n_len,
                                           const uint8_t *e, size_t e_len) {
    if (!n || !e || n_len < 256 || n_len > 2048 || e_len == 0 || e_len > 16) return NULL;
    if (n[0] == 0 || e[0] == 0) return NULL;
    if (n_len == 256 && (n[0] & 0x80) == 0) return NULL;

    size_t n_pad = (n[0] & 0x80) ? 1 : 0;
    size_t e_pad = (e[0] & 0x80) ? 1 : 0;
    size_t n_int_body = n_len + n_pad;
    size_t e_int_body = e_len + e_pad;

    size_t rsa_seq_body = 1 + der_len_size(n_int_body) + n_int_body +
                          1 + der_len_size(e_int_body) + e_int_body;
    size_t rsa_seq_total = 1 + der_len_size(rsa_seq_body) + rsa_seq_body;
    size_t bitstr_body = 1 + rsa_seq_total;
    size_t bitstr_total = 1 + der_len_size(bitstr_body) + bitstr_body;

    /* OID rsaEncryption (1.2.840.113549.1.1.1) + NULL = 15 bytes */
    static const uint8_t rsa_alg_id[15] = {
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00
    };
    size_t spki_body = sizeof(rsa_alg_id) + bitstr_total;
    size_t spki_total = 1 + der_len_size(spki_body) + spki_body;

    uint8_t *der = (uint8_t *)malloc(spki_total);
    if (!der) return NULL;
    size_t pos = 0;

    der[pos++] = 0x30;
    pos += der_write_len(der + pos, spki_body);
    memcpy(der + pos, rsa_alg_id, sizeof(rsa_alg_id));
    pos += sizeof(rsa_alg_id);

    der[pos++] = 0x03;
    pos += der_write_len(der + pos, bitstr_body);
    der[pos++] = 0x00;

    der[pos++] = 0x30;
    pos += der_write_len(der + pos, rsa_seq_body);

    der[pos++] = 0x02;
    pos += der_write_len(der + pos, n_int_body);
    if (n_pad) der[pos++] = 0x00;
    memcpy(der + pos, n, n_len);
    pos += n_len;

    der[pos++] = 0x02;
    pos += der_write_len(der + pos, e_int_body);
    if (e_pad) der[pos++] = 0x00;
    memcpy(der + pos, e, e_len);
    pos += e_len;

    const unsigned char *p = der;
    EVP_PKEY *pkey = g_ossl.d2i_PUBKEY(NULL, &p, (long)pos);
    free(der);
    if (!pkey) return NULL;
    if (g_ossl.EVP_PKEY_get_id_fn(pkey) != CIPHER_EVP_PKEY_RSA ||
        g_ossl.EVP_PKEY_get_bits_fn(pkey) < 2048) {
        g_ossl.EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

static EVP_PKEY *build_p256_spki_from_bytes(const uint8_t *x, size_t x_len,
                                            const uint8_t *y, size_t y_len) {
    if (!x || !y || x_len != 32 || y_len != 32) return NULL;
    static const uint8_t p256_prefix[27] = {
        0x30, 0x59,
        0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04
    };
    uint8_t der[91];
    memcpy(der, p256_prefix, 27);
    memcpy(der + 27, x, 32);
    memcpy(der + 59, y, 32);
    const unsigned char *p = der;
    EVP_PKEY *pkey = g_ossl.d2i_PUBKEY(NULL, &p, 91);
    if (!pkey) return NULL;
    if (g_ossl.EVP_PKEY_get_id_fn(pkey) != CIPHER_EVP_PKEY_EC ||
        g_ossl.EVP_PKEY_get_bits_fn(pkey) != 256) {
        g_ossl.EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

static EVP_PKEY *load_pem_pubkey(const char *pem) {
    if (!pem || pem[0] == '\0') return NULL;
    size_t len = strlen(pem);
    if (len > 32768) return NULL;
    BIO *bio = g_ossl.BIO_new_mem_buf(pem, (int)len);
    if (!bio) return NULL;
    EVP_PKEY *pkey = g_ossl.PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    g_ossl.BIO_free(bio);
    return pkey;
}

static EVP_PKEY *load_pem_privkey(const char *pem) {
    if (!pem || pem[0] == '\0') return NULL;
    size_t len = strlen(pem);
    if (len > 32768) return NULL;
    BIO *bio = g_ossl.BIO_new_mem_buf(pem, (int)len);
    if (!bio) return NULL;
    EVP_PKEY *pkey = g_ossl.PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    g_ossl.BIO_free(bio);
    return pkey;
}

static int raw64_to_ecdsa_der(const uint8_t *raw64, uint8_t **der_out, size_t *der_len_out) {
    int r_zero = 1, s_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (raw64[i] != 0) r_zero = 0;
        if (raw64[32 + i] != 0) s_zero = 0;
    }
    if (r_zero || s_zero) return -1;

    BIGNUM *r = g_ossl.BN_bin2bn(raw64, 32, NULL);
    BIGNUM *s = g_ossl.BN_bin2bn(raw64 + 32, 32, NULL);
    if (!r || !s) {
        if (r) g_ossl.BN_free(r);
        if (s) g_ossl.BN_free(s);
        return -1;
    }
    ECDSA_SIG *sig = g_ossl.ECDSA_SIG_new();
    if (!sig) {
        g_ossl.BN_free(r);
        g_ossl.BN_free(s);
        return -1;
    }
    if (g_ossl.ECDSA_SIG_set0(sig, r, s) != 1) {
        g_ossl.ECDSA_SIG_free(sig);
        return -1;
    }
    int len = g_ossl.i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0 || len > 128) {
        g_ossl.ECDSA_SIG_free(sig);
        return -1;
    }
    uint8_t *der = (uint8_t *)malloc((size_t)len);
    if (!der) {
        g_ossl.ECDSA_SIG_free(sig);
        return -1;
    }
    unsigned char *p = der;
    int written = g_ossl.i2d_ECDSA_SIG(sig, &p);
    g_ossl.ECDSA_SIG_free(sig);
    if (written != len) {
        free(der);
        return -1;
    }
    *der_out = der;
    *der_len_out = (size_t)len;
    return 0;
}

static int ecdsa_der_to_raw64(const uint8_t *der, size_t der_len, uint8_t *raw64) {
    const unsigned char *p = der;
    ECDSA_SIG *sig = g_ossl.d2i_ECDSA_SIG(NULL, &p, (long)der_len);
    if (!sig || p != der + der_len) {
        if (sig) g_ossl.ECDSA_SIG_free(sig);
        return -1;
    }
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    g_ossl.ECDSA_SIG_get0(sig, &r, &s);
    int ok = 0;
    if (!r || !s || g_ossl.BN_bn2binpad(r, raw64, 32) != 32 ||
        g_ossl.BN_bn2binpad(s, raw64 + 32, 32) != 32) {
        ok = -1;
    }
    g_ossl.ECDSA_SIG_free(sig);
    return ok;
}

static int64_t rsa_verify_pkey(EVP_PKEY *pkey, const char *alg, const char *msg, const char *sig_hex) {
    if (!pkey || !alg || !msg || !sig_hex) return CIPHER_OSSL_ERR_BAD_INPUT;
    int is_pss = 0;
    if (strcmp(alg, "RS256") == 0) {
        is_pss = 0;
    } else if (strcmp(alg, "PS256") == 0) {
        is_pss = 1;
    } else {
        return CIPHER_OSSL_ERR_UNSUPPORTED;
    }

    if (g_ossl.EVP_PKEY_get_id_fn(pkey) != CIPHER_EVP_PKEY_RSA) return CIPHER_OSSL_ERR_BAD_KEY;
    int bits = g_ossl.EVP_PKEY_get_bits_fn(pkey);
    if (bits < 2048) return CIPHER_OSSL_ERR_BAD_KEY;

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (hex_decode(sig_hex, &sig, &sig_len) != 0) {
        return CIPHER_OSSL_ERR_BAD_INPUT;
    }
    if (sig_len != (size_t)((bits + 7) / 8)) {
        free(sig);
        return CIPHER_OSSL_VERIFY_INVALID;
    }

    EVP_MD_CTX *mctx = g_ossl.EVP_MD_CTX_new();
    if (!mctx) {
        free(sig);
        return CIPHER_OSSL_ERR_CRYPTO;
    }
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = g_ossl.EVP_sha256();
    int rc = g_ossl.EVP_DigestVerifyInit(mctx, &pctx, md, NULL, pkey);
    if (rc == 1 && pctx) {
        if (is_pss) {
            if (g_ossl.EVP_PKEY_CTX_set_rsa_padding(pctx, CIPHER_RSA_PKCS1_PSS_PADDING) <= 0 ||
                g_ossl.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) <= 0 ||
                g_ossl.EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0) {
                rc = -1;
            }
        } else {
            if (g_ossl.EVP_PKEY_CTX_set_rsa_padding(pctx, CIPHER_RSA_PKCS1_PADDING) <= 0) {
                rc = -1;
            }
        }
    }
    int verified = 0;
    if (rc == 1) {
        int v = g_ossl.EVP_DigestVerify(mctx, sig, sig_len, (const unsigned char *)msg, strlen(msg));
        verified = (v == 1) ? CIPHER_OSSL_VERIFY_VALID : CIPHER_OSSL_VERIFY_INVALID;
    } else {
        verified = CIPHER_OSSL_ERR_CRYPTO;
    }

    g_ossl.EVP_MD_CTX_free(mctx);
    free(sig);
    return verified;
}

int64_t cipher_ossl_is_available(void) {
    return cipher_ensure_loaded() ? 1 : 0;
}

int64_t cipher_ossl_const_time_hex_eq(const char *a_hex, const char *b_hex) {
    if (!a_hex || !b_hex) return 0;
    size_t la = strlen(a_hex);
    size_t lb = strlen(b_hex);
    if (la != lb) return 0;
    uint8_t diff = 0;
    for (size_t i = 0; i < la; i++) {
        diff |= (uint8_t)(a_hex[i] ^ b_hex[i]);
    }
    return diff == 0 ? 1 : 0;
}

int64_t cipher_ossl_hmac_hex(const char *alg, const char *key_hex, const char *msg,
                             char *out_hex, int64_t out_cap) {
    if (!cipher_ensure_loaded()) return CIPHER_OSSL_ERR_UNAVAILABLE;
    if (!alg || !key_hex || !msg || !out_hex) return CIPHER_OSSL_ERR_BAD_INPUT;

    const EVP_MD *md = NULL;
    size_t min_key = 0;
    if (strcmp(alg, "HS256") == 0) {
        md = g_ossl.EVP_sha256();
        min_key = 32;
    } else if (strcmp(alg, "HS384") == 0) {
        md = g_ossl.EVP_sha384();
        min_key = 48;
    } else if (strcmp(alg, "HS512") == 0) {
        md = g_ossl.EVP_sha512();
        min_key = 64;
    } else {
        return CIPHER_OSSL_ERR_UNSUPPORTED;
    }

    uint8_t *key_bytes = NULL;
    size_t key_len = 0;
    if (hex_decode(key_hex, &key_bytes, &key_len) != 0) return CIPHER_OSSL_ERR_BAD_KEY;
    if (key_len < min_key) {
        cipher_memzero(key_bytes, key_len);
        free(key_bytes);
        return CIPHER_OSSL_ERR_BAD_KEY;
    }

    uint8_t mac[64];
    unsigned int mac_len = 0;
    unsigned char *res = g_ossl.HMAC(md, key_bytes, (int)key_len,
                                     (const unsigned char *)msg, strlen(msg),
                                     mac, &mac_len);
    cipher_memzero(key_bytes, key_len);
    free(key_bytes);

    if (!res || mac_len == 0) {
        cipher_memzero(mac, sizeof(mac));
        return CIPHER_OSSL_ERR_CRYPTO;
    }
    int64_t status = hex_encode(mac, mac_len, out_hex, out_cap);
    cipher_memzero(mac, sizeof(mac));
    return status;
}

int64_t cipher_ossl_ed25519_sign_hex(const char *priv_seed_hex, const char *msg,
                                     char *out_hex, int64_t out_cap) {
    if (!cipher_ensure_loaded()) return CIPHER_OSSL_ERR_UNAVAILABLE;
    if (!priv_seed_hex || !msg || !out_hex) return CIPHER_OSSL_ERR_BAD_INPUT;

    uint8_t *seed = NULL;
    size_t seed_len = 0;
    if (hex_decode(priv_seed_hex, &seed, &seed_len) != 0) return CIPHER_OSSL_ERR_BAD_KEY;
    if (seed_len != 32) {
        cipher_memzero(seed, seed_len);
        free(seed);
        return CIPHER_OSSL_ERR_BAD_KEY;
    }

    EVP_PKEY *pkey = g_ossl.EVP_PKEY_new_raw_private_key(CIPHER_EVP_PKEY_ED25519, NULL, seed, 32);
    cipher_memzero(seed, seed_len);
    free(seed);
    if (!pkey) return CIPHER_OSSL_ERR_CRYPTO;

    EVP_MD_CTX *mctx = g_ossl.EVP_MD_CTX_new();
    if (!mctx) {
        g_ossl.EVP_PKEY_free(pkey);
        return CIPHER_OSSL_ERR_CRYPTO;
    }
    uint8_t sig[64];
    size_t sig_len = sizeof(sig);
    int64_t status = CIPHER_OSSL_ERR_CRYPTO;
    if (g_ossl.EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) == 1 &&
        g_ossl.EVP_DigestSign(mctx, sig, &sig_len, (const unsigned char *)msg, strlen(msg)) == 1 &&
        sig_len == 64) {
        status = hex_encode(sig, sig_len, out_hex, out_cap);
    }
    g_ossl.EVP_MD_CTX_free(mctx);
    g_ossl.EVP_PKEY_free(pkey);
    return status;
}

int64_t cipher_ossl_ed25519_verify_hex(const char *pub_hex, const char *msg,
                                       const char *sig_hex) {
    if (!cipher_ensure_loaded()) return CIPHER_OSSL_ERR_UNAVAILABLE;
    if (!pub_hex || !msg || !sig_hex) return CIPHER_OSSL_ERR_BAD_INPUT;

    uint8_t *pub = NULL;
    size_t pub_len = 0;
    if (hex_decode(pub_hex, &pub, &pub_len) != 0 || pub_len != 32) {
        if (pub) free(pub);
        return CIPHER_OSSL_ERR_BAD_KEY;
    }
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (hex_decode(sig_hex, &sig, &sig_len) != 0) {
        free(pub);
        return CIPHER_OSSL_ERR_BAD_INPUT;
    }
    if (sig_len != 64) {
        free(pub);
        free(sig);
        return CIPHER_OSSL_VERIFY_INVALID;
    }

    EVP_PKEY *pkey = g_ossl.EVP_PKEY_new_raw_public_key(CIPHER_EVP_PKEY_ED25519, NULL, pub, 32);
    free(pub);
    if (!pkey) {
        free(sig);
        return CIPHER_OSSL_ERR_BAD_KEY;
    }
    EVP_MD_CTX *mctx = g_ossl.EVP_MD_CTX_new();
    if (!mctx) {
        g_ossl.EVP_PKEY_free(pkey);
        free(sig);
        return CIPHER_OSSL_ERR_CRYPTO;
    }
    int64_t res = CIPHER_OSSL_VERIFY_INVALID;
    if (g_ossl.EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pkey) == 1) {
        int v = g_ossl.EVP_DigestVerify(mctx, sig, 64, (const unsigned char *)msg, strlen(msg));
        res = (v == 1) ? CIPHER_OSSL_VERIFY_VALID : CIPHER_OSSL_VERIFY_INVALID;
    }
    g_ossl.EVP_MD_CTX_free(mctx);
    g_ossl.EVP_PKEY_free(pkey);
    free(sig);
    return res;
}

int64_t cipher_ossl_rsa_verify_jwk_hex(const char *alg, const char *n_hex, const char *e_hex,
                                       const char *msg, const char *sig_hex) {
    if (!cipher_ensure_loaded()) return CIPHER_OSSL_ERR_UNAVAILABLE;
    if (!alg || !n_hex || !e_hex || !msg || !sig_hex) return CIPHER_OSSL_ERR_BAD_INPUT;

    uint8_t *n = NULL, *e = NULL;
    size_t n_len = 0, e_len = 0;
    if (hex_decode(n_hex, &n, &n_len) != 0 || hex_decode(e_hex, &e, &e_len) != 0) {
        if (n) free(n);
        if (e) free(e);
        return CIPHER_OSSL_ERR_BAD_KEY;
    }
    EVP_PKEY *pkey = build_rsa_spki_from_bytes(n, n_len, e, e_len);
    free(n);
    free(e);
    if (!pkey) return CIPHER_OSSL_ERR_BAD_KEY;

    int64_t rc = rsa_verify_pkey(pkey, alg, msg, sig_hex);
    g_ossl.EVP_PKEY_free(pkey);
    return rc;
}

int64_t cipher_ossl_rsa_verify_pem_hex(const char *alg, const char *pem,
                                       const char *msg, const char *sig_hex) {
    if (!cipher_ensure_loaded()) return CIPHER_OSSL_ERR_UNAVAILABLE;
    EVP_PKEY *pkey = load_pem_pubkey(pem);
    if (!pkey) return CIPHER_OSSL_ERR_BAD_KEY;
    int64_t rc = rsa_verify_pkey(pkey, alg, msg, sig_hex);
    g_ossl.EVP_PKEY_free(pkey);
    return rc;
}

int64_t cipher_ossl_rsa_sign_pem_hex(const char *alg, const char *priv_pem,
                                     const char *msg, char *out_hex, int64_t out_cap) {
    if (!cipher_ensure_loaded()) return CIPHER_OSSL_ERR_UNAVAILABLE;
    if (!alg || !priv_pem || !msg || !out_hex) return CIPHER_OSSL_ERR_BAD_INPUT;
    int is_pss = 0;
    if (strcmp(alg, "RS256") == 0) {
        is_pss = 0;
    } else if (strcmp(alg, "PS256") == 0) {
        is_pss = 1;
    } else {
        return CIPHER_OSSL_ERR_UNSUPPORTED;
    }

    EVP_PKEY *pkey = load_pem_privkey(priv_pem);
    if (!pkey) return CIPHER_OSSL_ERR_BAD_KEY;
    if (g_ossl.EVP_PKEY_get_id_fn(pkey) != CIPHER_EVP_PKEY_RSA ||
        g_ossl.EVP_PKEY_get_bits_fn(pkey) < 2048) {
        g_ossl.EVP_PKEY_free(pkey);
        return CIPHER_OSSL_ERR_BAD_KEY;
    }

    EVP_MD_CTX *mctx = g_ossl.EVP_MD_CTX_new();
    if (!mctx) {
        g_ossl.EVP_PKEY_free(pkey);
        return CIPHER_OSSL_ERR_CRYPTO;
    }
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = g_ossl.EVP_sha256();
    int rc = g_ossl.EVP_DigestSignInit(mctx, &pctx, md, NULL, pkey);
    if (rc == 1 && pctx) {
        if (is_pss) {
            if (g_ossl.EVP_PKEY_CTX_set_rsa_padding(pctx, CIPHER_RSA_PKCS1_PSS_PADDING) <= 0 ||
                g_ossl.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) <= 0 ||
                g_ossl.EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0) {
                rc = -1;
            }
        } else {
            if (g_ossl.EVP_PKEY_CTX_set_rsa_padding(pctx, CIPHER_RSA_PKCS1_PADDING) <= 0) {
                rc = -1;
            }
        }
    }

    int64_t status = CIPHER_OSSL_ERR_CRYPTO;
    size_t sig_len = 0;
    if (rc == 1 && g_ossl.EVP_DigestSign(mctx, NULL, &sig_len, (const unsigned char *)msg, strlen(msg)) == 1 &&
        sig_len > 0 && sig_len <= 2048) {
        uint8_t *sig = (uint8_t *)malloc(sig_len);
        if (sig) {
            if (g_ossl.EVP_DigestSign(mctx, sig, &sig_len, (const unsigned char *)msg, strlen(msg)) == 1) {
                status = hex_encode(sig, sig_len, out_hex, out_cap);
            }
            cipher_memzero(sig, sig_len);
            free(sig);
        }
    }
    g_ossl.EVP_MD_CTX_free(mctx);
    g_ossl.EVP_PKEY_free(pkey);
    return status;
}

static int64_t es256_verify_pkey(EVP_PKEY *pkey, const char *msg, const char *sig_hex) {
    if (!pkey || !msg || !sig_hex) return CIPHER_OSSL_ERR_BAD_INPUT;
    if (g_ossl.EVP_PKEY_get_id_fn(pkey) != CIPHER_EVP_PKEY_EC ||
        g_ossl.EVP_PKEY_get_bits_fn(pkey) != 256) {
        return CIPHER_OSSL_ERR_BAD_KEY;
    }
    uint8_t *raw64 = NULL;
    size_t raw_len = 0;
    if (hex_decode(sig_hex, &raw64, &raw_len) != 0) {
        return CIPHER_OSSL_ERR_BAD_INPUT;
    }
    if (raw_len != 64) {
        free(raw64);
        return CIPHER_OSSL_VERIFY_INVALID;
    }
    uint8_t *der = NULL;
    size_t der_len = 0;
    if (raw64_to_ecdsa_der(raw64, &der, &der_len) != 0) {
        free(raw64);
        return CIPHER_OSSL_VERIFY_INVALID;
    }
    free(raw64);

    EVP_MD_CTX *mctx = g_ossl.EVP_MD_CTX_new();
    if (!mctx) {
        free(der);
        return CIPHER_OSSL_ERR_CRYPTO;
    }
    int64_t res = CIPHER_OSSL_VERIFY_INVALID;
    if (g_ossl.EVP_DigestVerifyInit(mctx, NULL, g_ossl.EVP_sha256(), NULL, pkey) == 1) {
        int v = g_ossl.EVP_DigestVerify(mctx, der, der_len, (const unsigned char *)msg, strlen(msg));
        res = (v == 1) ? CIPHER_OSSL_VERIFY_VALID : CIPHER_OSSL_VERIFY_INVALID;
    }
    g_ossl.EVP_MD_CTX_free(mctx);
    free(der);
    return res;
}

int64_t cipher_ossl_es256_verify_jwk_hex(const char *x_hex, const char *y_hex,
                                         const char *msg, const char *sig_hex) {
    if (!cipher_ensure_loaded()) return CIPHER_OSSL_ERR_UNAVAILABLE;
    if (!x_hex || !y_hex || !msg || !sig_hex) return CIPHER_OSSL_ERR_BAD_INPUT;

    uint8_t *x = NULL, *y = NULL;
    size_t x_len = 0, y_len = 0;
    if (hex_decode(x_hex, &x, &x_len) != 0 || hex_decode(y_hex, &y, &y_len) != 0) {
        if (x) free(x);
        if (y) free(y);
        return CIPHER_OSSL_ERR_BAD_KEY;
    }
    EVP_PKEY *pkey = build_p256_spki_from_bytes(x, x_len, y, y_len);
    free(x);
    free(y);
    if (!pkey) return CIPHER_OSSL_ERR_BAD_KEY;

    int64_t rc = es256_verify_pkey(pkey, msg, sig_hex);
    g_ossl.EVP_PKEY_free(pkey);
    return rc;
}

int64_t cipher_ossl_es256_verify_pem_hex(const char *pem, const char *msg,
                                         const char *sig_hex) {
    if (!cipher_ensure_loaded()) return CIPHER_OSSL_ERR_UNAVAILABLE;
    EVP_PKEY *pkey = load_pem_pubkey(pem);
    if (!pkey) return CIPHER_OSSL_ERR_BAD_KEY;
    int64_t rc = es256_verify_pkey(pkey, msg, sig_hex);
    g_ossl.EVP_PKEY_free(pkey);
    return rc;
}

int64_t cipher_ossl_es256_sign_pem_hex(const char *priv_pem, const char *msg,
                                       char *out_hex, int64_t out_cap) {
    if (!cipher_ensure_loaded()) return CIPHER_OSSL_ERR_UNAVAILABLE;
    if (!priv_pem || !msg || !out_hex) return CIPHER_OSSL_ERR_BAD_INPUT;

    EVP_PKEY *pkey = load_pem_privkey(priv_pem);
    if (!pkey) return CIPHER_OSSL_ERR_BAD_KEY;
    if (g_ossl.EVP_PKEY_get_id_fn(pkey) != CIPHER_EVP_PKEY_EC ||
        g_ossl.EVP_PKEY_get_bits_fn(pkey) != 256) {
        g_ossl.EVP_PKEY_free(pkey);
        return CIPHER_OSSL_ERR_BAD_KEY;
    }

    EVP_MD_CTX *mctx = g_ossl.EVP_MD_CTX_new();
    if (!mctx) {
        g_ossl.EVP_PKEY_free(pkey);
        return CIPHER_OSSL_ERR_CRYPTO;
    }
    int64_t status = CIPHER_OSSL_ERR_CRYPTO;
    size_t der_len = 0;
    if (g_ossl.EVP_DigestSignInit(mctx, NULL, g_ossl.EVP_sha256(), NULL, pkey) == 1 &&
        g_ossl.EVP_DigestSign(mctx, NULL, &der_len, (const unsigned char *)msg, strlen(msg)) == 1 &&
        der_len > 0 && der_len <= 160) {
        uint8_t *der = (uint8_t *)malloc(der_len);
        if (der) {
            if (g_ossl.EVP_DigestSign(mctx, der, &der_len, (const unsigned char *)msg, strlen(msg)) == 1) {
                uint8_t raw64[64];
                if (ecdsa_der_to_raw64(der, der_len, raw64) == 0) {
                    status = hex_encode(raw64, 64, out_hex, out_cap);
                    cipher_memzero(raw64, sizeof(raw64));
                }
            }
            cipher_memzero(der, der_len);
            free(der);
        }
    }
    g_ossl.EVP_MD_CTX_free(mctx);
    g_ossl.EVP_PKEY_free(pkey);
    return status;
}
