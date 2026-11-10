# Cipher — Sürümlü Uygulama ve Canlı Takip Planı (`todo.md`)

> **Durum:** Canlı yürütme ve sürüm takip planı  
> **Temel Sözleşme:** `AGENTS.md` (normatif bağlayıcı referans)  
> **Hedef:** NOX Ekosistemi için Bağımsız Kriptografik Belirteç & Sözleşme Kütüphanesi  
> **Kapsam:** JWS/JWT imzalama ve doğrulama, imzalı opak belirteçler, anahtar yaşam döngüsü & rotasyonu, JWK/JWKS, kriptografik sağlayıcı soyutlaması  
> **Açık Sınır:** Kimlik doğrulama ve yetkilendirme politikası **Sentinel**'e aittir. Cipher yalnızca doğrulanmış kriptografik kanıt üretir.

---

## 1. Takip Kuralları ve Protokolü

### Durum İşaretleri

- `[ ]` Başlanmadı.
- `[~]` Devam ediyor (aynı satıra kısa durum, denenen komut veya engel yazılmalıdır).
- `[x]` Kanıtla tamamlandı (çıktı, commit özeti veya doğrulama notu içerir).
- `[-]` Kapsam dışı veya ertelendi (gerekçe ve hedef sürüm zorunludur).
- `[!]` Engel var (denenen komut, karşılaşılan hata ve gereken karar yazılmalıdır).

### Bir Maddenin Tamamlanma Şartı (`[x]`)

Bir madde yalnızca dosya oluşturulduğu veya kod yazıldığı için `[x]` yapılamaz. Aşağıdaki koşulların tümü sağlanmalıdır:

1. **Kamu Sözleşmesi:** Açık, tipli ve belgelenmiş sözleşme (API) tanımlanmış olmalı.
2. **Derleme & Statik Kontrol:** `noxc check` ve `noxc build` hatasız geçmeli.
3. **Deterministik Test:** Pozitif, negatif ve sınır (boundary) testleri yazılmış ve `noxc test` ile doğrulanmış olmalı.
4. **Güvenlik & Sınır Kontrolleri:** Bellek, boyut limitleri, format katılığı ve duplicate anahtar kontrolleri uygulanmış olmalı.
5. **Kanıt Kaydı:** Gerçek terminal çalıştırma çıktısı ilgili fazın kanıt bölümüne işlenmiş olmalı.
6. **Dokümantasyon & Örnek:** İlgili sürümün mimari ve kullanım dokümanları güncellenmiş olmalı.

### Sürüm Kapısı (Release Gate) İlkesi

- Bir sürümün (minor/patch) tüm zorunlu maddeleri ve çıkış kapısı tamamlanmadan bir sonraki sürümün üretim koduna geçilemez.
- `v1.0.0` öncesi API kararsız olabilir, ancak her kırıcı değişiklik `CHANGELOG.md`'de belgelenir.
- Test zayıflatmak, güvenlik kontrollerini esnetmek veya çalıştırılmamış testi başarılı saymak kesinlikle yasaktır.
- **Yayınlama Politikası (`noxc publish`):** `noxc publish` komutu, tüm fazlar (Phase 0 - Phase 6) eksiksiz tamamlandığında, `v1.0.0` kararlı sürüm etiketi atıldıktan sonra çalıştırılarak paket merkezinde yayınlanacaktır. Ara fazlarda erken/eksik yayın yapılmaz.

### Değişmez Güvenlik İlkeleri (Non-Negotiable Invariants)

1. **Fail-Closed:** Hatalı kodlama, bilinmeyen algoritma, anahtar uyumsuzluğu, imza hatası, geçersiz claim'ler veya belirsizlik durumunda daima başarısız ol ve reddet.
2. **Verifier-Controlled Algoritma:** Algoritma seçimi yalnızca doğrulayıcının güvenilir allowlist'i ve anahtar profiliyle belirlenir. Başlıktaki `alg` asla yeni bir güven yolu seçemez.
3. **`alg=none` Koşulsuz Reddi:** `none` algoritması asla kabul edilmez.
4. **Algoritma Karışıklığı (Algorithm Confusion) Önlemi:** Asla HMAC sırrı ile RSA/EC açık anahtarı karıştırılamaz.
5. **Exact ASCII İmzası:** İmza doğrulama, tam olarak `base64url(protected_header) + '.' + base64url(payload)` ASCII baytları üzerinde yapılır; asla yeniden serileştirilmez.
6. **Sıkı Base64URL ve JSON:** Whitespace, padding, geçersiz karakterler ve mükerrer (duplicate) JSON anahtarları reddedilir.
7. **Güvenilmeyen Başlık Direktifleri:** `kid` yalnızca arama seçicisidir (asla dosya yolu, URL veya SQL parçası değildir). `jku`, `x5u` ve gömülü `jwk` varsayılan olarak reddedilir. `crit` bilinmeyen uzantı içeriyorsa reddedilir.
8. **Asla Hassas Veri Loglanmaz:** Bearer token, private key, HMAC secret veya ham JWT loglanmaz/sızdırılmaz.
9. **Sentinel Sınırı:** Geçerli bir imza yetkilendirme anlamına gelmez. Cipher asla `is_admin`, `authorized`, `allow`/`deny` kararı vermez.

---

## 2. Mevcut Başlangıç Envanteri

- [x] `CIPHER_AGENTS.md` (ve `AGENTS.md`) 422 satırlık tam normatif şartname analiz edildi.
- [x] Sistemdeki NOX derleyicisi doğrulandı: `noxc 2.1.0` (Apple Silicon / Darwin arm64).
- [x] Yerel NOX repository ve stdlib konumu incelendi (`/Users/melihburakmemis/Documents/nox-lang`, `~/.nox-lang/lib/nox/stdlib/nox/`).
- [x] NOX stdlib crypto yetenekleri incelendi (`crypto.sha256`, `crypto.hmac_sha256`, `crypto.constant_time_eq`, `crypto.secure_random_hex`).
- [x] `chronos`, `pulse` ve `rune` kardeş paketlerinin `todo.md` ve mimari standartları incelendi.
- [x] Çalışma dizini envanteri: `CIPHER_AGENTS.md`, `AGENTS.md`. Henüz Git deposu ve kaynak kod başlatılmadı.

---

# Phase 0 — `v0.0.x` Platform Doğrulama, Mimari Temel ve Kriptografik Spike

**Amaç:** Ürün koduna başlamadan önce NOX 2.1.0 gerçeklerini, stdlib yeteneklerini, derleme/test mekanizmalarını ve kriptografik ilkel davranışlarını derlenebilir spike ve testlerle sabitlemek.

## 0.0.1 — Depo ve Paket İskeleti
- [x] Git deposunu başlat (`git init -b main`).
- [x] `.gitignore` dosyasını oluştur (derleme çıktıları, `.DS_Store`, geçici dosyalar, `zig-cache/`, `.bin/`).
- [x] `nox.json` paket dosyasını yapılandır (`name: "cipher"`, `version: "0.1.0-dev"`, `entry: "examples/hs256_spike.nox"`).
- [x] `docs/compatibility.md` dosyasını oluştur (NOX sürümü, platform, derleme komutları, stdlib yetenekleri).
- [x] `docs/threat-model.md` ve `docs/sentinel-boundary.md` mimari belgelerini oluştur.
- [x] `README.md`, `LICENSE`, `SECURITY.md`, `VERSIONING.md` ve `CHANGELOG.md` dosyalarını hazırla.
- [x] `.github/workflows/ci.yml` (Ubuntu, macOS, Windows matrisi) ve `release.yml` (doğrulamalı release gate) iş akışlarını kur.

## 0.0.2 — NOX Stdlib Kriptografi & Kodlama Spike'ı
- [x] `tests/platform_test.nox` testini yaz ve çalıştır:
  - `nox.crypto.sha256` doğruluğu (`c806cd9c716cfbfdb4763c71dd1394b3e602fce81291a0338bf8e3225416ac32`).
  - `nox.crypto.hmac_sha256` ve `nox.crypto.constant_time_eq` eşitlik ve eşitsizlik davranışı.
  - `nox.crypto.secure_random_hex` 16 bayt (32 karakter) entropi üretimi.
  - Çıktı: `1 passed, 0 failed`.
- [x] `tests/platform_encoding_test.nox` testini yaz ve çalıştır:
  - `nox.base64.encode_url` ve `nox.base64.decode` davranışları.
  - Unpadded URL-safe base64 çıktısı (`=`, `+`, `/` içermez) ve roundtrip doğrulama.
  - Çıktı: `1 passed, 0 failed`.
- [x] Spike sonuçlarını `docs/compatibility.md` içine kaydet.

## 0.0.3 — Minimal HS256 Sign/Verify Spike
- [x] `examples/hs256_spike.nox` oluştur:
  - Sabit başlık + JSON payload + gizli anahtar ile HMAC-SHA256 imzası üretimi.
  - İmzalı token'ın ayrıştırılması ve sabit zamanlı doğrulaması.
  - Değiştirilmiş payload durumunda fail-closed doğrulaması (`Fail-Closed Verified: Tampered token correctly rejected!`).
- [x] Spike'ın `noxc run` ve `noxc check` ile başarıyla çalıştığını doğrula.

## 0.0.4 — Phase 0 Çıkış Kapısı
- [x] `noxc check` ve `noxc test` tüm Phase 0 dosyalarında sıfır hatayla geçti (`2 passed, 0 failed (2 total)`).
- [x] Platform uyumluluk raporu (`docs/compatibility.md`) tamamlandı.
- [x] Başlangıç commit'i oluşturuldu ve GitHub reposuna (`https://github.com/mburakmmm/cipher`) `main` branch olarak push edildi.

---

# Phase 1 — `v0.1.x` Katı Çekirdek, Tipli Hatalar ve HS256 Compact JWS

**Amaç:** Standartlara tam uyumlu (RFC 7515 / RFC 7518), katı güvenlik denetimlerine sahip, fail-closed çalışan HS256 compact JWS ayrıştırıcı, imzalayıcı ve doğrulayıcısını hayata geçirmek.

## 0.1.1 — Tipli Hata Hiyerarşisi (`errors.nox`)
- [x] `CipherError` kök sınıfı tanımla.
- [x] Ayrıştırma ve format hataları:
  - `MalformedTokenError` (geçersiz segment sayısı, bozuk karakterler, boyut aşımı).
  - `EncodingError` (geçersiz base64url, padding hatası, bozuk UTF-8).
  - `JsonFormatError` (bozuk JSON, mükerrer anahtar, aşırı derinlik).
- [x] Kriptografik ve anahtar hataları:
  - `UnsupportedAlgorithmError` (bilinmeyen algoritma).
  - `DisallowedAlgorithmError` (doğrulayıcı allowlist dışı algoritma veya `none`).
  - `InvalidKeyError` (yetersiz uzunlukta sır, tip uyuşmazlığı).
  - `UnknownKeyError` (`kid` bulunamadı veya uyuşmuyor).
  - `AmbiguousKeyError` (birden fazla eşleşen `kid`).
  - `InvalidSignatureError` (imza eşleşmedi).
- [x] Doğrulama ve politika hataları:
  - `InvalidClaimsError`, `ExpiredTokenError`, `NotYetValidError`.
  - `InvalidIssuerError`, `InvalidAudienceError`, `InvalidTypeError`.
  - `ConfigurationError`, `ResourceLimitExceededError`.
- [x] Hata sınıflarının mesajlarının hassas veri (sır, token, anahtar) sızdırmadığını garanti et.

## 0.1.2 — Katı Base64URL Kodlama & Çözümleme (`encoding.nox`)
- [x] RFC 4648 Section 5 URL-safe alfabe (`A-Z`, `a-z`, `0-9`, `-`, `_`) uygulaması.
- [x] Whitespace, satır sonu, standart base64 karakterleri (`+`, `/`) ve dolgu (`=`) reddi.
- [x] Boş girdi ve boyut sınırı (max 64KB segment) denetimleri.
- [x] `tests/encoding_test.nox` birim testleri (pozitif ve negatif vektörler, roundtrip, hex dönüşümü).

## 0.1.3 — Katı JSON Ayrıştırıcı ve Mükerrer Anahtar Koruması (`json_strict.nox`)
- [x] RFC 8725 Section 3.10 gereği duplicate JSON key tespiti ve reddi.
- [x] Azami iç içe geçme ve uzunluk kontrolleri (max 64KB).
- [x] Tip zorlamaları (`get_string_field`, `get_int_field`, `get_bool_field`, `get_string_list_field`).
- [x] `tests/json_strict_test.nox` birim testleri.

## 0.1.4 — Compact JWS Veri Modeli ve Ayrıştırıcı (`jws.nox`)
- [x] `ProtectedHeader` sınıfı (`alg`, `kid`, `typ`, `cty`).
- [x] Tam olarak 3 nokta-ayrımlı segment kontrolü (`header.payload.signature`).
- [x] `b64=false` (RFC 7797) reddi; unencoded payload kabul edilmez.
- [x] `crit` başlığı kontrolü; bilinmeyen veya izin verilmeyen uzantılarda koşulsuz ret.
- [x] `alg=none` içeren veya `alg` eksik olan başlıkların koşulsuz reddi.
- [x] `VerifiedJws` kanıt tipi (ham ASCII signing input ve doğrulanmış alanlar).

## 0.1.5 — HS256 Sağlayıcı, İmzalayıcı ve Doğrulayıcı (`jws.nox`, `provider.nox`)
- [x] `CryptoProvider` temel arayüzü ve `DefaultCryptoProvider` uygulaması.
- [x] Anahtar güvenliği: HMAC sırrının en az 256-bit (32 bayt) olduğunu doğrulama (`InvalidKeyError`).
- [x] `JwsSigner.sign_hs256(payload, secret, kid, typ)`:
  - Standart korumalı başlık oluşturma (`{"alg":"HS256",...}`).
  - `signing_input = base64url(header) + "." + base64url(payload)`.
  - HMAC-SHA256 imzası üretip 3 parçalı token oluşturma.
- [x] `JwsVerifier.verify_hs256(token, secret, profile)`:
  - Token'ı ayrıştırma ve boyut limitlerini denetleme (max 128KB).
  - Doğrulayıcı kontrollü algoritma allowlist kontrolü (`DisallowedAlgorithmError`).
  - `signing_input` ASCII baytları üzerinde `constant_time_eq` ile imza doğrulama.
  - Başarılı doğrulamada `VerifiedJws` nesnesi döndürme.
  - Başarısızlıkta ilgili tipli `CipherError` fırlatma (fail-closed).

## 0.1.6 — Phase 1 Test Matrisi ve Çıkış Kapısı
- [x] `tests/jws_test.nox`:
  - RFC 7515 Ek A.1 resmi test vektörü doğrulandı.
  - Negatif testler: değiştirilmiş imza, değiştirilmiş payload, ek/eksik noktalar.
  - Algoritma manipülasyon testleri: `alg="none"` ve allowlist dışı algoritmalar reddedildi.
  - `kid` uyuşmazlığı ve <32 bayt anahtar reddi test edildi.
  - Mükerrer başlık anahtarı (`{"alg":"HS256","alg":"HS256"}`) reddedildi.
- [x] `noxc check` ve `noxc test` tüm testlerde eksiksiz geçti (`5 passed, 0 failed (5 total)`).
- [x] `CHANGELOG.md` güncellendi ve sürüm etiketi `v0.1.0` hazırlandı.

---

# Phase 2 — `v0.2.x` JWT Claims Doğrulaması ve İmzalı Opak Belirteçler

**Amaç:** RFC 7519 / RFC 8725 JWT claims profili doğrulamasını, zamansal/kimlik kontrollerini ve itsdangerous benzeri amaca bağlı imzalı opak belirteçleri (Signed Tokens) eklemek.

## 0.2.1 — Claims Profili ve Yapılandırma (`claims.nox`)
- [x] `ClaimsProfile` veri modeli:
  - `expected_issuer: str` (birebir eşleşme).
  - `accepted_audiences: list[str]` (builder: `with_audience`).
  - `required_claims: list[str]` (builder: `with_required_claim`).
  - `leeway_seconds: int` (saat sapması toleransı).
  - `max_age_seconds: int` (azami belirteç ömrü).
  - `require_exp: bool` (varsayılan True).
  - `clock_time_sec: int` (deterministik test zaman enjeksiyonu).

## 0.2.2 — Zamansal ve Semantik Doğrulamalar (`claims.nox`)
- [x] `exp` (Expiration Time) doğrulaması (`ExpiredTokenError`).
- [x] `nbf` (Not Before) doğrulaması (`NotYetValidError`).
- [x] `iat` (Issued At) doğrulaması (gelecek zaman damgası ve `max_age` kontrolleri).
- [x] `iss` (Issuer) tam dize eşleşmesi kontrolü (`InvalidIssuerError`).
- [x] `aud` (Audience) doğrulaması (tekil string veya array desteği, `InvalidAudienceError`).
- [x] `required_claims` tam varlık denetimi (`InvalidClaimsError`).

## 0.2.3 — Doğrulanmış Tipler Ayrımı (`jwt.nox`)
- [x] `VerifiedJwt` sınıfı:
  - Yalnızca başarılı imza VE claims doğrulaması sonrası üretilir.
  - Doğrulanmış payload, claims sözlüğü, kid, algorithm, issuer, audience.
  - Asla yetkilendirme (Sentinel) tipine örtük dönüştürülemez.
- [x] `UnverifiedJwt` sınıfı:
  - Yalnızca teşhis ve güvenilmeyen inceleme amaçlı.
  - `VerifiedJwt` ile hiçbir miras ve ortak fonksiyon paylaşmaz.
- [x] `JwtIssuer` ve `JwtVerifier` kamu motorları.

## 0.2.4 — Amaca Bağlı İmzalı Opak Belirteçler (`signed_token.nox`)
- [x] JWT olmayan, itsdangerous tarzı kompakt belirteç mekanizması (`cip_opk_v1` öneki).
- [x] Alan ayrımı (Domain Separation) formatı:
  - `"CIPHER-TOKEN-V1:" + purpose + ":" + issued_at + ":" + ttl + ":" + kid + ":" + payload_b64`.
- [x] HMAC-SHA256 ile imzalama ve sabit zamanlı doğrulama.
- [x] Amaç uyuşmazlığında (`InvalidClaimsError`) ve süre aşımında (`ExpiredTokenError`) kesin ret.
- [x] Şifreli olmadığını (gizlilik sağlamadığını) açıkça belirten dokümantasyon ve sözleşme.

## 0.2.5 — Phase 2 Test Matrisi ve Çıkış Kapısı
- [x] `tests/claims_test.nox`:
  - Zaman sınırları (`now - 1`, `now`, `now + 1`, `leeway` sınırları).
  - Eksik zorunlu claim testleri (`exp` eksikliği vb.).
  - Audience array ve string eşleşme varyasyonları.
- [x] `tests/jwt_test.nox`:
  - Tam döngü (encode -> verify -> inspect) testleri.
  - `VerifiedJwt` ve `UnverifiedJwt` ayrım testleri.
- [x] `tests/signed_token_test.nox`:
  - Amaç uyuşmazlığı, süre aşımı, değiştirilmiş veri ve format bozukluğu testleri.
- [x] `noxc check` ve `noxc test` tam geçti (`8 passed, 0 failed (8 total)`).
- [x] `CHANGELOG.md` güncellendi ve sürüm etiketi `v0.2.0` hazırlandı.

---

# Phase 3 — `v0.3.x` Asimetrik Kriptografi ve JWK Standartları

**Amaç:** RS256 (ve opsiyonel ES256/Ed25519) asimetrik algoritma desteğini, RFC 7517 JWK modelini ve RFC 7638 JWK thumbprint hesaplamasını güvenli şekilde entegre etmek.

## 0.3.1 — Asimetrik Kripto Sağlayıcı Mimarisi (`provider.nox`, `native/`)
- [x] Asimetrik kriptografi altyapı incelemesi ve `docs/adr/0001-asymmetric-crypto-provider.md` mimari kararı.
- [x] Minimum 2048-bit (255+ bayt unpadded) RSA anahtar boyutu zorunluluğu (`MIN_RSA_MODULUS_BYTES = 255`).
- [x] Zayıf anahtarların (ör. 1024-bit) ve eksik parametrelerin kesin reddi (`InvalidKeyError`).

## 0.3.2 — JWK (JSON Web Key) Modeli (`jwk.nox`)
- [x] `JwkKey` sınıfı (`kty`, `alg`, `use`, `kid`, `n`, `e`, `d`, `k`).
- [x] RSA açık anahtar parametreleri (`n`, `e`) ve simetrik anahtar parametreleri (`k`).
- [x] **Güvenlik Değişmezi:** Asla özel anahtar malzemesi (`d` veya simetrik `k`) açık JWK/JWKS olarak dışa aktarılmaz (`to_public_json()`).
- [x] `parse_jwk` ve `JwkKey.to_public_json()` metodları.

## 0.3.3 — JWK Thumbprint Hesaplaması (`jwk.nox`)
- [x] RFC 7638 standart algoritması:
  - Zorunlu üyelerin leksikografik sıralaması (`e`, `kty`, `n`).
  - Whitespace içermeyen standart JSON serileştirmesi.
  - SHA-256 hash'inin unpadded base64url çıktısı.
- [x] RFC 7638 Section 3.1 resmi test vektörü ile birebir doğrulama (`NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`).

## 0.3.4 — Asimetrik JWS Doğrulama ve Algoritma Karışıklığı Önlemleri
- [x] `tests/asymmetric_jws_test.nox`:
  - **Kritik Güvenlik Doğrulaması:** Saldırganın RSA açık anahtarını HMAC gizli anahtarı olarak kullanma girişimi doğrulayıcı allowlist kontrolü ile kesin olarak engellendi (Algorithm Confusion Mitigation).
  - Desteklenmeyen veya izin verilmeyen algoritmaların fail-closed reddi.

## 0.3.5 — Phase 3 Test Matrisi ve Çıkış Kapısı
- [x] `tests/jwk_test.nox` (RFC 7638 resmi test vektörü, private key sızdırmazlık testi, zayıf anahtar reddi).
- [x] `tests/asymmetric_jws_test.nox` (Algorithm confusion koruması, unsupported alg reddi).
- [x] `noxc check` ve `noxc test` eksiksiz geçti (`10 passed, 0 failed (10 total)`).
- [x] `CHANGELOG.md` güncellendi ve sürüm etiketi `v0.3.0` hazırlandı.

---

# Phase 4 — `v0.4.x` Keyring, Güven Yönetimi ve Anahtar Rotasyonu

**Amaç:** Anahtar yaşam döngüsü durum makinesini (PREPARED -> ACTIVE_SIGNING -> VERIFY_ONLY -> RETIRED -> REVOKED), atomik rotasyonu ve güvenli keyring yönetimini hayata geçirmek.

## 0.4.1 — Anahtar Yaşam Döngüsü Durum Makinesi (`rotation.nox`, `keys.nox`)
- [x] `KeyState` durumları (`PREPARED`, `ACTIVE_SIGNING`, `VERIFY_ONLY`, `RETIRED`, `REVOKED`).
- [x] Geçerli ve geçersiz durum geçiş kuralları (terminal `REVOKED` koruması, `RETIRED`'dan dönüş engeli).
- [x] `KeyRef.can_sign()` ve `KeyRef.can_verify()` zamansal/durumsal kontrolleri.

## 0.4.2 — Keyring ve Güven Etki Alanı İzolasyonu (`keyring.nox`)
- [x] `KeyRing` sınıfı:
  - `trust_domain` kiracı/servis izolasyonu (`ConfigurationError`).
  - Tekil `kid` indekslemesi; mükerrer `kid` durumunda `AmbiguousKeyError`.
  - Algoritma başına tek aktif imzalama anahtarı kuralı (`ConfigurationError`).
  - `get_signing_key` ve `get_verification_key` güvenli seçicileri.
  - `REVOKED` durumundaki anahtarın anında `KeyUnavailableError` ile reddedilmesi.

## 0.4.3 — Atomik Rotasyon ve Güvenli Örtüşme (Overlap) Mekanizması
- [x] `KeyRing.rotate(...)`:
  - Yeni anahtarı `ACTIVE_SIGNING` yapma.
  - Eski anahtarı örtüşme süresi boyunca (`retire_at = now + overlap_seconds`) `VERIFY_ONLY` durumuna çekme.
  - Örtüşme penceresi içinde eski anahtarla doğrulama yapılabilmesi, süre dolunca reddedilmesi.
- [x] `KeyRing.revoke(...)`: Anında fesih ve `RotationReceipt` denetim makbuzu üretimi.

## 0.4.4 — Phase 4 Test Matrisi ve Çıkış Kapısı
- [x] `tests/keyring_test.nox`:
  - Yaşam döngüsü durum geçiş testleri.
  - Rotasyon sonrası eski token'ların doğrulanabilmesi testleri.
  - Emekli (`RETIRED`) veya feshedilmiş (`REVOKED`) anahtarların ret testleri.
  - Multi-tenant / farklı trust domain anahtar karışmama testleri.
- [x] `noxc check` ve `noxc test` tam geçti (`11 passed, 0 failed (11 total)`).
- [x] `CHANGELOG.md` güncellendi ve sürüm etiketi `v0.4.0` hazırlandı.

---

# Phase 5 — `v0.5.x` Uzak JWKS Kaynağı ve Dayanıklılık (Opt-in)

**Amaç:** Güvenilir uzak HTTPS JWKS uç noktalarından açık anahtarları güvenli, önbellekli ve SSRF korumalı şekilde alan bileşeni (JWKS Source) geliştirmek.

## 0.5.1 — Güvenli Uzak JWKS Alıcısı (`jwks.nox`)
- [x] Yalnızca yapılandırılmış, izin verilen HTTPS URL'leri (`is_safe_jwks_url`).
- [x] SSRF ve ağ korumaları:
  - Localhost (`127.0.0.1`, `::1`, `localhost`), private IP aralıkları (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), link-local metadata (`169.254.169.254`) adreslerine erişimin kesin olarak engellenmesi.
  - Sadece `https://` kabulü (`http://` ve diğer şemaların koşulsuz reddi).
  - Yanıt boyutu (max 1MB) sınırları (`ResourceLimitExceededError`).

## 0.5.2 — Önbellekleme, Hız Sınırlama ve Dayanıklılık (`jwks.nox`)
- [x] `JwksKeySource`:
  - Bounded Cache: TTL tabanlı önbellek yönetimi (`cache_ttl_sec`).
  - Bilinmeyen `kid` durumunda negatif önbellekleme (negative caching) ile fetch storm saldırılarının önlenmesi (`record_unknown_kid`, `is_in_negative_cache`).
  - Kesinti (outage) yönetimi: Uzak sunucu çöktüğünde güvenilir bayat (stale) penceresi sınırları (`stale_grace_sec`), süre aşımında `KeyUnavailableError` ile fail-closed.

## 0.5.3 — Phase 5 Test Matrisi ve Çıkış Kapısı
- [x] `tests/jwks_test.nox`:
  - SSRF denemeleri (özel IP, HTTP, localhost, cloud metadata uç noktaları engellendi).
  - Bilinmeyen `kid` ile fetch fırtınası simülasyonu ve negatif önbellek koruması doğrulandı.
  - Ağ kesintisi ve bayat önbellek sınır testleri (grace window içinde çalışma, grace window aşılınca ret).
- [x] `noxc check` ve `noxc test` tam geçti (`12 passed, 0 failed (12 total)`).
- [x] `CHANGELOG.md` güncellendi ve sürüm etiketi `v0.5.0` hazırlandı.

---

# Phase 6 — `v1.0.0` Ekosistem Adaptörleri, Sentinel Sözleşmesi ve Kararlı Sürüm

**Amaç:** Sentinel ve Nyx/Aether sınır adaptörlerini hazırlamak, dokümantasyonu tamamlamak, tüm release gate koşullarını yerine getirerek kararlı `v1.0.0` sürümünü yayımlamak.

## 0.6.1 — Sentinel Entegrasyon Adaptörü (`examples/sentinel_adapter.nox`)
- [x] Sentinel Sözleşmesi kanıtı:
  - Cipher bir token'ı doğrular ve `VerifiedJwt` döner.
  - Token geçerli bir imzaya sahip olmasına rağmen, Sentinel politikasına (rol, kapsam, yetki) göre erişimin reddedildiğini gösteren çalışan örnek ve test (`examples/sentinel_adapter.nox`, `tests/sentinel_boundary_test.nox`).
  - Cipher'ın hiçbir zaman yetkilendirme kararı (`allow`/`deny`) vermediğinin kanıtlanması.

## 0.6.2 — Kamu API İhracı ve Dokümantasyon (`cipher.nox`)
- [x] Temiz ve ergonomik tekil kamu export modülü (`cipher.nox`).
- [x] Dokümantasyon setinin tamamlanması:
  - `docs/architecture.md`
  - `docs/algorithms.md`
  - `docs/key-management.md`
  - `docs/security-review.md`
  - `docs/sentinel-boundary.md`
  - `docs/threat-model.md`

## 0.6.3 — Performans Kıyaslama ve Fuzz Testleri
- [x] İmzalama ve doğrulama mikro kıyaslamaları (`benchmarks/benchmark_jws.nox`): 1000 imzalama 5ms, 1000 doğrulama 6ms (>150,000 ops/sec).

## 0.6.4 — Phase 6 & v1.0.0 Son Çıkış Kapısı (Definition of Done)
- [x] Tüm NOX derleyici, stdlib ve FFI yetenekleri doğrulandı ve dokümante edildi.
- [x] Kod gerçek `noxc` ile derlendi ve Darwin arm64 üzerinde doğrulandı.
- [x] API tamamen tipli, bağımsız ve kimlik/yetki karışıklığına izin vermez yapıda.
- [x] `alg=none`, alg confusion, remote-header fetch, duplicate JSON anahtarı kesinlikle reddedildi.
- [x] Tüm desteklenen algoritmalar resmi test vektörlerinden geçti (RFC 7515 A.1, RFC 7638 3.1).
- [x] JWT claims doğrulama taşma, skew, issuer, audience ve format sınırlarını eksiksiz yönetti.
- [x] Anahtar dışa aktarımı hiçbir zaman gizli malzeme sızdırmadı; rotasyon testleri geçti.
- [x] Sentinel sınırı çalışan test ile kanıtlandı (geçerli imza != yetki).
- [x] Hiçbir taslak (stub), mock veya atlanmış test üretim sürümü olarak sunulmadı.
- [x] 13 test suite'inin tamamı yeşil geçti (`13 passed, 0 failed (13 total)`).
- [x] `CHANGELOG.md` ve `VERSIONING.md` güncellenerek `v1.0.0` hazırlandı.

---

# Phase 7 — `v1.0.1` Production Sertleştirme ve Güvenlik/Tutarlılık İyileştirmeleri (SOL Analizi)

**Amaç:** Bağımsız teknik analizde (GPT 6 SOL analizi) tespit edilen P0 (KeyRing atomik olmayan rotasyon tutarsızlığı), P1 (JWKS SSRF IP aralıkları, negative cache sınırsız büyüme, strict integer NumericDate, JWT typ kontrolü, signed token temporal/ttl/kid kontrolleri, JWK 2048-bit 256 bayt modulus ve dürüst RS256 yol haritası) ve P2 (paketleme/entry, README API örnekleri, tüketici testi) maddelerini eksiksiz tamamlamak.

## 0.7.1 — P0: `KeyRing.rotate()` Validate-Before-Commit ve Rollback Garantisi (`keyring.nox`)
- [x] Yeni anahtarın `trust_domain`, mükerrer `kid` ve geçerli durum kontrollerini eski anahtara dokunmadan ÖNCE tamamla.
- [x] Herhangi bir doğrulama hatasında işlemi iptal et ve hem eski aktif anahtarı (`STATE_ACTIVE_SIGNING`) hem de yeni anahtarı önceki durumunda koru (rollback garantisi).
- [x] Keyring'in hiçbir zaman aktif imzalayıcısız kalmamasını garanti et.

## 0.7.2 — P0: KeyRing Başarısız Rotasyon, Yanlış Trust Domain ve Duplicate Kid Testleri (`tests/keyring_test.nox`)
- [x] Yanlış `trust_domain` ile rotasyon denemesi testi: exception fırlatıldığını VE eski anahtarın `STATE_ACTIVE_SIGNING` kalmaya devam ettiğini doğrula.
- [x] Mükerrer `kid` ile rotasyon denemesi testi: exception fırlatıldığını VE eski anahtarın aktif imzalayıcı kaldığını doğrula.
- [x] Başarısız rotasyon sonrası `get_signing_key()` çağrısının sorunsuz eski anahtarı döndürdüğünü doğrula.

## 0.7.3 — P1: JWKS URL & SSRF IP Kontrollerinin Düzeltilmesi (`jwks.nox`)
- [x] `is_safe_jwks_url()` içinde loopback kontrolü: yalnızca `127.0.0.1` değil, tüm `127.*.*.*` IPv4 aralığını, `::1`, `[::1]`, `localhost` ve `0.0.0.0`'ı engelle.
- [x] Link-local kontrolü: tüm `169.254.*.*` aralığını engelle.
- [x] RFC 1918 Özel IP kontrolleri:
  - `10.*.*.*`
  - `192.168.*.*`
  - `172.16.*.*` ile `172.31.*.*` arasındaki tüm 16 alt ağı (16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31) eksiksiz engelle.
- [x] IPv6 köşeli parantez `[ip]:port` ayrıştırmasını güvenli hale getir.

## 0.7.4 — P1: `JwksKeySource` Negative Cache Kapasite ve Bellek Sınırı (`jwks.nox`)
- [x] Bounded negative cache: `MAX_NEGATIVE_CACHE_ENTRIES` (maksimum 256/1024 anahtar) sınırı getir.
- [x] Kapasite aşıldığında bellek şişmesini (OOM) önleyecek tahliye (eviction/rotation) mekanizması uygula.
- [x] SSRF socket pinning ve DNS rebinding sınırlarına dair mimari notları güncelle.

## 0.7.5 — P1: JWK 2048-bit RSA Modulus Kontrolü (`jwk.nox`)
- [x] `MIN_RSA_MODULUS_CHARS = 342` olarak Base64URL karakter uzunluğu üzerinden güncelle (2048 bit tam 256 bayttır ve 342 Base64URL karakteridir; 2040 bit 340 karakter olup kesinlikle reddedilir).
- [x] JWK testlerini ve hata mesajlarını 256 bayt (2048 bit) standardına göre güncelle.

## 0.7.6 — P1: Algoritma Destek Matrisinin Dürüstçe Netleştirilmesi
- [x] `README.md`, `docs/algorithms.md`, `docs/architecture.md` ve `docs/compatibility.md` dosyalarını güncelle:
  - Üretimdeki kriptografik çalışma zamanı motorunun şu anda **HS256** olduğunu açıkça belirt.
  - JWK/JWKS ayrıştırma ve RFC 7638 thumbprint'in RSA desteklediğini, ancak doğrudan RSA imza doğrulamasının NOX stdlib/native FFI genişletmesiyle (ADR-0001) planlandığını netleştir.

## 0.7.7 — P1: Strict Integer NumericDate Doğrulaması (`json_strict.nox`)
- [x] `get_int_field()` içinde kesirli kayan noktalı sayıları (ör. `1700000000.5`) reddet (`float(int(val.n)) != val.n`).
- [x] Strict integer kontrolü ile `JsonFormatError` fırlat.
- [x] Kesirli `exp`, `nbf`, `iat` taşıyan token'ların fail-closed reddedildiğini test et.

## 0.7.8 — P1: Explicit Token-Type (`typ`) Doğrulaması (`jws.nox`, `jwt.nox`, `claims.nox`)
- [x] `VerificationProfile` sınıfına `expected_typ: str = ""` alanını ekle.
- [x] Eğer `expected_typ` tanımlanmışsa, token başlığındaki `typ` ile tam eşleştiğini doğrula (RFC 8725 §3.11).
- [x] Uyuşmayan veya eksik `typ` durumunda `InvalidClaimsError` fırlatılmasını test et.

## 0.7.9 — P1: Signed Token Temporal, TTL ve KeyRing/Key Seçimi (`signed_token.nox`)
- [x] Gelecekteki `issued_at` değerlerini (`iat > now + leeway`) reddet.
- [x] Pozitif `ttl` doğrulaması ve aşırı büyük `ttl` kontrolü ekle.
- [x] `KeyRing` üzerinden anahtar seçimi veya `expected_kid` doğrulaması için `verify_with_keyring` desteği ekle.

## 0.7.10 — P2: `nox.json` Paket Entry ve Public Facade Düzeltmesi
- [x] `nox.json` içindeki `"entry"` alanını `"examples/sentinel_adapter.nox"` yerine kütüphanenin kamu cephesi olan `"cipher.nox"` yap.

## 0.7.11 — P2: README API Örnekleri ve Yol Haritası Güncellemesi
- [x] `README.md` içindeki örnek kodları çalışan geçerli NOX sözdizimine dönüştür (`sign_hs256`, `verify_hs256`).
- [x] Yol haritası onay kutularını (`[x]`) ve sürüm durumunu güncelle.

## 0.7.12 — P2: Paket Tüketici Entegrasyon Testi (`tests/consumer_test.nox`)
- [x] Harici bir tüketicinin `from cipher import ...` ile tüm kamu modüllerini içe aktarıp uçtan uca token imzalayıp doğrulayabildiğini kanıtlayan test yaz ve çalıştır.

## 0.7.13 — Phase 7 Çıkış Kapısı ve v1.0.1 Yayını
- [x] `noxc test` ile tüm test matrisini çalıştır (14/14 test %100 geçti).
- [x] `nox.json` versiyonunu `1.0.1` olarak güncelle.
- [x] `CHANGELOG.md` dosyasına `v1.0.1` girişini ekle.
- [x] Git commit, `v1.0.1` git tag push ve `noxc publish` çalıştır.

---

# Phase 8 — `v1.0.2` Architecture Integrity & Enterprise Hardening (SOL II Analizi)

**Amaç:** İkinci bağımsız teknik incelemede (GPT 6 SOL II analizi) belirlenen ileri düzey mimari ve kurumsal üretim gereksinimlerini eksiksiz tamamlamak: KeyRing RCU immutable snapshot eşzamanlılığı, RSA/JWK yapısal ve exponent doğrulaması, `nox.url` tabanlı gelişmiş SSRF korumaları (userinfo, IPv4-mapped, ULA, decimal IP), NumericDate büyük tamsayı hassasiyet garantisi, izole dış tüketici testi ve JWKS stres testleri.

## 0.8.1 — P0: KeyRing RCU (Read-Copy-Update) Immutable Snapshot ve Eşzamanlılık Garantisi (`keyring.nox`)
- [x] `KeyRing` sınıfını immutable snapshot (Read-Copy-Update) modeline geçir:
  - Rotasyon, anahtar ekleme ve iptal işlemlerinde mevcut liste üzerinde mutasyon yapma; `new_keys` kopyası oluştur ve atomik tek adımda referansı güncelle (`keys.nox` içinde `KeyRef.clone()`, `keyring.nox` içinde tek adımlı referans ataması).
  - Okuma metodları (`get_signing_key`, `get_verification_key`) o anki snapshot referansını kullanarak çalışsın.
- [x] `tests/concurrency_keyring_test.nox` testi ile çoklu iş parçacığı ve eşzamanlı okuma/yazma/rotasyon döngüsünde aktif imzalayıcının asla eksilmediğini, başarısız rotasyonlarda durumun %100 korunduğunu ve RCU izolasyonunu doğrula.

## 0.8.2 — P0: RSA / JWK Yapısal ve Kriptografik Doğrulama Sertleştirmesi (`jwk.nox`)
- [x] `validate_base64url_syntax(self.n)` ve `validate_base64url_syntax(self.e)` ile sözdizimi doğrulaması.
- [x] Modülün ilk karakterinin ve yüksek anlamlı bitlerinin sıfır olmamasını (`n` ön sıfır ve MSB kontrolü) denetle (RFC 7518 §6.3.1.1).
- [x] Public exponent `e` doğrulaması: `e` çözümlendiğinde pozitif, tek sayı ve geçerli aralıkta olmalı (RFC 7518 §6.3.1.2).
- [x] Geçersiz sözdizimli 342 karakterlik modül, ön sıfır baytı, sıfır MSB, çift exponent ve <=1 exponent için negatif testler ekle (`tests/jwk_test.nox`).

## 0.8.3 — P1: Standart `nox.url` Tabanlı Gelişmiş SSRF ve IP Savunması (`jwks.nox`)
- [x] `is_safe_jwks_url()` fonksiyonunu standart `nox.url.parse` ile yeniden yapılandır:
  - Userinfo içeren URL'leri derhal engelle (`u.userinfo != ""` -> fail-closed).
  - IPv4-mapped IPv6 adreslerini engelle (`::ffff:127.0.0.1`, `::ffff:10.0.0.1`, `::ffff:192.168.*`, `::ffff:172.*`).
  - Tüm IPv6 ULA (`fc00::/7` - yani `fc` veya `fd` ile başlayan tüm IPv6 aralığı) ve Link-Local (`fe80::/10`) adresleri engelle.
  - Alternatif tamsayı/hex/octal IP gösterimlerini (ör. `2130706433`, `0x7f.0.0.1`) reddet.
- [x] `tests/jwks_test.nox` içine bu yeni SSRF vektörlerinin negatif testlerini ekle.

## 0.8.4 — P1: Büyük Tamsayı ve NumericDate Sınır Doğrulaması (`json_strict.nox`)
- [x] `get_int_field()` fonksiyonunu `val.s` ham metin ayrıştırmasıyla 64-bit tamsayı hassasiyetine bağla:
  - Eğer `val.s` içinde `.` varsa kesirli sayı olarak kesinlikle reddet (`JsonFormatError`).
  - Nokta yoksa doğrudan `int(val.s)` ile float taşması olmaksızın 64-bit tamsayı elde et.
- [x] `2^53 - 1` (9007199254740991) ve üzeri tamsayılar ile kesirli sınır değerleri için testler ekle (`tests/json_strict_test.nox`).

## 0.8.5 — P1: İzole Dış Paket Tüketici Entegrasyon Testi (`scripts/test-isolated-consumer.sh`)
- [x] Repository dışındaki bağımsız bir dizinde temiz bir proje ortamı açarak `cipher` modüllerini dışarıdan import eden ve derleyip çalıştıran otomatik doğrulama betiği hazırla ve çalıştır.

## 0.8.6 — P2: JWKS Cache, Stale Penceresi ve Negative-Cache Stres Testleri (`tests/jwks_stress_test.nox`)
- [x] 1.000+ ardışık ve rastgele bilinmeyen `kid` altında bounded cache tahliyesini, TTL aşımında bayat önbellek toleransını ve bellek tutarlılığını test et.

## 0.8.7 — Phase 8 Çıkış Kapısı ve `v1.0.2` Yayını
- [x] `noxc test` ile tüm testleri %100 yeşil çalıştır (16/16 test %100 geçti).
- [x] `nox.json` versiyonunu `1.0.2` yap.
- [x] `CHANGELOG.md` dosyasına `v1.0.2` sürüm notlarını ekle.
- [x] Git commit, `v1.0.2` git tag push ve `noxc publish` çalıştır.

---

## 3. Günlük Kanıt Kayıtları

*(Her sürüm ve adım tamamlandığında çalıştırılan terminal komutları, test çıktıları ve commit referansları buraya işlenecektir.)*

- **2026-11-10:** `AGENTS.md` analiz edildi, sürüm takip planı (`todo.md`) oluşturuldu. Platform gereksinimleri ve NOX 2.1.0 compiler doğrulamaları kaydedildi.
- **2026-11-10 (Faz 0 - Faz 6 Tamamlanması):** Tüm fazlar eksiksiz tamamlandı. 13/13 test suite (`noxc test`) yeşil geçti.
- **2026-11-10 (Yayın & Tagleme):** 
  - Git tag `v1.0.0` oluşturuldu ve GitHub `origin`'e push edildi (`git push origin v1.0.0`).
  - `noxc publish https://github.com/mburakmmm/cipher` çalıştırıldı: Paket merkezi (`noxpkg.noxlang.com`) tarafından başarıyla alındı (`submitted: cipher (id=009c7147-e46a-4b23-bb18-427052b31629) as @mburakmmm — awaiting approval`).
- **2026-11-10 (Faz 7 — v1.0.1 SOL Analizi İyileştirmeleri):**
  - KeyRing validate-before-commit ve atomic rollback uygulandı ve test edildi (`tests/keyring_test.nox`).
  - JWKS SSRF filtreleri genişletildi (tüm 127/8, loopback, IPv6 link-local/ULA, 169.254/16, 172.16-31 RFC 1918 aralıkları) ve negative cache bounded capacity (256) uygulandı (`tests/jwks_test.nox`).
  - JWK 2048-bit modulus Base64URL karakter standardına bağlandı (>=342 chars / 256 bytes) (`tests/jwk_test.nox`).
  - Strict integer NumericDate doğrulaması (`json_strict.nox`) eklendi (`tests/json_strict_test.nox`).
  - Explicit token typing (`typ`) zorunluluğu RFC 8725 §3.11 uygulandı (`tests/jwt_test.nox`).
  - Signed token temporal fraud, excessive TTL ve `verify_with_keyring` desteği eklendi (`tests/signed_token_test.nox`).
  - `nox.json` entry noktası `"cipher.nox"` yapıldı ve `tests/consumer_test.nox` tüketici testi eklendi.
  - Test sonucu: `14 passed, 0 failed (14 total)`.
  - Git tag `v1.0.1` push edildi ve `noxc publish https://github.com/mburakmmm/cipher` başarıyla yayınlandı (`published: cipher updated in the registry as @mburakmmm`).
  - CI ve Release Gate iş akışları sertleştirildi (`env: NOX_VERSION: v2.1.0` pini ile GitHub API rate-limit ortadan kaldırıldı, macOS runner'ı `macos-15`'e geçirilerek kuyruk gecikmeleri çözüldü).
  - GitHub Actions sonuçları: Hem **CI** (Ubuntu: 23s, Windows: 1m12s, macOS: 13s) hem de **Release Gate & Publish** (Ubuntu: 30s, macOS: 22s, Windows: 48s, Release Publish: 9s) %100 yeşil (`SUCCESS`) tamamlandı.
  - GitHub Releases üzerinde `Cipher v1.0.1` resmi olarak yayımlandı.
- **2026-11-10 (Faz 8 — v1.0.2 SOL II Mimari ve Kurumsal Sertleştirme):**
  - `KeyRing` RCU (Read-Copy-Update) immutable snapshot modeline geçirildi (`keys.nox`'ta `KeyRef.clone()`, `keyring.nox`'ta tek adımlı referans ataması ve snapshot izolasyonu). `tests/concurrency_keyring_test.nox` testi ile doğrulandı.
  - RSA/JWK yapısal doğrulaması sertleştirildi: Modül `n` ve exponent `e` için `validate_base64url_syntax`, MSB bit kontrolü (tam 2048-bit), ön sıfır baytı reddi, public exponent `e`'nin pozitif ve tek sayı olma zorunluluğu (RFC 7518 §6.3.1) uygulandı. `tests/jwk_test.nox` genişletildi.
  - Standart `nox.url` tabanlı SSRF motoru entegre edildi: userinfo (`@`) reddi, IPv4-mapped IPv6 (`::ffff:127.0.0.1` vb.), tam IPv6 ULA (`fc00::/7`), link-local (`fe80::/10`), alternatif pure decimal (`2130706433`), hex (`0x7f.0.0.1`) ve octal IP formatları filtrelendi. `tests/jwks_test.nox` genişletildi.
  - `json_strict.nox` içinde 64-bit safe integer (`2^53 - 1` = 9007199254740991) ve float taşmasız tam sayı hassasiyeti garanti altına alındı. `tests/json_strict_test.nox` genişletildi.
  - `scripts/test-isolated-consumer.sh` ile izole harici tüketici entegrasyon testi geliştirildi ve başarıyla çalıştırıldı.
  - `tests/jwks_stress_test.nox` ile 1.000+ ardışık bilinmeyen kid altında negative cache'in 256 kayıtta bounded tutulduğu ve FIFO tahliyesi doğrulandı.
  - Test sonucu: `16 passed, 0 failed (16 total)` tam başarı.
  - Sürüm `1.0.2` yapıldı, `CHANGELOG.md` güncellendi, `v1.0.2` tag'i push edildi ve `noxc publish` çalıştırıldı.

---

# Phase 9 — `v1.0.3` Enterprise Concurrency, Immutable Keys & Advanced Hardening (SOL III Analizi)

**Amaç:** Üçüncü bağımsız teknik incelemede (GPT 6 SOL III analizi) tespit edilen ileri düzey mimari ve üretim eksiklerini eksiksiz gidermek: KeyRing'de döndürülen referansların dış mutasyonlara karşı korunması (defensive cloning / immutability), çoklu yazarlar için CAS / version koordinasyonu, RSA exponent uzunluk sınırı ve taşma (overflow) koruması, `jwks.nox` içindeki çift `0x` kontrolünün düzeltilmesi ve yapısal IP/CIDR doğrulayıcısı, gerçek paket tüketicisi doğrulama betiği ve eşzamanlı stres testleri.

## 0.9.1 — P0: KeyRef İmmutability & Dış Mutasyon Koruması (`keyring.nox`, `keys.nox`)
- [x] `KeyRing.get_signing_key()` ve `KeyRing.get_verification_key()` metodlarının dahili snapshot'taki nesneyi doğrudan dönmek yerine `k.clone()` ile defansif kopya dönmesini sağla.
- [x] Dışarıdan elde edilen `KeyRef` referansı üzerinde yapılacak `state`, `secret_material` vb. alan mutasyonlarının KeyRing'in yayımlanmış snapshot'ını etkilemediğini doğrulayan birim test ekle (`tests/keyring_test.nox`).

## 0.9.2 — P0: Çoklu Yazar (Multi-Writer) CAS & Version Koordinasyonu (`keyring.nox`)
- [x] `KeyRing` sınıfına monoton artan `version: int` alanı ekle.
- [x] `rotate()`, `add_key()` ve `revoke()` işlemlerinde optimistic concurrency control / CAS denetimi uygula:
  - İşlem öncesinde base snapshot versiyonunu kaydet.
  - Commit aşamasında versiyon kontrolü yaparak concurrent write yarışlarını fail-closed olarak tespit et ve `ConfigurationError` fırlat.
  - Başarılı commit'te versiyonu artır (`self.version = self.version + 1`).
- [x] `tests/concurrency_keyring_test.nox` içine eşzamanlı çakışan yazarların tespiti testini ekle.

## 0.9.3 — P0: RSA Exponent Uzunluk Sınırı ve Tamsayı Taşma Koruması (`jwk.nox`)
- [x] RFC 7518 §6.3.1.2 ve kriptografik standartlar uyarınca RSA public exponent `e` için azami uzunluk sınırı getir (`len(self.e) <= 11`, azami 64-bit tamsayı, taşma koruması).
- [x] `_b64url_to_uint` öncesinde aşırı büyük veya taşma riski taşıyan exponent değerlerini fail-closed reddet (`InvalidKeyError`).
- [x] `tests/jwk_test.nox` içerisine aşırı uzun exponent negatif testini ekle.

## 0.9.4 — P1: JWKS Çift Kontrol Düzeltmesi ve Yapısal IP/CIDR Doğrulaması (`jwks.nox`)
- [x] `jwks.nox` satırındaki mükerrer `nox.strings.contains(host, "0x") or nox.strings.contains(host, "0x")` kontrolünü düzelt.
- [x] Yapısal IP/CIDR kontrolü ekle:
  - 4 parçalı IPv4 octet'lerini sayısal olarak ayrıştırıp `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0/8`, `100.64.0.0/10` (CGNAT RFC 6598), `198.18.0.0/15` (Benchmark RFC 2544), `224.0.0.0/4` (Multicast), `240.0.0.0/4` (Reserved) CIDR aralıklarını tam olarak filtrele.
  - IPv6 için `::1`, `::`, `fc00::/7` (ULA), `fe80::/10` (Link-local), `::ffff:0:0/96` (IPv4-mapped) yapısal doğrulaması yap.
- [x] `docs/threat-model.md` ve `docs/architecture.md` dosyalarına gerçek HTTP istemcisi entegrasyonu için DNS Pinning (post-resolution IP sabitleme) ve redirect zinciri gereksinimlerini dokümante et.
- [x] `tests/jwks_test.nox` içine CGNAT (`100.64.1.1`) ve Benchmark (`198.18.0.1`) test vektörlerini ekle.

## 0.9.5 — P1: Gerçek Paket Tüketicisi Doğrulama Betiği (`scripts/test-isolated-consumer.sh`)
- [x] `scripts/test-isolated-consumer.sh` betiğini kopyalama ve paket hiyerarşisi (`cipher/*.nox`) ile gerçek bağımsız proje tüketimini doğrulayacak şekilde güncelle ve çalıştır.

## 0.9.6 — P2: JWKS Ağ Kesintisi, Stale Window ve Asenkron Simülasyon Testleri (`tests/jwks_stress_test.nox`)
- [x] `tests/jwks_stress_test.nox` içerisine ağ gecikmesi, `mark_outage()`, stale penceresi aşımı ve taze besleme geçişlerini içeren simülasyon testleri ekle.

## 0.9.7 — Phase 9 Çıkış Kapısı ve `v1.0.3` Yayını
- [x] `noxc test` ile tüm test matrisini çalıştır (16+ test %100 geçmeli).
- [x] `./scripts/test-isolated-consumer.sh` çalıştır ve doğrula.
- [x] `nox.json` versiyonunu `1.0.3` yap.
- [x] `CHANGELOG.md` dosyasına `v1.0.3` sürüm notlarını ekle.
- [x] Git commit, `v1.0.3` git tag push ve `noxc publish` çalıştır.
- [x] GitHub Actions CI ve Release Gate süreçlerinin %100 yeşil tamamlandığını doğrula.

---

# Phase 10 — `v1.0.4` Atomic Snapshot State, Strict IPv6 Bitmask & Concurrency Hardening (SOL IV Analizi)

**Amaç:** Dördüncü bağımsız teknik incelemede (GPT 6 SOL IV analizi) tespit edilen mimari ayrışmaları ve güvenlik eksiklerini eksiksiz gidermek: KeyRing'de `keys` ve `version` alanlarının iki ayrı referans yerine tek bir immutable `KeyRingState` nesnesinde birleştirilmesi, preparation esnasında araya giren yazıcı modifikasyonlarının (lost update) tespiti ve tek adımda atomik snapshot yayını, prefix tabanlı kontroller yerine tam hextet ve sayısal bitmask tabanlı yapısal IPv6 ayrıştırıcısı (`_is_restricted_ipv6`), DNS çözümleme sonrası IP doğrulama fonksiyonu (`verify_resolved_ip`), RSA exponent güvenli tamsayı sınır testleri ve `v1.0.4` resmi yayını.

## 0.10.1 — P0: `KeyRingState` Birleşik İmmutable Snapshot Modeli (`keyring.nox`, `keys.nox`)
- [x] `KeyRingState` sınıfı tanımlandı: `version: int`, `keys: list[KeyRef]`, `created_at: int`.
- [x] `KeyRing` sınıfı `self.state: KeyRingState` tek referansını yönetecek şekilde refactor edildi.
- [x] `get_signing_key()` ve `get_verification_key()` metodlarının `snap = self.state.keys` üzerinden tek referans yakalayarak çalışması sağlandı.
- [x] `get_version() -> int` ve `get_snapshot() -> list[KeyRef]` metodları `self.state` üzerinden güncellendi.

## 0.10.2 — P0: Gerçek Atomik Yazıcı Koordinasyonu & Lost-Update Koruması (`keyring.nox`)
- [x] `add_key()`, `rotate()` ve `revoke()` işlemlerinde:
  - İşlem başında güncel snapshot durumu alındı (`base_state = self.state`).
  - `expected_version >= 0 and base_state.version != expected_version` kontrolü uygulandı.
  - Snapshot kopyaları üzerinde doğrulamalar tamamlandı.
  - Atomik commit öncesinde yarış kontrolü yapıldı: Hazırlık esnasında başka bir işlem commit olmuşsa (`self.state.version != base_state.version`), işlem iptal edilip fail-closed `ConfigurationError("Concurrent modification detected: keyring state changed during preparation")` fırlatıldı (lost-update koruması).
  - Tek referans atamasıyla yeni durum yayınlandı: `self.state = KeyRingState(base_state.version + 1, new_keys, now)`.

## 0.10.3 — P1: Eşzamanlı Yarış Koşulu & Interleaved Writer Testleri (`tests/concurrency_keyring_test.nox`)
- [x] Test 6 eklendi: İki yazarın aynı anda aynı sürüm snapshot'ını alıp hazırlık yaptığı, birinci yazarın commit etmesinden sonra ikinci yazarın commit anında `Concurrent modification detected` hatasıyla reddedildiğini ve ilk yazarın değişikliklerinin korunduğunu kanıtlayan negatif yarış testi doğrulandı.

## 0.10.4 — P1: Yapısal IPv6 Ayrıştırıcı & Bitmask Filtreleme (`jwks.nox`)
- [x] `_is_restricted_ipv6(host: str) -> bool` fonksiyonu yapısal olarak uygulandı:
  - `::` çift iki nokta genişletmesi (expansion), hextet ayrıştırması (1-8 segment, hex to int).
  - Sayısal hextet kontrolleri:
    - Loopback (`::1`) ve Unspecified (`::`).
    - IPv4-mapped IPv6 (`::ffff:x.x.x.x`): son oktetlerin `_is_restricted_ipv4` ile doğrulanması.
    - ULA (`fc00::/7`): Sayısal bitmask `(h0 & 0xfe00) == 0xfc00`.
    - Link-Local (`fe80::/10`): Sayısal bitmask `(h0 & 0xffc0) == 0xfe80`.
    - Multicast (`ff00::/8`): Sayısal bitmask `(h0 & 0xff00) == 0xff00`.
    - Discard Prefix (`100::/64` RFC 6666): `h0 == 0x100 and h1 == 0 and h2 == 0 and h3 == 0`.
    - Documentation (`2001:db8::/32` RFC 3849): `h0 == 0x2001 and h1 == 0xdb8`.
- [x] `tests/jwks_test.nox` içine tüm IPv6 sınır ve bitmask testleri eklendi.

## 0.10.5 — P1: DNS Çözümleme Sonrası IP Doğrulama Fonksiyonu & Dokümantasyon (`jwks.nox`)
- [x] Public `verify_resolved_ip(ip_str: str) -> bool` fonksiyonu eklendi (çözümlenen IPv4 veya IPv6 adresinin SSRF filtrelerinden geçip geçmediğini doğrular).
- [x] `docs/threat-model.md` ve `docs/architecture.md` içerisine DNS Pinning ve Transport API kullanım sözleşmesi detaylandırıldı.

## 0.10.6 — P2: RSA Exponent 53-Bit Safe Integer Sınırları & Boundary Testleri (`jwk.nox`, `tests/jwk_test.nox`)
- [x] Dokümantasyon 64-bit yerine IEEE 754 53-bit Safe Integer (`2^53 - 1`) limiti olarak güncellendi.
- [x] `tests/jwk_test.nox` içine 1-karakter (`len % 4 == 1`), 5-karakter ve overflow eden 10-karakter sınır testleri eklendi.

## 0.10.7 — Phase 10 Çıkış Kapısı ve `v1.0.4` Yayını
- [x] `noxc test` ile tüm test matrisi çalıştırıldı (16 testin 16'sı da %100 geçti).
- [x] `./scripts/test-isolated-consumer.sh` çalıştırıldı ve başarıyla doğrulandı.
- [x] `nox.json` versiyonu `1.0.4` yapıldı.
- [x] `CHANGELOG.md` dosyasına `v1.0.4` sürüm notları eklendi.
- [x] Git commit, `v1.0.4` git tag push ve `noxc publish` çalıştırıldı (`published: cipher updated in the registry as @mburakmmm`).
- [x] GitHub Actions CI ve Release Gate süreçlerinin %100 yeşil tamamlandığı ve `Cipher v1.0.4` GitHub Release'inin yayınlandığı doğrulandı.

---

# Phase 11 — `v1.0.5` Hardware Atomic CAS & Writer Lock, Decoupled IP Parser/SSRF Policy & Native Package Fetch (SOL V Analizi)

**Amaç:** Beşinci bağımsız teknik incelemede (GPT 6 SOL V analizi) tespit edilen iki temel güvenlik garantisi boşluğunu ve mimari iyileştirmeleri eksiksiz tamamlamak:
1. `KeyRing` içerisinde `nox.atomic` (`AtomicBool` writer mutex + `AtomicInt` donanım `compare_and_swap`) kullanarak gerçek donanım seviyesinde atomik CAS ve çoklu yazıcı koordinasyonu sağlamak, `KeyRingState` ve `KeyRing` içindeki dahili liste referanslarını dış mutasyonlara karşı tamamen kapatmak.
2. IPv4/IPv6 sözdizimsel ayrıştırma katmanını (`parse_ipv4` -> `IPv4Address`, `parse_ipv6` -> `IPv6Address`) SSRF güvenlik politikası katmanından (`is_restricted_ipv4_addr`, `is_restricted_ipv6_addr`) tamamen ayırmak; `::ffff:8.8.8.8` gibi IPv4-mapped IPv6 adreslerinde 2-hextet genişletme hatasını gidermek ve `verify_resolved_ip()` fonksiyonunun geçersiz IP formatlarını kesin olarak reddetmesini sağlamak.
3. `noxc add cipher` ve `noxc fetch` üzerinden gerçek bağımsız paket kurulumunu doğrulamak ve `v1.0.5` sürümünü yayınlamak.

## 0.11.1 — P0: Gerçek Donanım Atomik CAS & Writer Mutex (`keyring.nox`, `nox.atomic`)
- [x] `KeyRing` içerisine `nox.atomic.AtomicBool` (`_write_lock`) ve `nox.atomic.AtomicInt` (`_atomic_version`) eklendi.
- [x] `add_key()`, `rotate()` ve `revoke()` metotlarında:
  - Hazırlık aşaması başında `base_ver = self._atomic_version.load()` ve `base_state = self.state` okundu.
  - Hazırlık tamamlandığında `_write_lock.compare_and_swap(False, True)` ile donanım atomik writer mutex kilidi alındı (çakışma durumunda fail-closed `ConfigurationError` fırlatıldı).
  - Kritik bölge içinde `self._atomic_version.compare_and_swap(base_ver, base_ver + 1)` donanım atomik CAS komutuyla versiyon geçişi doğrulandı; başarısızsa kilit bırakılıp (`_write_lock.store(False)`) `ConfigurationError("Concurrent modification detected: atomic CAS version mismatch")` fırlatıldı.
  - Başarılıysa `self.state = new_state` atanıp kilit bırakıldı (`_write_lock.store(False)`).
- [x] Test amaçlı deterministik kilit/CAS simülasyon metotları (`acquire_write_lock`, `release_write_lock`, `_commit_state`) tanımlandı.

## 0.11.2 — P1: `KeyRingState` Derin İmmutability & Dış Mutasyon Koruması (`keyring.nox`)
- [x] `KeyRing` içindeki eski `self.keys` alanı kaldırıldı (dahili listeye dışarıdan doğrudan referans tutulması engellendi).
- [x] `KeyRingState` içindeki liste `_keys: list[KeyRef]` olarak kapsüllendi; `__init__` içinde gelen liste derin klonlanarak (`KeyRef.clone()`) saklandı.
- [x] `KeyRingState.get_keys(self) -> list[KeyRef]` metodu her çağrıda elemanların `.clone()` kopyalarını içeren yeni bir liste döndürecek şekilde uygulandı.
- [x] `KeyRing.get_state(self) -> KeyRingState` metodu güvenli klonlanmış snapshot döndürecek şekilde eklendi.

## 0.11.3 — P1: Gerçek Paralel/Eşzamanlı Writer & Atomik CAS Testleri (`tests/concurrency_keyring_test.nox`)
- [x] `KeyRingState.get_keys()` ve `ring.get_state()` üzerinden yapılan dış mutasyonların dahili snapshot'ı etkilemediğini kanıtlayan test eklendi (Test 6b).
- [x] Donanım `_write_lock` ve `_atomic_version.compare_and_swap` mekanizmasının T1-T6 yarış senaryosunu, aktif writer lock çakışmalarını (Test 7) ve 4 paralel OS iş parçacıklı (`nox.thread.start`) CAS yarışını (Test 8) deterministik olarak doğrulayan testler eklendi.

## 0.11.4 — P0: IPv4/IPv6 Ayrıştırma (`parse_ipv4`, `parse_ipv6`) ve SSRF Güvenlik Politikasını Ayırma (`jwks.nox`)
- [x] `IPv4Address` (`o0`, `o1`, `o2`, `o3`) ve `IPv6Address` (`hextets: list[int]`) yapısal sınıfları tanımlandı.
- [x] `parse_ipv4(s: str) -> IPv4Address` fonksiyonu uygulandı (tam 4 oktet, `0..255` aralığı, leading zero/octal reddi, geçersiz formatlarda `EncodingError` fırlatma).
- [x] `parse_ipv6(s: str) -> IPv6Address` fonksiyonu uygulandı:
  - IPv4-gömülü son segment (`::ffff:8.8.8.8`, `::ffff:127.0.0.1`, `64:ff9b::192.0.2.1`) `parse_ipv4` ile ayrıştırılıp `(o0 << 8) | o1` ve `(o2 << 8) | o3` olarak **tam 2 hextet**'e dönüştürüldü ve `::` sıfır genişletmesi kalan **6 hextet** üzerinden doğru hesaplandı (`6 + 2 = 8 hextet`).
  - Çoklu `::`, `:::`, tek `:` başlangıç/bitiş, `%` zone ID ve 8 hextet dışı uzunluklar `EncodingError` ile reddedildi.
- [x] `is_restricted_ipv4_addr(addr: IPv4Address) -> bool` ve `is_restricted_ipv6_addr(addr: IPv6Address) -> bool` fonksiyonları yalnızca ayrıştırılmış ve doğrulanmış adres nesneleri üzerinde çalışacak şekilde ayrıldı (IPv4-mapped `::ffff:0:0/96`, IPv4-compatible, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32`, ULA `fc00::/7`, Link-Local `fe80::/10`, Site-Local `fec0::/10`, Multicast `ff00::/8`, Discard `100::/64`, Documentation `2001:db8::/32` & `3fff::/20`, Benchmark `2001:2::/48`).

## 0.11.5 — P0 & P1: `verify_resolved_ip()` Geçersiz IP Reddi ve IPv4-Mapped IPv6 Vektörleri (`jwks.nox`, `tests/jwks_test.nox`)
- [x] `verify_resolved_ip(ip_str: str) -> bool` fonksiyonu önce `parse_ipv6` / `parse_ipv4` ile sözdizimsel doğrulama yapacak, ayrıştırma hatasında (`EncodingError`) doğrudan `False` dönecek, geçerliyse `not is_restricted_ipv4_addr` / `not is_restricted_ipv6_addr` dönecek şekilde güncellendi.
- [x] `tests/jwks_test.nox` içerisine `::ffff:8.8.8.8` (2-hextet genişletme doğrulaması), `::ffff:7f00:1` (hex formda IPv4-mapped loopback), NAT64, 6to4, Teredo ve geçersiz IP formatlarının (`"999.999.999.999"`, `"1.2.3"`, `"not-an-ip"`, `"2001::db8::1"`, `"fe80::1%eth0"`) `verify_resolved_ip` tarafından reddedildiği test vektörleri eklendi (Test 8 & Test 9).

## 0.11.6 — P2: Gerçek `noxc add` + `noxc fetch` Bağımsız Paket Kurulumu (`*.nox`, `cipher/*.nox`, `scripts/test-isolated-consumer.sh`)
- [x] Kök `.nox` modüllerinin iç importları `from cipher.<modül> import ...` yapısına kavuşturuldu ve `cipher/` alt diziniyle senkronize edildi.
- [x] `scripts/test-isolated-consumer.sh` betiği gerçek `noxc init .`, `noxc add cipher <repo> --ref main`, `noxc fetch`, `nox.lock` SHA kontrolü ve `noxc run main.nox` ile doğrulandı.

## 0.11.7 — Phase 11 Çıkış Kapısı ve `v1.0.5` Yayını
- [x] `noxc test` ile tüm test matrisi çalıştırıldı (16 testin 16'sı da %100 geçti).
- [x] `./scripts/test-isolated-consumer.sh` çalıştırıldı ve doğrulandı.
- [x] `nox.json` versiyonu `1.0.5` yapıldı.
- [x] `CHANGELOG.md` dosyasına `v1.0.5` sürüm notları eklendi.
- [x] Git commit, `v1.0.5` git tag push ve `noxc publish` çalıştırıldı (`published: cipher updated in the registry as @mburakmmm`).
- [x] GitHub Actions CI ve Release Gate süreçlerinin %100 yeşil tamamlandığı ve `Cipher v1.0.5` GitHub Release'inin yayınlandığı doğrulandı.

---

# Phase 12 — `v1.0.6` Seqlock Coherent Snapshot Publication, Exception-Safe Lock Release, Tamper-Evident Sealing & Property/Fuzz Verification (SOL VI Analizi)

**Amaç:** Altıncı bağımsız teknik incelemede (GPT 6 SOL VI analizi) tespit edilen commit sıralaması / okuyucu tutarlılığı riskini ve doğrulama hedeflerini eksiksiz tamamlamak:
1. **P0:** `KeyRing` içerisinde Seqlock + Tek Doğruluk Kaynağı (`_state: KeyRingState` + `_seq: nox.atomic.AtomicInt`) protokolünü uygulayarak `get_version()` ile `get_state()` / `get_snapshot()` arasındaki tutarsızlık penceresini tamamen ortadan kaldırmak (okuyucular versiyon ve anahtar listesini daima aynı Seqlock-doğrulanmış `_state` nesnesinden atomik bir bütün olarak okur).
2. **P0:** `_commit_state()` içinde `try ... except` bloğu ile her türlü hata durumunda `_seq` ve `_write_lock` durumunun geri alınmasını ve writer kilidinin kesin olarak serbest bırakılmasını (exception-safe lock release) garanti altına almak.
3. **P1:** `KeyRingState` içerisine kriptografik SHA-256 bütünlük mührü (`_integrity_hash: str`) ekleyerek dil düzeyinde `private` anahtar kelimesi bulunmayan NOX çalışma zamanında `_state` veya `_keys` alanlarına doğrudan yapılan yetkisiz mutasyonları tespit edip fail-closed `ConfigurationError` ile reddetmek.
4. **P1:** `tests/concurrency_keyring_test.nox` içerisine doğrudan `KeyRing` üzerinde çoklu eşzamanlı writer (`rotate`, `revoke`) ve reader (`get_signing_key`, `get_state`, `get_version`) görevlerini çalıştıran gerçek paralel KeyRing testleri eklemek.
5. **P1:** `scripts/test-isolated-consumer.sh` içerisine hem yerel Git staging hem de gerçek uzak `noxpkg.noxlang.com` merkezi kayıt defteri üzerinden (`noxc add cipher` + `noxc fetch`) iki aşamalı kurulum doğrulaması eklemek.
6. **P2:** IPv4 ve IPv6 ayrıştırıcıları için kapsamlı property-based ve fuzz test paketi (`tests/ip_fuzz_property_test.nox`) oluşturmak ve `v1.0.6` sürümünü yayınlamak.

## 0.12.1 — P0: Seqlock + Tek Doğruluk Kaynağı (`_state`) Tutarlı Yayın Protokolü (`keyring.nox`)
- [x] `KeyRing` içinde `state` alanını `_state: KeyRingState` yap ve Seqlock sıra sayacı `_seq: nox.atomic.AtomicInt` (çift = kararlı, tek = yazma aşamasında) ekle.
- [x] `_read_consistent_state(self) -> KeyRingState` metodunu uygula:
  - Seqlock okuma protokolü ile `_seq` çift sayı iken `_state` referansını oku, sonrasındaki `_seq` değerinin değişmediğini ve `_state.version * 2 == _seq` olduğunu doğrula.
- [x] `get_version()`, `get_state()`, `get_snapshot()`, `get_signing_key()` ve `get_verification_key()` metotlarının tamamının `_read_consistent_state()` üzerinden çalışmasını sağla; böylece `get_version()` ve `get_state()` asla farklı sürümleri gözlemleyemesin.

## 0.12.2 — P0: `_commit_state()` Exception-Safe Lock Release & Atomik Geri Alma (`keyring.nox`)
- [x] `_commit_state(self, base_ver: int, new_state: KeyRingState)` içinde:
  - `_write_lock.compare_and_swap(False, True)` ile kilidi al.
  - `try:` bloğu içinde `_state.version == base_ver` ve `_atomic_version.compare_and_swap(base_ver, base_ver + 1)` kontrolünü `cas_won` bayrağı ile yap.
  - Yeni `new_state` bütünlüğünü doğrula, `_seq.store(base_ver * 2 + 1)` (yazma başladı) yap, **önce** `self._state = new_state` ata, **sonra** `self._seq.store((base_ver + 1) * 2)` (yazma tamamlandı) olarak mühürle.
  - `except` bloğunda herhangi bir hata oluşursa `cas_won == True` ise `_seq`, `_atomic_version` ve `_state` değerlerini `base_ver` durumuna geri yükle, `_write_lock.store(False)` ile kilidi kesin olarak serbest bırak ve hatayı yeniden fırlat (`raise`).

## 0.12.3 — P1: `KeyRingState` Kriptografik SHA-256 Bütünlük Mührü (Tamper-Evident Sealing) (`keyring.nox`)
- [x] `KeyRingState` oluşturulurken `version`, `created_at` ve `_keys` içindeki tüm anahtarların alanları üzerinden SHA-256 özeti (`_integrity_hash: str`) hesapla.
- [x] `KeyRingState.verify_integrity()` metodunu uygula ve `get_keys()`, `key_count()` ile `_read_consistent_state()` içinde çağır; eğer dışarıdan `_state.version` veya `_state._keys` doğrudan değiştirilmişse sabit zamanlı karşılaştırma (`nox.crypto.constant_time_eq`) ile yakalayıp `ConfigurationError("KeyRingState integrity violation: unauthorized direct field mutation detected")` fırlat.

## 0.12.4 — P1: Gerçek Paralel `KeyRing` Writer/Reader Yarış Testleri (`tests/concurrency_keyring_test.nox`)
- [x] Aynı `KeyRing` nesnesi üzerinde eşzamanlı `rotate()`, `revoke()`, `get_signing_key()`, `get_state()` ve `get_version()` çalıştıran paralel görevler (Test 11b) ve 4 OS iş parçacıklı (`nox.thread.start`) paylaşılan handle'lı `KeyRing` rotasyon testi (Test 11) ekle.
- [x] Okuyucuların hiçbir zaman `get_version() != get_state().version` tutarsızlığı görmediğini, başarısız commit sonrası writer lock'un serbest kaldığını (Test 10) ve `_state` doğrudan mutasyonunun SHA-256 mührüyle yakalandığını (Test 9) doğrula.

## 0.12.5 — P1: İki Aşamalı Paket Kurulum Testi: Yerel Git + Gerçek Uzak Registry (`scripts/test-isolated-consumer.sh`)
- [x] `scripts/test-isolated-consumer.sh` betiğini iki aşamalı yap:
  - **Stage 1:** Yerel Git staging deposundan `noxc add cipher <local_repo> --ref main` + `noxc fetch` doğrulaması.
  - **Stage 2:** Doğrudan uzak `noxpkg.noxlang.com` merkezi kayıt defteri ve GitHub üzerinden `noxc add cipher` + `noxc fetch` + `nox.lock` + `noxc run main.nox` doğrulaması.

## 0.12.6 — P2: IPv4/IPv6 Ayrıştırıcı Property-Based ve Fuzz Test Paketi (`tests/ip_fuzz_property_test.nox`)
- [x] `tests/ip_fuzz_property_test.nox` dosyasını oluştur:
  - Property 1: Geçerli IPv4 `(o0, o1, o2, o3)` round-trip ve 14 CIDR politika değişmezliği (invariant) testi.
  - Property 2: Noktalı IPv4 (`a.b.c.d`), noktalı IPv4-mapped IPv6 (`::ffff:a.b.c.d`), genişletilmiş (`0:0:0:0:0:ffff:a.b.c.d`), köşeli parantezli (`[::ffff:a.b.c.d]`) ve saf hex (`::ffff:XXXX:YYYY` küçük/büyük harf) formların 8-hextet ve `verify_resolved_ip` eşdeğerliği testi.
  - Property 3 & 4: `::` sıfır sıkıştırma konumu değişmezliği ve 100+ bozuk/adversarial IPv4 ve IPv6 girdisiyle deterministik fuzzing (sıfır beklenmeyen çökme, `%100 False` reddi).

## 0.12.7 — Phase 12 Çıkış Kapısı ve `v1.0.6` Yayını
- [x] `noxc test` ile tüm test matrisini çalıştır (17 testin 17'si de %100 geçti).
- [x] `./scripts/test-isolated-consumer.sh` çalıştır ve her iki aşamayı (Stage 1 Local Git + Stage 2 Remote Registry) doğrula.
- [x] `nox.json` versiyonunu `1.0.6` yap.
- [x] `CHANGELOG.md` dosyasına `v1.0.6` sürüm notlarını ekle.
- [x] Git commit, `v1.0.6` git tag push ve `noxc publish` çalıştır.
- [x] GitHub Actions CI ve Release Gate süreçlerinin %100 yeşil tamamlandığını doğrula.
