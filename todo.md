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
- [ ] `KeyState` enum/tipleri:
  - `PREPARED`: Doğrulayıcılara dağıtılmış, henüz imzalama yapmayan yeni anahtar.
  - `ACTIVE_SIGNING`: Güncel imzalama anahtarı (her güven alanı için en fazla bir aktif).
  - `VERIFY_ONLY`: Eski token'ları doğrulamak için tutulan, imza atmayan anahtar.
  - `RETIRED`: Süresi dolmuş, kullanım dışı anahtar.
  - `REVOKED`: Güvenliği ihlal edilmiş, anında reddedilmesi gereken anahtar.
- [ ] Geçerli ve geçersiz durum geçiş kuralları (state machine invariants).

## 0.4.2 — Keyring ve Güven Etki Alanı İzolasyonu (`keyring.nox`)
- [ ] `KeyRing` sınıfı:
  - `trust_domain` ayrımı (kiracı veya servis izolasyonu).
  - Tekil `kid` indekslemesi; mükerrer `kid` durumunda `AmbiguousKeyError`.
  - İmzacı seçimi: Yalnızca `ACTIVE_SIGNING` ve `use="sig"` durumundaki anahtar kullanılabilir.
  - Doğrulayıcı seçimi: Yalnızca `ACTIVE_SIGNING` veya `VERIFY_ONLY` durumundaki anahtar kullanılabilir.
  - `REVOKED` durumundaki bir anahtarla gelen token derhal `InvalidSignatureError` / `KeyRevokedError` ile reddedilir.

## 0.4.3 — Atomik Rotasyon ve Güvenli Örtüşme (Overlap) Mekanizması
- [ ] `KeyRing.rotate(...)`:
  - Yeni anahtarı `ACTIVE_SIGNING` yapma.
  - Eski anahtarı güvenli örtüşme süresi boyunca (`token_lifetime + leeway + propagation`) `VERIFY_ONLY` durumuna çekme.
  - Acil durum ihlali (compromise): Örtüşme beklemeden anında `REVOKED` etme.
- [ ] Rotasyon makbuzu (`RotationReceipt`) ve denetim log kayıtları (özel anahtar sızdırmadan).

## 0.4.4 — Phase 4 Test Matrisi ve Çıkış Kapısı
- [ ] `tests/keyring_test.nox`:
  - Yaşam döngüsü durum geçiş testleri.
  - Rotasyon sonrası eski token'ların doğrulanabilmesi testleri.
  - Emekli (`RETIRED`) veya feshedilmiş (`REVOKED`) anahtarların ret testleri.
  - Multi-tenant / farklı trust domain anahtar karışmama testleri.
- [ ] `noxc check` ve `noxc test` tam geçti.
- [ ] `CHANGELOG.md` güncellendi ve sürüm etiketi `v0.4.0` hazırlandı.

---

# Phase 5 — `v0.5.x` Uzak JWKS Kaynağı ve Dayanıklılık (Opt-in)

**Amaç:** Güvenilir uzak HTTPS JWKS uç noktalarından açık anahtarları güvenli, önbellekli ve SSRF korumalı şekilde alan bileşeni (JWKS Source) geliştirmek.

## 0.5.1 — Güvenli Uzak JWKS Alıcısı (`jwks.nox`)
- [ ] Yalnızca yapılandırılmış, izin verilen HTTPS URL'leri (asla belirteç başlığındaki `jku`/`x5u` takip edilmez!).
- [ ] SSRF ve ağ korumaları:
  - Localhost (`127.0.0.1`, `::1`), private IP aralıkları (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), link-local (`169.254.169.254`) adreslerine erişimin kesin olarak engellenmesi.
  - Yanıt boyutu (max 1MB) ve zaman aşımı limitleri.

## 0.5.2 — Önbellekleme, Hız Sınırlama ve Dayanıklılık (`jwks.nox`)
- [ ] Bounded Cache: TTL tabanlı önbellek yönetimi.
- [ ] Bilinmeyen `kid` durumunda negatif önbellekleme (negative caching) ile fetch storm saldırılarının önlenmesi.
- [ ] Throttling / Rate limiting: Arka arkaya tetiklenen anahtar çekme isteklerinin sınırlandırılması.
- [ ] Kesinti (outage) yönetimi: Uzak sunucu çöktüğünde güvenilir bayat (stale) penceresi sınırları.

## 0.5.3 — Phase 5 Test Matrisi ve Çıkış Kapısı
- [ ] `tests/jwks_test.nox`:
  - SSRF denemeleri (özel IP, redirect saldırıları).
  - Bilinmeyen `kid` ile fetch fırtınası simülasyonu.
  - Ağ kesintisi ve bayat önbellek sınır testleri.
- [ ] `noxc check` ve `noxc test` tam geçti.
- [ ] `CHANGELOG.md` güncellendi ve sürüm etiketi `v0.5.0` hazırlandı.

---

# Phase 6 — `v1.0.0` Ekosistem Adaptörleri, Sentinel Sözleşmesi ve Kararlı Sürüm

**Amaç:** Sentinel ve Nyx/Aether sınır adaptörlerini hazırlamak, dokümantasyonu tamamlamak, tüm release gate koşullarını yerine getirerek kararlı `v1.0.0` sürümünü yayımlamak.

## 0.6.1 — Sentinel Entegrasyon Adaptörü (`examples/sentinel_adapter.nox`)
- [ ] Sentinel Sözleşmesi kanıtı:
  - Cipher bir token'ı doğrular ve `VerifiedJwt` döner.
  - Token geçerli bir imzaya sahip olmasına rağmen, Sentinel politikasına (rol, kapsam, yetki) göre erişimin reddedildiğini gösteren çalışan örnek ve test.
  - Cipher'ın hiçbir zaman yetkilendirme kararı (`allow`/`deny`) vermediğinin kanıtlanması.

## 0.6.2 — Kamu API İhracı ve Dokümantasyon (`cipher.nox`)
- [ ] Temiz ve ergonomik tekil kamu export modülü (`cipher.nox`).
- [ ] Dokümantasyon setinin tamamlanması:
  - `docs/architecture.md`
  - `docs/algorithms.md`
  - `docs/key-management.md`
  - `docs/security-review.md`
  - `docs/sentinel-boundary.md`

## 0.6.3 — Performans Kıyaslama ve Fuzz Testleri
- [ ] İmzalama ve doğrulama mikro kıyaslamaları (`benchmarks/`).
- [ ] Fuzz test senaryoları (bozuk baytlar, bellek taşmaları, anormal JSON).

## 0.6.4 — Phase 6 & v1.0.0 Son Çıkış Kapısı (Definition of Done)
- [ ] [ ] Tüm NOX derleyici, stdlib ve FFI yetenekleri doğrulandı ve dokümante edildi.
- [ ] [ ] Kod gerçek `noxc` ile derlendi ve Darwin arm64 üzerinde doğrulandı.
- [ ] [ ] API tamamen tipli, bağımsız ve kimlik/yetki karışıklığına izin vermez yapıda.
- [ ] [ ] `alg=none`, alg confusion, remote-header fetch, duplicate JSON anahtarı kesinlikle reddedildi.
- [ ] [ ] Tüm desteklenen algoritmalar resmi test vektörlerinden geçti.
- [ ] [ ] JWT claims doğrulama taşma, skew, issuer, audience ve format sınırlarını eksiksiz yönetti.
- [ ] [ ] Anahtar dışa aktarımı hiçbir zaman gizli malzeme sızdırmadı; rotasyon testleri geçti.
- [ ] [ ] Sentinel sınırı çalışan test ile kanıtlandı (geçerli imza != yetki).
- [ ] [ ] Hiçbir taslak (stub), mock veya atlanmış test üretim sürümü olarak sunulmadı.
- [ ] [ ] `CHANGELOG.md` ve `VERSIONING.md` güncellenerek `v1.0.0` hazırlandı.

---

## 3. Günlük Kanıt Kayıtları

*(Her sürüm ve adım tamamlandığında çalıştırılan terminal komutları, test çıktıları ve commit referansları buraya işlenecektir.)*

- **2026-11-10:** `AGENTS.md` analiz edildi, sürüm takip planı (`todo.md`) oluşturuldu. Platform gereksinimleri ve NOX 2.1.0 compiler doğrulamaları kaydedildi.
