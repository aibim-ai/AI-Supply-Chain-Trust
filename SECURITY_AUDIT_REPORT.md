# 🔒 AI Supply Chain Trust — Public Release Security Audit

**Tarih:** 2026-07-15
**Denetçi:** CyberStrike AI Security Agent
**Kapsam:** Tam kaynak kodu, git geçmişi, CI/CD, Docker, altyapı konfigürasyonu
**Depo:** `aibim-ai/AI-Supply-Chain-Trust`
**Risk Seviyesi:** 🔴 **ELEŞTİREL — Public release öncesi aksiyon gerekli**

---

## 📊 Bulgular Özeti

| Seviye | Sayı |
|--------|------|
| 🔴 ELEŞTİREL | 1 |
| 🟠 YÜKSEK | 2 |
| 🟡 ORTA | 3 |
| 🟢 DÜŞÜK / BİLGİ | 6 |
| **Toplam** | **12** |

---

## 🔴 ELEŞTİREL BULGU

### CRITICAL-1: Canlı GitHub PAT `.env` ve `.env.prod` dosyalarında

**Dosyalar:** `.env`, `.env.prod`
**Token:** `ghp_xxx_REDACTED (iptal edildi)`

```
GITHUB_TOKEN=ghp_xxx_REDACTED (iptal edildi)
AI_REPO_TRUST_GITHUB_TOKEN=ghp_xxx_REDACTED (iptal edildi)
```

**Durum:**
- ✅ `.gitignore` doğru yapılandırılmış (`.env` ve `.env.*` ignore ediliyor)
- ✅ Git geçmişinde bu dosyalar YOK
- ✅ `.dockerignore` ve `.gcloudignore` bu dosyaları dışlıyor
- ❌ **Token hala canlı ve geçerli!** Aynı token hem dev hem prod için kullanılıyor

**Risk:** Token sızdırılırsa (disk erişimi, yanlışlıkla `git add -f`, backup sızıntısı) tüm GitHub hesabına erişim sağlanır.

**Aksiyon:**
```bash
# 1. GitHub'da token'ı İPTAL ET
# https://github.com/settings/tokens → "AI Repo Trust" token → Revoke

# 2. Yeni token oluştur (minimum yetki: public_repo, read:org)
# https://github.com/settings/tokens/new

# 3. .env ve .env.prod dosyalarını güncelle
# 4. CI/CD secrets'i güncelle (GitHub Actions → Secrets)
```

---

## 🟠 YÜKSEK BULGULAR

### HIGH-1: `CorsLayer::permissive()` — Tüm origin'lere açık CORS

**Dosya:** `backend/crates/server/src/lib.rs:352`
**Kod:**
```rust
.layer(CorsLayer::permissive())
```

**Durum:** Bu konfigürasyon **tüm origin'lerden** gelen isteklerin API'ye erişmesine izin veriyor. Public API için kasıtlı olabilir ancak:
- Cookie/session tabanlı auth olsaydı kritik olurdu
- API zaten auth gerektirmeyen public endpoint'lerden oluşuyor
- Admin endpoint'leri `require_worker_token()` ile korunuyor

**Öneri:** `env.example`'daki `AI_SUPPLY_CHAIN_TRUST_ALLOWED_ORIGINS` değişkeni kullanılarak production'da explicit origin listesi yapılandırılmalı. Şu an `env.example`'da `*` olarak ayarlanmış.

### HIGH-2: Aynı GitHub token dev ve prod ortamlarında paylaşılıyor

**Dosyalar:** `.env` ve `.env.prod` aynı token'ı içeriyor.

**Risk:** Bir ortamda token sızarsa diğer ortam da etkilenir. Token scope'u aşırı geniş olabilir.

**Aksiyon:**
- Production için ayrı bir GitHub token oluştur (minimum yetki)
- Development için ayrı bir GitHub token oluştur
- Production token sadece CI/CD secrets üzerinden enjekte edilsin, `.env.prod` dosyasında tutulmasın

---

## 🟡 ORTA BULGULAR

### MEDIUM-1: `Command::new()` kullanıcı kontrollü path ile çalışıyor

**Dosya:** `backend/crates/scanner_runner/src/lib.rs:160,170,317`
**Kod:**
```rust
let path = self.source_path.as_deref().unwrap_or(".");
// ...
let output = run_cmd("gitleaks", &["detect", "--source", path, "--no-git", "-f", "json"], ...);
```

**Analiz:**
- `source_path` doğrudan `ServerRunner::with_source()` ile geliyor
- Binary isimleri sabit enum'dan (`ScannerTool`) geliyor — injection mümkün değil
- Path'in var olup olmadığı kontrol ediliyor (`Path::new(path).exists()`)
- Ancak **symlink attack** veya **path traversal** riski tam olarak elimine edilmemiş

**Öneri:**
```rust
let path = std::fs::canonicalize(self.source_path.as_deref().unwrap_or("."))?;
// Canonicalize path traversal'ı önler ve symlink'leri çözer
```

### MEDIUM-2: `SECURITY.md`'de referans verilen script mevcut değil

**Dosya:** `SECURITY.md` (line ~35)
**Referans:** `scripts/check_secret_expiry.py`

Bu script repository'de bulunmuyor. CI'da çalışması beklenen bir kontrol eksik.

**Aksiyon:** Script'i oluşturun VEYA dokümantasyondan referansı kaldırın.

### MEDIUM-3: Tek `CODEOWNER` — Bus-factor riski

**Dosya:** `.github/CODEOWNERS`
```
* @r1z4x
```

Single point of failure. Public repo'da en az 2 reviewer olması önerilir.

---

## 🟢 DÜŞÜK / BİLGİ BULGULARI

### LOW-1: `chmod 777 /data` — Dünya tarafından yazılabilir veri dizini

**Dosya:** `backend/Dockerfile:21`
```dockerfile
RUN mkdir -p /data && chmod 777 /data
```

Container `USER nobody` olarak çalışıyor, bu yüzden yazma izni gerekli. Ancak `chmod 777` yerine `chown nobody /data && chmod 700 /data` daha güvenli.

### LOW-2: `safe.directory=*` git konfigürasyonunda

**Git config:** `safe.directory=*`

Git'in dizin sahipliği kontrolünü tamamen devre dışı bırakır. Geliştirme ortamında yaygın ama güvenlik riski taşır.

### LOW-3: Frontend Dockerfile `root` kullanıcısı

**Dosya:** `frontend/Dockerfile:13`
```dockerfile
FROM nginx:alpine
```

Nginx base image varsayılan olarak root çalışır (nginx master process), worker process'ler `nginx.conf` içinde `nginx` kullanıcısına düşürülür. Bu kabul edilebilir standart bir pratiktir.

### LOW-4: 50 unreachable git objesi

**Durum:** `git fsck --unreachable` 50 obje buldu. Bunlar force-push ve amend operasyonlarından kalan "zombi" objeler.

**Risk:** Bu objeler içinde eski `.env` kalıntısı olabilir. `git gc --prune=now` ile temizlenmeli.

### INFO-1: Geliştirme nginx.conf'unda güvenlik header'ları yok

**Dosya:** `frontend/nginx.conf`

Production nginx konfigürasyonunda (`deploy/production/nginx.conf`) tüm güvenlik header'ları mevcut (HSTS, X-Content-Type-Options, X-Frame-Options). Frontend geliştirme nginx.conf'unda bunlar yok — geliştirme ortamı için kabul edilebilir.

### INFO-2: `.cache/` içinde SQLite veritabanı var

**Dosya:** `backend/.cache/ai-repo-trust/verify.db`

Gitignored durumda. İçeriğinde `scan_jobs`, `evaluations`, `audit_events` gibi tablolar var. Public repoya pushlanmamış, güvende.

---

## ✅ POZİTİF BULGULAR

Güvenlik açısından iyi uygulanmış noktalar:

| Alan | Durum |
|------|-------|
| **SQL Injection** | ✅ Tüm sorgular parametrize — `rusqlite::params![]` ve `sqlx` binding |
| **XSS (Server-side)** | ✅ `esc()` fonksiyonu ile tüm render output'ları HTML-escape ediliyor |
| **Hardcoded Secret (kod içi)** | ✅ Üretim kodunda hiçbir secret yok |
| **`.gitignore`** | ✅ `.env`, `.env.*`, `.cache/`, `runs/`, `target/` dahil, kapsamlı |
| **`.gitleaks.toml`** | ✅ Varsayılan kurallar + README için allowlist |
| **JWT Auth** | ✅ Constant-time karşılaştırma, scope/audience/issuer doğrulama |
| **Rate Limiting** | ✅ IP-bazlı (10 scan/gün), feedback (3/10dk), semaphore (4 concurrent) |
| **Worker Auth** | ✅ Tüm admin endpoint'leri `require_worker_token()` ile korunuyor |
| **Input Validation** | ✅ `validate_repo()` ile sıkı GitHub owner/repo validasyonu |
| **Docker** | ✅ Non-root user (`USER nobody`), multi-stage build |
| **CI/CD** | ✅ `persist-credentials: false`, pinned commit SHA, minimal permissions |
| **HTTPS** | ✅ Production: TLS 1.2+, HSTS 1 yıl, güvenlik header'ları |
| **LLM Guard** | ✅ Hallucination tespiti, output validation, response limit |
| **Token Redaction** | ✅ Upstream hata mesajlarındaki token'lar sanitize ediliyor |
| **Bot PR Reddi** | ✅ `security-independence.yml` bot PR'ları reddediyor |
| **Security Independence** | ✅ Hardcoded metric ve third-party referansları kontrol eden CI guard |
| **Bug Report Template** | ✅ Public issue'larda güvenlik açığı bildirilmemesi uyarısı |

---

## 📋 ÖNCELİKLİ AKSİYON PLANI

### Public Release Öncesi (Engelleyici)

1. **[CRITICAL]** GitHub token'ı **derhal iptal et** ve yeniden oluştur
   ```bash
   # Settings → Developer settings → Personal access tokens → Revoke
   # Yeni token: public_repo, read:org scope'larıyla
   ```

2. **[HIGH]** Dev ve prod için ayrı token'lar oluştur
   ```
   Dev:  GITHUB_TOKEN (CI secrets: DEV_GITHUB_TOKEN)
   Prod: GITHUB_TOKEN (CI secrets: PROD_GITHUB_TOKEN)
   ```

3. **[MEDIUM]** `chmod 777 /data` → `chown nobody:nogroup /data && chmod 700 /data`

### İlk Hafta İçinde

4. **[MEDIUM]** `check_secret_expiry.py` script'ini oluştur VEYA SECURITY.md'den referansı kaldır
5. **[LOW]** `git gc --prune=now` ile unreachable objeleri temizle
6. **[MEDIUM]** `source_path` için `std::fs::canonicalize()` ekle

### İlk Ay İçinde

7. **[HIGH]** Production CORS'u `AI_SUPPLY_CHAIN_TRUST_ALLOWED_ORIGINS` ile yapılandır
8. **[MEDIUM]** En az bir backup CODEOWNER ekle
9. **[LOW]** `safe.directory=*` yerine proje bazlı safe.directory ayarla

---

## 🎯 Genel Değerlendirme

**Kod kalitesi ve güvenlik bilinci yüksek.** Parametrize SQL, HTML escaping, JWT doğrulama, rate limiting, LLM guard, CI security gate'leri, Docker non-root — hepsi doğru uygulanmış.

Tek kritik bulgu: **disk üzerindeki canlı token.** Bu, public release öncesi mutlaka çözülmeli. `.gitignore` doğru olsa da, token'ın varlığı tek başına bir risktir.

Git geçmişi temiz — hiçbir secret commit'lenmemiş. CI/CD pipeline'ı güvenli. Kodun kendisinde exploitable zafiyet bulunamadı.

**Public release için kritik engel token rotasyonu. Bunun dışında güvenli.**
