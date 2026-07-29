# Depx Karşılaştırması ve Discovery Akış Analizi — 2026-07-30

Referans: [projectdiscovery/depx](https://github.com/projectdiscovery/depx), `dev` branch, audit sırasında klonlanan durum.

## Sonuç

Eski discovery akışı gerçek anlamda yeni GitHub reposu bulmuyordu. Worker varsayılanı kapalıydı; çalışsa bile yalnızca son güncellenen, son yedi günde push almış, en az 500 yıldızlı sekiz sabit konuyu arıyordu. Bu filtre yeni repoları pratikte sıfıra yakın indirdi. CLI ve `daemon` yolları da farklı ve hatalı davranıyordu.

Bu turda akış düzeltildi ve gerçek GitHub ile doğrulandı: yeni repo bulundu, queue'ya girdi, tarandı ve kalıcı SQLite raporu oluştu.

## Depx Ne Yapıyor, Bizden Farkı Ne?

| Alan | Depx | AI Repo Trust bugün | Açık |
|---|---|---|---|
| Ürün odağı | Bilinen kötü amaçlı package istihbaratı ve dependency audit | GitHub repo güven skoru, evidence/context | Aynı ürün değil; Depx skor motorunun yerine geçmez |
| GitHub kapsamı | Açık repo veya org hedefi; GitHub dependency-graph SBOM export | Konu tabanlı yeni GitHub repo keşfi, sonra tam repo değerlendirmesi | Org/repo hedefli SBOM audit yok |
| Hedef seçimi | Açık hedef, token varsa daha büyük limit, token yoksa düşük limit | Yeni oluşturulmuş GitHub repo, yıldız ve global cycle limiti | Kullanıcı/org hedef listesi ve allowlist yok |
| Paket riski | OpenSSF Malicious Packages lokal index, hızlı verdict | OSV/NVD/GitHub intelligence; tam package-malware index yok | Yüksek öncelik: Depx benzeri malicious-package feed/index entegrasyonu |
| İşletim | Lokal cache/background sync, net CLI exit contract, SARIF | SQLite queue, recovery/evidence workers, API/CLI | Discovery cycle geçmişi, kaynak/aday/açıklama kalıcılığı zayıf |
| Hata davranışı | Upstream unavailable için ayrı exit code | Queue retry/backoff var | Discovery başarı/boş sonuç/rate-limit metriği ayrı değil |

Depx'ten alınması gereken prensipler: hedef kapsamını açık tutmak, token/rate limit bütçesini görünür yapmak, package verisini repo verisinden ayırmak, export/CI sözleşmesini stabil tutmak. Depx'i doğrudan kopyalamak doğru değil: Depx package-malware aracı, bu proje repo-trust değerlendirme ürünü.

## Bulunan ve Düzeltilen Kırıklar

| ID | Eski davranış | Etki | Düzeltme | Kanıt |
|---|---|---|---|---|
| DISC-001 | `serve` yalnız `AI_SUPPLY_CHAIN_TRUST_DAEMON=1` iken worker başlatıyor; Docker bunu vermiyordu | Yayınlanan image yeni repo bulmuyor/taramıyordu | Docker image worker varsayılanı `1`; env örneği API-only replica için `0` bırakıyor | `backend/Dockerfile`, server canlı doğrulama |
| DISC-002 | "recent" sorgusu `pushed:>=`, `sort=updated`, `min_stars=500` | Yeni repo yerine eski popüler repo aranıyor; çoğu cycle boş | `created:>=`, `sort=created`, varsayılan minimum 5 yıldız | Discovery unit test + gerçek GitHub sonucu |
| DISC-003 | Aynı repo birden fazla topic'ten tekrar gelebiliyordu; server limiti topic başınaydı | Yanlış queue sayısı ve gereksiz kapasite tüketimi | Case-insensitive tekilleştirme, cycle başına global `take(limit)` | `discovery_candidates_keep_unique_valid_github_repositories` |
| DISC-004 | `discover --min-stars/--days` değerleri yok sayılıyor, score service token olmadan yaratılıyordu | CLI beklenmedik eski repo buluyor; tokenlı tarama anonime düşüyor | Filtreleri gerçek GitHub discovery sorgusuna bağla; service'e token ver | Gerçek `discover` taraması ve DB kalıcılığı |
| DISC-005 | `daemon` `discover_all` ile `pypi:*`/`hf:*` değerlerini GitHub repo taramasına veriyor; `queue_poll_interval` kullanılmıyordu | Geçersiz işler, discovery ve queue zinciri farklı | Daemon yalnız canonical GitHub repo queue'lar; poll interval queue worker'ı çalıştırır | Daemon canlı doğrulama |

## Canlı Kanıt

1. `discover --no-score --min-stars 0 --days 30` gerçek GitHub'dan 15 tekil yeni aday buldu; ilk dört aday `Optim-Agent/optim-agent`, `arcships/light-ocr`, `egeorcun/lucida`, `lucidrains/x-jepa` idi.
2. `discover --max-total 1` gerçek `Optim-Agent/optim-agent` reposunu taradı ve geçici DB'de `scans_total: 1`, `unique_repos: 1` üretti.
3. `serve` worker ile: 7 aday bulundu, global limit ile 1 aday queue'landı, `Optim-Agent/optim-agent` için scan/persistence loglandı; DB `unique_repos: 1` gösterdi.
4. `cargo test --workspace --all-targets` geçti. Altı GitHub-token bağımlı canlı test beklenen şekilde ignored.

## Kalan Ürün Eksikleri

1. **Kapatıldı (online evidence):** GitHub Dependency Graph SPDX SBOM exportu, sürümlü third-party purl normalizasyonu ve en fazla 250 purl için OSV `querybatch` eklendi. OpenSSF malicious-packages `MAL-*` kaydı eşleşirse rapor açık `supply_chain` critical flag ile F'ye zorlanır. SBOM kapalı/erişilemezse durum `unavailable`; temiz sonuç üretilmez. Deterministic HTTP fixture ve gerçek OSV sorgusu doğrulandı. Tam yerel feed mirror/cache henüz yok; bu bilinçli olarak ayrı bir ölçek/availability iyileştirmesidir.
2. **Kapatıldı:** Her discovery cycle ve aday artık source, açıklama, yıldız, cycle id, disposition/reddedilme nedeni ve bağlı scan job ile SQLite'a kalıcı yazılır. `/api/v1/discovery/cycles` operatör görünürlüğünü sağlar.
3. **Kapatıldı:** Cycle `found`, `eligible`, `queued`, `existing`, `failed` sayaçlarını ve yapılandırmayı kalıcı tutar; API metrikleri ile Prometheus `discovery_queued_today` göstergesini verir. Deterministik storage regresyon testi vardır.
4. **Kısmen kapatıldı:** `AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVERY_TOPICS` ile en fazla 20 doğrulanmış topic yönetilebilir; cycle configi kullanılan listeyi kalıcı gösterir. Org allowlist ile dil/license/archived/fork filtreleri, ürün kapsamı netleştiğinde ayrı hedefleme politikası olarak eklenmelidir.
5. **Kapatıldı:** `/healthz`, gerçek storage bağlantısını denetler; daemon discovery açıkken GitHub token yoksa readiness başarısız olur. Worker token olmadan discovery başlatmaz; `AI_SUPPLY_CHAIN_TRUST_DAEMON_DISABLE_DISCOVERY=1` ile bilinçli olarak kapatılabilir.
6. **Kapatıldı:** Discovery günlük queue bütçesi, atomik queue kapasitesi ve kill switch ile sınırlandırılır; kullanılan bütçe cycle ve Prometheus metriklerinde görünür.
7. **Kapatıldı:** Server worker cycle, yerel deterministic GitHub HTTP fixture ile doğrulanır: oluşturulmuş sorgu, kalıcı cycle sayaçları/config ve queue job aynı testte denetlenir (`discovery_cycle_persists_mocked_github_candidate_and_queue_job`).

## Operasyon Ayarı

Tek worker-capable instance:

```bash
GITHUB_TOKEN=... \
AI_SUPPLY_CHAIN_TRUST_DAEMON=1 \
AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVER_LIMIT=10 \
AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVER_DAYS=7 \
AI_SUPPLY_CHAIN_TRUST_DAEMON_DISCOVER_MIN_STARS=5 \
cargo run -p ai-supply-chain-trust -- serve
```

Diğer API replica'larında `AI_SUPPLY_CHAIN_TRUST_DAEMON=0` kalmalı. Aynı SQLite dosyasını birden çok bağımsız host paylaşmak doğru deployment modeli değildir; çok worker için Postgres/queue backend gerekir.
