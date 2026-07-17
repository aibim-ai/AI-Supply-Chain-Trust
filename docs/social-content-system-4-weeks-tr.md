# AI Supply Chain Trust — 4 Haftalık LinkedIn ve X İçerik Sistemi

**Yayın dönemi:** 20 Temmuz–16 Ağustos 2026
**Saat dilimi:** Europe/Istanbul
**Birincil hedef:** Güvenlik bilincine sahip geliştiricileri, coding-agent geliştiricilerini ve AppSec/Platform ekiplerini ücretsiz public repository taramasına taşımak.
**Birincil CTA:** “Public repository’yi tara.”
**Editoryal ilke:** Gözlenen kanıt, çıkarım ve eksik kanıt ayrı tutulur. Hiçbir içerik “güvenli”, “vulnerability-free”, “onaylandı” veya “tam kapsama” iddiası kurmaz.

## 1. Sistemin çalışma biçimi

### Haftalık ritim

| Gün | Saat | Kanal / format | Görev |
|---|---:|---|---|
| Pazartesi | 10:30 | LinkedIn post 1 | Haftanın karar çerçevesi |
| Salı | 12:30 | X post 1 | Tek, keskin içgörü |
| Çarşamba | 10:30 | LinkedIn post 2 | Kanıt veya olay incelemesi |
| Çarşamba | 18:30 | X thread | Adım adım yöntem / kanıt zinciri |
| Perşembe | 12:30 | X post 2 | Eksik kanıt veya ürün prensibi |
| Cuma | 10:30 | LinkedIn carousel | Kaydedilebilir çerçeve veya demo walkthrough |
| Cuma | 16:30 | Ürün demosu | 60–90 saniye, kesintisiz gerçek ekran kaydı |
| Cumartesi | 12:00 | X post 3 | Demo bulgusu / açık soru |

Saatler başlangıç hipotezidir. İki hafta sonra yayın saati değil; hook türü, format ve CTA bazında sonuç okunmalıdır.

### İçerik sütunu dağılımı

| Sütun | Dört haftadaki ana rol |
|---|---|
| Repository due diligence | Haftalar 1 ve 3; intake kararı, ilk inceleme soruları |
| Coding-agent ve MCP güvenliği | Hafta 2; agent eyleminden önce trust gate |
| Gerçek supply-chain olayları | Haftalar 2 ve 3; XZ Utils ve GitHub Actions örüntüsü |
| Explainable security ve missing evidence | Her hafta; özellikle 1 ve 4 |
| Ürün geliştirme / open-source journey | Hafta 4; mimari prensipler ve ölçümler |

### UTM standardı

- `utm_source`: `linkedin` veya `x`
- `utm_medium`: `organic_social`
- `utm_campaign`: `trust_system_w01` … `trust_system_w04`
- `utm_content`: hafta + kanal + format + konu; ör. `w01_li01_stars_not_evidence`
- Link, içerikte tek dönüşüm hedefidir. LinkedIn’de ana metni temiz tutmak için link ilk yoruma da alınabilir; UTM değişmez.

### “No invented evidence” yayın kapısı

Her içerik yayınlanmadan önce şu beş kontrol uygulanır:

1. Sayısal iddianın yanında rapor, API veya birincil kaynak URL’si var mı?
2. `0 CVE` ifadesi yanlışlıkla “CVE yok” veya “güvenli” diye çevrilmiş mi? Doğru ifade: “Bu raporda 0 CVE referansı kaydedildi.”
3. Eksik veya erişilemeyen veri, olumlu kanıt gibi kullanılmış mı?
4. Bir olay incelemesinde saldırgan niyeti, etki alanı veya kök neden kaynağın söylediğinden ileri taşınmış mı?
5. Ekran görüntüsü yayın günü yenilenmiş mi? Rapor değiştiyse copy’deki sayılar da yenilenmelidir.

## 2. Kanıt defteri

Canlı rapor değerleri 16 Temmuz 2026’da kontrol edildi. Public raporlar değişebildiği için aşağıdaki değerler “yakalama anı” verisidir.

| Kaynak | Doğrulanmış kullanım |
|---|---|
| [Public scan listesi](https://ai-supply-chain-trust.aibim.ai/api/v1/recent-scans?limit=100) | Son 100 rapor örneklemi ve ready rapor alanları |
| [Canlı metrikler](https://ai-supply-chain-trust.aibim.ai/api/v1/metrics) | 1.387 tarama, 319 benzersiz repo, 4.194 regression contract, 18.602 karar: 18.510 rule-based, 9 LLM-verified, 83 deterministic fallback |
| [github/github-mcp-server raporu](https://ai-supply-chain-trust.aibim.ai/r/github/github-mcp-server) | 14 Temmuz yakalaması: 981 commit tarandı, 2 tarihsel fix, 0 CVE referansı, 15 review lead, %47 coverage, 4 eksik kanıt alanı |
| [coreyhaines31/marketingskills raporu](https://ai-supply-chain-trust.aibim.ai/r/coreyhaines31/marketingskills) | 15 Temmuz yakalaması: 376 commit, 4 tarihsel fix, 0 CVE referansı, 15 review lead, %47 coverage, 4 eksik kanıt alanı |
| [vllm-project/vllm raporu](https://ai-supply-chain-trust.aibim.ai/r/vllm-project/vllm) | 14 Temmuz yakalaması: 1.000 commit, 10 tarihsel fix, 51 CVE referansı, 15 review lead, %47 coverage, 4 eksik kanıt alanı |
| [firecrawl/firecrawl raporu](https://ai-supply-chain-trust.aibim.ai/r/firecrawl/firecrawl) | 14 Temmuz yakalaması: 1.000 commit, 43 tarihsel fix, 0 CVE referansı, 15 review lead, %47 coverage, 4 eksik kanıt alanı |
| [OpenSSF: XZ backdoor, CVE-2024-3094](https://openssf.org/blog/2024/03/30/xz-backdoor-cve-2024-3094/) | Etkilenen sürümler 5.6.0/5.6.1; obfuscated backdoor’ın release tarball/build sürecine bağlanması; downgrade önerisi |
| [OpenSSF/OpenJS takeover uyarısı](https://openssf.org/blog/2024/04/15/open-source-security-openssf-and-openjs-foundations-issue-alert-for-social-engineering-takeovers-of-open-source-projects/) | Maintainer sosyal mühendisliği ve proje ele geçirme girişimlerinin incelenmesi |
| [GitHub Actions 2026 security roadmap](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) | `tj-actions/changed-files`, Nx ve `trivy-action` olaylarının CI/CD otomasyonunun hedeflenmesi örüntüsüyle anılması |
| [GitHub supply-chain önerileri](https://github.blog/security/supply-chain-security/securing-the-open-source-supply-chain-across-github/) | Full-length SHA pinning, `pull_request_target` dikkatleri, user-controlled input ile script injection ve OIDC/trusted publishing önerileri |

**Dil kuralı:** Rapordaki `fixes`, “ürünün doğruladığı açık sayısı” değil, tarihsel güvenlik düzeltmesi olarak işaretlenen commit/fingerprint sayısıdır. `known_cves`, rapora bağlanan CVE referanslarıdır; güncel exploitability kararı değildir. `review_leads`, manuel veya agent-assisted inceleme başlangıç noktalarıdır; bulgu veya açık hükmü değildir.

---

# Hafta 1 — Repository due diligence: yıldızdan karara

**Haftanın tezi:** Popülerlik bir keşif sinyalidir; adoption kararı için kanıt kapsamı, eksikler ve tarihsel inceleme noktaları gerekir.

## LinkedIn post 1 — Yıldız sayısı güvenlik kanıtı değildir

**Hook**
Bir repository’nin yıldız sayısı, neden güvenebileceğinizi açıklamaz.

**Body**
Bir public repo’yu workflow’a almadan önce “popüler mi?” sorusundan daha fazlasına ihtiyacımız var:

- Hangi kanıt kaynakları gerçekten değerlendirildi?
- Hangi güvenlik kontrolleri eksik kaldı?
- Tarihte hangi security fix’ler var?
- Hangi bileşenler önce incelenmeli?
- Bu kararın güven düzeyi ne?

`coreyhaines31/marketingskills` için 15 Temmuz tarihli public rapor 376 commit ve 4 tarihsel güvenlik düzeltmesi kaydediyor. Aynı rapor yalnızca %47 evidence coverage gösteriyor ve AI/MCP, code safety, model/artifact integrity ile OpenSSF kanıtlarını eksik olarak işaretliyor.

Bu yüzden doğru sonuç “repo güvenli” değil. Doğru sonuç: Elde olan kanıtı kullan, dört boşluğu kapatmadan approval verme ve review lead’lerden başla.

Trust score bir bitiş çizgisi değil; incelemenin haritasıdır.

**CTA**
Bir sonraki public repo kararınızı yıldızlarla değil, görünen kanıt ve boşluklarla başlatın: ücretsiz tarayın.

**Görsel önerisi**
İkiye bölünmüş statik görsel. Solda “Popularity: stars / forks / activity”; sağda “Decision context: coverage / missing evidence / history / review leads”. Alt bantta küçük kaynak notu: “marketingskills public report · captured 2026-07-16”.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/coreyhaines31/marketingskills?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w01&utm_content=w01_li01_stars_not_evidence

## LinkedIn post 2 — 5 soruluk repository intake kartı

**Hook**
Bir public repository için “install” demeden önce bu 5 soruya cevap verin.

**Body**
1. **Kim yayımlıyor?** Publisher identity ve ownership hakkında hangi canlı kanıt var?
2. **Repo ne durumda?** Lisans, activity, release ve maintenance sinyalleri nasıl?
3. **Ne tarandı?** Sadece metadata mı, yoksa code/dependency ve artifact kontrolleri de var mı?
4. **Geçmiş ne söylüyor?** CVE referansları, security-fix geçmişi ve tekrar riski taşıyan bileşenler hangileri?
5. **Ne bilmiyoruz?** Eksik kanıt approval koşulunu değiştiriyor mu?

Bu kart bir SCA/SAST replacement değildir. Ama manuel GitHub, OSV, NVD ve history araştırmasını tek bir bounded intake konuşmasına dönüştürür.

İyi bir karar “kaç puan aldı?” ile değil, “hangi kanıt bu kararı destekliyor ve ne eksik?” ile savunulabilir.

**CTA**
Kartı kaydedin; sıradaki public repository değerlendirmesinde raporla birlikte kullanın.

**Görsel önerisi**
Tek sayfalık “Repository Intake Card”; beş numaralı blok, her blokta bir soru ve bir boş checkbox. Korku görseli veya kırmızı alarm yok; krem zemin, koyu lacivert metin, evidence channel çizgisi.

**UTM**
https://ai-supply-chain-trust.aibim.ai/?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w01&utm_content=w01_li02_intake_card

## LinkedIn carousel — Bir public repo raporu nasıl okunur?

**Framework:** Demo Walkthrough, 8 slide.
**Hook**
Bir trust score’a bakıp karar vermeyin. Raporu şu sırayla okuyun.

**Body / slide taslağı**

1. **Kapak:** “Bir public repository raporu 6 adımda nasıl okunur?” Alt başlık: “Score’dan önce evidence.”
2. **Problem:** “Tek sayı belirsizliği saklayabilir.” Görsel: score tek başına; yanında soru işaretleri.
3. **Yol haritası:** “Decision → coverage → missing evidence → history → review leads → action.”
4. **Adım 1:** Gerçek `github/github-mcp-server` ekranında decision ve confidence alanını crop’la. Caption: “Karar etiketini garanti değil, review policy olarak oku.”
5. **Adım 2:** %47 evidence coverage ve dört missing-evidence satırını göster. Caption: “Bulunamayanı temiz sonuç sayma.”
6. **Adım 3:** 981 taranan commit, 2 tarihsel fix ve 0 CVE referansını birlikte göster. Caption: “0 referans, sıfır risk kanıtı değildir.”
7. **Adım 4:** 15 review lead ekranını göster. Caption: “İncelemeyi en ilgili tarihsel noktalardan başlat.”
8. **Sonuç:** Public raporun tamamı + “A trust score that shows its work.” CTA: “Bir repo tara.”

**CTA**
PDF’i kaydedin; her OSS intake’inde aynı okuma sırasını uygulayın.

**Görsel önerisi**
1080×1350, tüm iç slaytlarda aynı şablon. Yalnızca gerçek rapor ekran görüntüleri; önemli alan başına tek crop ve tek ok. Slide 8’de ekran görüntüsüne yakalama tarihi eklenir.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/github/github-mcp-server?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w01&utm_content=w01_carousel_how_to_read

## X post 1

**Hook**
“0 CVE found” ile “güvenli” aynı cümle değildir.

**Body**
Doğru okuma: “Bu raporda 0 CVE referansı kaydedildi.” Sonra coverage’a, eksik kaynaklara ve taramanın kapsamına bakılır.

**CTA**
Evidence boşluklarını görün:

**Görsel önerisi**
“Observed / Missing / Inferred” başlıklı üç kolonlu mini kart.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/github/github-mcp-server?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w01&utm_content=w01_x01_zero_cve

## X post 2

**Hook**
%47 evidence coverage, ürünün saklamaması gereken bir sonuçtur.

**Body**
Eksik veri sessizce “temiz”e dönüşürse score açıklanabilir değildir. Missing evidence kararın parçası olmalı.

**CTA**
Public raporda nasıl gösterdiğimize bakın:

**Görsel önerisi**
%47 progress bar; dolu alan “observed”, boş alan “missing—not clean”.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/coreyhaines31/marketingskills?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w01&utm_content=w01_x02_coverage

## X post 3

**Hook**
Trust score bir verdict değil, navigation aid olmalı.

**Body**
Karar için en az dört şey gerekir: nedenler, evidence coverage, missing evidence ve ilk review lead.

**CTA**
Bir public repo ile deneyin:

**Görsel önerisi**
Score’dan dört ayrı karta çıkan sade bağlantı diyagramı.

**UTM**
https://ai-supply-chain-trust.aibim.ai/?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w01&utm_content=w01_x03_score_navigation

## X thread — 7 adımda bounded repository due diligence

**Hook / 1/7**
Bir public repo’yu install etmeden önce yaptığımız due diligence 7 tweet’e sığıyor. Ama cevap “güvenli/güvensiz” değil; evidence + gaps + next action.

**Body**

**2/7** Repo kimliğini sabitle: owner/name, default branch, değerlendirme tarihi ve mümkünse head SHA. Değişen repo için tarihsiz karar yeniden üretilemez.
**3/7** Publisher ve repository health sinyallerini oku. Stars yardımcı olabilir; identity, license ve maintenance kanıtının yerine geçmez.
**4/7** Coverage’a bak. Bir kaynak unavailable ise bunu “sorun bulunmadı” diye değil, “bu alan değerlendirilmedi” diye kaydet.
**5/7** Security history’yi ayır: CVE referansları, tarihsel fix’ler ve etkilenen bileşenler. Bunlar bugünkü exploitability hükmü değil, review başlangıcıdır.
**6/7** Review lead’leri sırala. İlk soru: “Geçmişte düzeltilen davranış bu değişiklikte geri gelebilir mi?”
**7/7** Kararı policy’ye bağla: standard review, missing evidence’i tamamla veya security owner’a escalate et. Artifact’i URL/JSON/Markdown olarak sakla.

**CTA**
Bu akışı gerçek bir public repo üzerinde çalıştırın.

**Görsel önerisi**
Thread’e tek görsel: “Identity → Coverage → History → Leads → Action” yatay akışı.

**UTM**
https://ai-supply-chain-trust.aibim.ai/?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w01&utm_content=w01_thread_due_diligence

## Gerçek ürün demosu — marketingskills raporunda evidence gap okuma

**Hook**
60 saniyede bir public repo için “ne biliyoruz / ne bilmiyoruz?” ayrımını çıkaralım.

**Body / kayıt akışı**

- **0–08 sn:** Ana sayfada `coreyhaines31/marketingskills` seç; “Run evidence scan” akışını göster. Hazır cached report açılırsa bunu sesli olarak belirt.
- **08–20 sn:** Decision alanını göster; “Bu bir safety guarantee değil, mevcut kanıta göre review action.”
- **20–35 sn:** %47 coverage ve dört missing-evidence satırını tek tek highlight et.
- **35–50 sn:** 376 commit, 4 tarihsel fix ve 15 review lead alanlarını göster; “fix sayısı doğrulanmış güncel açık sayısı değildir” de.
- **50–65 sn:** JSON veya Markdown artifact linkini aç; aynı bağlamın bir agent veya ticket’a taşınabildiğini göster.

**CTA**
Aynı akışı incelemek istediğiniz bir public repo ile çalıştırın.

**Görsel önerisi**
Gerçek tarayıcı ekranı, 1440×900; zoom %125; cursor highlight; son karede URL + “Captured live — date/time” etiketi. Sonuçları değiştiren mockup kullanılmaz.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/coreyhaines31/marketingskills?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w01&utm_content=w01_demo_missing_evidence

---

# Hafta 2 — Coding-agent ve MCP güvenliği: eylemden önce context

**Haftanın tezi:** Agent’ın repo önermesi ile repo üzerinde eylem yapması arasına görünür ve bounded bir evidence gate konmalıdır.

## LinkedIn post 1 — Suggest ile execute arasındaki trust gate

**Hook**
Coding agent bir repository önerebilir. Onu çalıştırmadan önce farklı bir karar gerekir.

**Body**
Agent workflow’larında kritik sınır şudur:

**Suggest → inspect → decide → execute**

“Repo bulundu” sinyali, “repo çalıştırılabilir” izni değildir. Execute aşamasından önce agent’a şu context verilmeli:

- repository ve publisher kanıtı,
- hangi security kaynaklarının değerlendirildiği,
- missing evidence,
- tarihsel CVE/fix bağlamı,
- öncelikli review lead’ler,
- insan onayı veya escalation policy’si.

Bu context JSON, Markdown, REST veya MCP ile taşınabilir. Ama LLM’nin eksik kanıtı tamamladığını varsaymamalıyız. AI Supply Chain Trust’ta LLM çıktısı evidence yaratamaz ve score’u doğrudan değiştiremez.

Agent daha hızlı olabilir. Kararın kanıt standardı daha düşük olmak zorunda değil.

**CTA**
Bir agent’a repo erişimi vermeden önce public security context üretin.

**Görsel önerisi**
`Suggest → Evidence gate → Human/policy decision → Execute` akışı. Gate altında üç küçük etiket: coverage, gaps, leads.

**UTM**
https://ai-supply-chain-trust.aibim.ai/mcp?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w02&utm_content=w02_li01_agent_gate

## LinkedIn post 2 — XZ Utils’tan çıkarılabilecek bounded ders

**Hook**
XZ Utils olayı “open source’a güvenmeyin” dersi değil.

**Body**
OpenSSF’nin CVE-2024-3094 özetine göre backdoor, XZ Utils 5.6.0 ve 5.6.1 sürümlerini etkiledi; obfuscated içerik belirli x86-64 DEB/RPM build koşullarında liblzma’ya dahil oluyordu. OpenSSF/OpenJS ayrıca maintainer’ları hedefleyen sosyal mühendislik ve takeover örüntülerine dikkat çekti.

Buradan savunulabilir üç intake sorusu çıkar:

1. İncelediğimiz source ile kullandığımız release artifact arasında provenance var mı?
2. Publisher/maintainer değişimleri ve release süreci görünür mü?
3. Repository metadata’sının dışında build ve artifact kanıtımız var mı?

Çıkaramayacağımız sonuç ise şu: “Her az-maintainer’lı proje risklidir” veya “bir trust score benzer olayı tek başına engeller.”

Olay incelemesinin değeri korku üretmek değil, tekrar kullanılabilir review soruları üretmektir.

**CTA**
Bu üç soruyu OSS intake checklist’inize ekleyin; repository context’i de eksikleri görünür tutmak için kullanın.

**Görsel önerisi**
Kaynak kod → release tarball → build koşulu → binary package akışı. Kırmızı “hack” görseli yerine, farkın nerede oluştuğunu gösteren provenance diyagramı. Alt bilgi: OpenSSF, CVE-2024-3094.

**UTM**
https://ai-supply-chain-trust.aibim.ai/?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w02&utm_content=w02_li02_xz_bounded_lessons

## LinkedIn carousel — Bir MCP server için 5 intake sorusu

**Framework:** Value-Stack, 7 slide. Cover’daki beş sorunun tamamı ve yalnızca beşi teslim edilir.
**Hook**
MCP server’a credential veya repository erişimi vermeden önce beş soruyu cevaplayın.

**Body / slide taslağı**

1. **Kapak:** “Bir MCP server’ı çalıştırmadan önce 5 intake sorusu.”
2. **Soru 1 — Kaynak:** Hangi owner/repo ve hangi sürüm/SHA çalışacak?
3. **Soru 2 — Yetki:** Server hangi dosya, repo, secret ve network hedeflerine erişebilecek?
4. **Soru 3 — Kanıt:** Code/dependency, OpenSSF ve artifact evidence mevcut mu; hangisi unavailable?
5. **Soru 4 — Geçmiş:** Security fix/CVE geçmişinde hangi component ve permission boundary’leri öne çıkıyor?
6. **Soru 5 — Eylem:** Agent suggest edebilir mi, execute edebilir mi, yoksa insan onayı mı gerekir?
7. **Kapanış:** “Eksik evidence = temiz sonuç değil.” CTA: “Checklist’i kaydet, public repo context’i üret.”

**CTA**
Carousel’i MCP intake review’ünüz için kaydedin.

**Görsel önerisi**
1080×1350; her iç slaytta aynı soru kartı. Soru 4’te gerçek `github/github-mcp-server` raporundan küçük crop; “2 historical fixes / 4 evidence gaps” ifadelerinin yakalama tarihi görünür.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/github/github-mcp-server?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w02&utm_content=w02_carousel_mcp_questions

## X post 1

**Hook**
Agent’ın repo önermesi permission değildir.

**Body**
Sağlam akış: suggest → inspect evidence → apply policy → human approval when needed → execute.

**CTA**
Araya public repo context koyun:

**Görsel önerisi**
Beş aşamalı yatay akış; execute son adımda.

**UTM**
https://ai-supply-chain-trust.aibim.ai/mcp?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w02&utm_content=w02_x01_suggest_execute

## X post 2

**Hook**
MCP güvenliğinde en yararlı cevap bazen “bilmiyoruz”dur.

**Body**
AI/MCP detection veya code-safety evidence unavailable ise agent bunu olumlu sinyal olarak yorumlamamalı. Gap, policy input’tur.

**CTA**
Gerçek raporda gap’leri görün:

**Görsel önerisi**
Bir missing-evidence satırının gerçek UI crop’u; repo ve tarih görünür.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/github/github-mcp-server?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w02&utm_content=w02_x02_mcp_unknown

## X post 3

**Hook**
XZ Utils için repo source tek başına bütün resmi vermedi.

**Body**
OpenSSF özeti, backdoor’ın release/build yolunda etkinleştiğini anlatıyor. Intake sorusu: kullandığımız artifact’ın provenance’ı ne?

**CTA**
Source + artifact evidence’i ayrı değerlendirin:

**Görsel önerisi**
Source ve artifact’ı iki ayrı kutu; arada build/provenance kontrolü.

**UTM**
https://ai-supply-chain-trust.aibim.ai/?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w02&utm_content=w02_x03_xz_provenance

## X thread — XZ Utils olayını kanıt zinciriyle okumak

**Hook / 1/7**
XZ Utils olayından korku sloganı değil, review sorusu çıkaralım. Kaynak: OpenSSF’nin CVE-2024-3094 özeti ve OpenSSF/OpenJS takeover uyarısı.

**Body**

**2/7** Gözlenen: OpenSSF, etkilenen sürümleri 5.6.0 ve 5.6.1 olarak listeliyor; kullanıcılara 5.4.x’e dönmelerini öneriyordu.
**3/7** Gözlenen: obfuscated backdoor belirli x86-64, gcc ve GNU linker build koşullarında liblzma’ya dahil oluyordu.
**4/7** Gözlenen: OpenSSF/OpenJS daha geniş sosyal mühendislik ve maintainer takeover girişimlerine karşı ayrıca uyardı.
**5/7** Çıkarım: Repo metadata’sı tek başına source→release→build→artifact zincirini kanıtlamaz. Bu bir review gap’idir.
**6/7** Uygulanabilir kontrol: exact version/SHA, artifact digest/attestation, publisher değişimi, release workflow ve build provenance’ı ayrı ayrı doğrula.
**7/7** Sınır: Bir public scan böyle bir olayı tek başına önlediğini iddia edemez. Yapabileceği şey kanıtı, boşluğu ve sonraki inceleme noktasını görünür kılmaktır.

**CTA**
Sıradaki OSS intake’inizde source ve artifact kanıtını ayrı satırlara yazın.

**Görsel önerisi**
OpenSSF kaynak linkleriyle “Observed / Inference / Control / Limit” dört satırlı evidence card.

**UTM**
https://ai-supply-chain-trust.aibim.ai/?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w02&utm_content=w02_thread_xz_evidence_chain

## Gerçek ürün demosu — github-mcp-server için agent-ready context

**Hook**
Bir coding agent’a GitHub MCP Server context’i vermeden önce raporda ne var, 75 saniyede bakalım.

**Body / kayıt akışı**

- **0–10 sn:** `github/github-mcp-server` public report URL’sini aç; repo ve rapor tarihini göster.
- **10–25 sn:** Decision/coverage bölümünde %47 coverage ve düşük confidence’ı anlat.
- **25–42 sn:** Dört missing-evidence alanını aç; özellikle AI/MCP-specific ve code-safety evidence unavailable satırlarını göster.
- **42–58 sn:** 981 commit, iki tarihsel fix ve 15 review lead’e geç. “Lead, finding değildir” notunu seslendir.
- **58–75 sn:** Markdown artifact’ı açıp bunun agent prompt/context veya review ticket’ına nasıl eklenebileceğini göster; execute izni vermediğini belirt.

**CTA**
Agent workflow’unuza public repository context ekleyin; eksik evidence için human gate’i koruyun.

**Görsel önerisi**
Split-screen yalnızca son 15 saniyede: solda gerçek rapor, sağda gerçek Markdown artifact. Başta ve sonda capture tarihi.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/github/github-mcp-server?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w02&utm_content=w02_demo_agent_context

---

# Hafta 3 — Security history: sayıdan regression review’a

**Haftanın tezi:** CVE ve fix sayıları karar değil; bileşen, zaman ve evidence coverage ile birlikte review önceliği üretir.

## LinkedIn post 1 — 51 CVE referansı ne söyler, ne söylemez?

**Hook**
Bir raporda 51 CVE referansı görmek, tek başına “kullanma” kararı değildir.

**Body**
14 Temmuz tarihli `vllm-project/vllm` public raporu:

- 1.000 commit’in incelendiğini,
- 10 tarihsel security fix fingerprint’i,
- 51 CVE referansı,
- 15 review lead,
- %47 evidence coverage ve dört eksik evidence alanı

gösteriyor.

Bu veriler güncel exploitability, reachability veya sizin deployment’ınızın etkilenme durumunu tek başına kanıtlamaz. Ama review sırasını iyileştirir:

1. CVE referansını kaynak advisory ile doğrula.
2. Etkilenen sürüm ve component’i kendi kullanımınla eşleştir.
3. Tarihsel fix’in dokunduğu dosya/symbol’leri incele.
4. Yaklaşan değişikliğin aynı davranışı geri getirip getirmediğini test et.
5. Eksik scanner/artifact evidence’i ayrıca tamamla.

Sayı alarm değildir. İyi bağlanmış sayı, inceleme başlangıcıdır.

**CTA**
Public raporu açın; CVE sayısından önce coverage ve review lead’leri okuyun.

**Görsel önerisi**
Merkezde “51 CVE references”; dışarı çıkan dört ok: version, component, advisory, reachability. Alt not: “reference count ≠ current exploitability”.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/vllm-project/vllm?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w03&utm_content=w03_li01_cve_context

## LinkedIn post 2 — CI/CD otomasyonu da dependency’dir

**Hook**
Supply chain review yalnızca `package.json` veya `requirements.txt` ile bitmez.

**Body**
GitHub’ın 2026 Actions security roadmap’i `tj-actions/changed-files`, Nx ve `trivy-action` olaylarını aynı örüntü içinde anıyor: saldırganlar yalnızca ürün kodunu değil, onu build ve publish eden CI/CD otomasyonunu da hedefliyor.

GitHub’ın yayınladığı uygulanabilir kontroller açık:

- third-party Actions’ı full-length commit SHA’ya pinlemek,
- `pull_request_target` kullanımını dikkatle değerlendirmek,
- user-controlled input’ın shell/script içine taşınmasını önlemek,
- uzun ömürlü publish secret’ları yerine OIDC/trusted publishing düşünmek.

Repository due diligence bu yüzden iki scope içermeli:

**Ne build ediyoruz?** ve **Bunu ne build ediyor?**

Bu kontroller olayların tekrarını garanti etmez. Ancak review yüzeyini dependency graph’ından workflow graph’ına genişletir.

**CTA**
Bu hafta bir repo seçin; `.github/workflows` altındaki third-party Actions ve permission’ları inventory edin.

**Görsel önerisi**
Application dependency graph’ın yanına workflow dependency graph. İkinci grafikte action ref, permissions, secrets, network egress etiketleri.

**UTM**
https://ai-supply-chain-trust.aibim.ai/?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w03&utm_content=w03_li02_cicd_dependency

## LinkedIn carousel — CVE sayısından regression review’a

**Framework:** Demo Walkthrough, 8 slide.
**Hook**
Bir CVE sayısını karar değil, review planına böyle dönüştürüyoruz.

**Body / slide taslağı**

1. **Kapak:** “51 CVE referansından 1 bounded review planına.”
2. **Problem:** “Count, version ve component bağlamı olmadan action söylemez.”
3. **Yol haritası:** “Source → affected version → component → historical fix → regression check.”
4. **Adım 1:** Gerçek vLLM raporunda 51 CVE referansı ve rapor tarihini göster.
5. **Adım 2:** %47 coverage + dört missing-evidence satırını göster. Caption: “Önce sınırı kaydet.”
6. **Adım 3:** 10 historical fix ve ilgili component/symbol alanından gerçek crop.
7. **Adım 4:** 15 review lead içinden bir lead’i göster; “lead ≠ validated vulnerability”.
8. **Sonuç:** “Version’ı doğrula, component’i eşleştir, fix’i incele, regression test yaz.” CTA: “Raporu aç.”

**CTA**
Carousel’i AppSec triage veya OSS review toplantınız için kaydedin.

**Görsel önerisi**
Gerçek report UI; CVE listesinde kişisel veri veya token olmadığını kayıttan önce doğrula. Her sayı yanında “captured 2026-07-16” etiketi.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/vllm-project/vllm?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w03&utm_content=w03_carousel_cve_to_review

## X post 1

**Hook**
51 CVE reference = 51 exploitable vulnerability demek değildir.

**Body**
Version, component, advisory ve deployment context olmadan count yalnızca triage başlangıcıdır.

**CTA**
Gerçek raporu coverage ile birlikte okuyun:

**Görsel önerisi**
“Reference → Verify → Match → Review” dört adımlı kart.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/vllm-project/vllm?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w03&utm_content=w03_x01_cve_not_exploitability

## X post 2

**Hook**
Dependency review’ın görünmeyen yarısı: `.github/workflows`.

**Body**
Third-party Action ref’leri, permissions, untrusted input ve publish credentials da supply-chain yüzeyidir.

**CTA**
Workflow graph’ını inventory edin:

**Görsel önerisi**
Dört maddelik workflow audit mini-checklist.

**UTM**
https://ai-supply-chain-trust.aibim.ai/?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w03&utm_content=w03_x02_workflow_graph

## X post 3

**Hook**
Historical security fix, regression review için bir test sorusudur.

**Body**
“Bu fix hangi component/symbol’e dokundu ve bugünkü değişiklik aynı davranışı geri getirebilir mi?”

**CTA**
Review lead’lerle başlayın:

**Görsel önerisi**
Commit → component → invariant → regression test akışı.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/vllm-project/vllm?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w03&utm_content=w03_x03_regression_question

## X thread — Supply-chain olayını reusable control’e çevirmek

**Hook / 1/7**
Bir supply-chain olayı hakkında paylaşım yapmak kolay. Onu reusable engineering control’e çevirmek daha değerli. GitHub Actions örüntüsü üzerinden 6 adım:

**Body**

**2/7** Primary source’u sabitle. GitHub’ın 2026 roadmap’i `tj-actions/changed-files`, Nx ve `trivy-action` olaylarını CI/CD automation targeting örüntüsünde anıyor.
**3/7** Gözlenen ile genellemeyi ayır. “Bu projeler anıldı” gözlemdir; “tüm Actions tehlikelidir” kanıtsız genellemedir.
**4/7** Etki yüzeyini çıkar: trigger, permissions, third-party ref, secrets/publish credential, untrusted input, network egress.
**5/7** Kontrole çevir: full SHA pinning; `pull_request_target` review; script injection önleme; OIDC/trusted publishing. Bunlar GitHub’ın yayımladığı önerilerle uyumludur.
**6/7** Evidence gap’i kaydet: Repo scan’i workflow semantics veya runtime egress’i doğrulamadıysa “pass” verme. Ayrı tarama veya manuel review iste.
**7/7** Regression sorusu yaz: “Bu değişiklik untrusted input’ı privileged workflow’a taşıyor mu?” Kontrol versioned, testable ve owner’lı olsun.

**CTA**
Son incelediğiniz olayı bir cümlelik regression contract’a dönüştürün.

**Görsel önerisi**
Incident → evidence → surface → control → regression contract diyagramı; primary-source linkleri dipnotta.

**UTM**
https://ai-supply-chain-trust.aibim.ai/?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w03&utm_content=w03_thread_incident_to_control

## Gerçek ürün demosu — vLLM raporundan review planı üretmek

**Hook**
Bir rapordaki 51 CVE referansını alarm listesi değil, bounded review planı olarak okuyalım.

**Body / kayıt akışı**

- **0–10 sn:** `vllm-project/vllm` report URL, repo ve 14 Temmuz rapor tarihini göster.
- **10–25 sn:** 1.000 taranan commit, 10 historical fix ve 51 CVE referansını göster; terimleri tanımla.
- **25–40 sn:** %47 coverage ve dört evidence gap’i göster; kapsam sınırını söyle.
- **40–60 sn:** CVE/fix detayından bir component veya commit evidence linkini aç; gerçek kaynağa geçişi göster.
- **60–78 sn:** Review leads ekranına dön; tek bir lead’i seçip “version → component → regression test” notu oluştur.
- **78–90 sn:** Markdown/JSON artifact ile planı paylaşılabilir hale getir.

**CTA**
Kendi public repo’nuzda count’tan önce source, coverage ve component bağlamını kontrol edin.

**Görsel önerisi**
90 saniyelik gerçek ekran kaydı; CVE detayı varsa kaynak linki yeni tab’da açılır. Voiceover hiçbir CVE’nin güncel exploitability’si hakkında raporun söylemediği hükmü kurmaz.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/vllm-project/vllm?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w03&utm_content=w03_demo_vllm_review_plan

---

# Hafta 4 — Explainable security ve open-source journey

**Haftanın tezi:** Güven, modelin ne kadar iddialı konuştuğundan değil; evidence yaratma yetkisinin sınırlandırılmasından ve eksiklerin görünür kalmasından gelir.

## LinkedIn post 1 — LLM evidence yaratamaz

**Hook**
Security product’ta LLM’nin en önemli özelliği ne söyleyebildiği değil, neyi değiştiremediğidir.

**Body**
AI Supply Chain Trust’ın “no invented evidence” sınırı basit:

- LLM output yeni security evidence oluşturamaz.
- LLM score’u doğrudan değiştiremez.
- Kaynak unavailable ise model o boşluğu dolduramaz.
- Karar rule version, evidence source ve fallback state ile izlenebilir kalır.

16 Temmuz canlı metriklerinde 18.602 kayıtlı karar vardı:

- 18.510 rule-based,
- 9 LLM-verified,
- LLM servisi unavailable olduğunda 83 deterministic fallback.

Bu dağılım “AI hiç kullanılmıyor” demek değildir. Ürünün kanıt ve karar sınırında deterministik davranışı merkeze koyduğunu gösterir.

Explainable security için hedef daha ikna edici metin değil; daha denetlenebilir evidence lineage’dır.

**CTA**
Metrikleri ve açık kaynak uygulamayı inceleyin; hangi kararların modelden bağımsız kaldığını görün.

**Görsel önerisi**
18.602 kararın ölçekli stacked bar’ı. 18.510 / 9 / 83 etiketleri doğrudan API yakalamasından; “captured 2026-07-16” notu.

**UTM**
https://ai-supply-chain-trust.aibim.ai/api/v1/metrics?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w04&utm_content=w04_li01_no_invented_evidence

## LinkedIn post 2 — %47 coverage’ı neden yayımlıyoruz?

**Hook**
Erken aşama bir security product için %47 evidence coverage rahat bir metrik değil. Bu yüzden görünür olmalı.

**Body**
16 Temmuz’da incelenen son 100 ready rapor ortalama %47 evidence coverage gösteriyordu. Bu bir başarı metriği olarak sunulmamalı. Ürünün bugün nerede eksik olduğunu söyleyen limitation’dır.

Ama aynı zamanda tasarım kararını test eder:

- unavailable kaynaklar clean result’a dönüşmüyor,
- confidence düşüyor,
- missing evidence kararla birlikte gösteriliyor,
- kullanıcıya “önce neyi tamamlamalı?” sorusunun cevabı veriliyor.

Open source journey’mizde sıradaki iş yalnızca daha fazla scanner eklemek değil. Coverage’ın anlamını korumak, source freshness’i göstermek ve her review lead’i gerçek evidence’e bağlamak.

Build in public, yalnızca feature duyurmak değildir. Sınırı ve eksikliği de yayımlamaktır.

**CTA**
Bir public raporu eleştirel gözle inceleyin; eksik veya yanıltıcı gördüğünüz alanı GitHub’da paylaşın.

**Görsel önerisi**
“What works / What is missing / What we’re improving” üç kolonlu build-in-public kart. Yalnızca mevcut dokümanlarda veya issue’da doğrulanabilen roadmap ifadeleri kullanılır.

**UTM**
https://github.com/aibim-ai/AI-Supply-Chain-Trust?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w04&utm_content=w04_li02_build_in_public

## LinkedIn carousel — İlk public ölçümler: sayı + sınır

**Framework:** Problem-Proof, 8 slide. Son slayt gerçek metrics endpoint/UI screenshot ile “receipt” verir.
**Hook**
İlk public ölçümlerimizi, iyi görünenleri ve limitation’ı aynı carousel’de yayımlıyoruz.

**Body / slide taslağı**

1. **Kapak:** “1.387 scan. 319 repo. Ortalama %47 evidence coverage.”
2. **Reframe:** “Daha çok scan, daha çok güven kanıtı değildir.”
3. **Mekanizma:** “Evidence source → deterministic evaluation → coverage/gaps → public artifact.”
4. **Ölçüm 1:** 1.387 tarama / 319 benzersiz repo. “Usage, adoption veya customer count değildir.”
5. **Ölçüm 2:** 4.194 regression contract. “Generated count; verified contract count iddiası kurma.”
6. **Ölçüm 3:** 18.602 decision: 18.510 rule-based, 9 LLM-verified, 83 fallback.
7. **Limitation:** Son 100 ready raporda ortalama %47 coverage. “Missing ≠ clean.”
8. **Proof:** Canlı metrics endpoint ve örnek public report ekranı. CTA: “Kaynağı aç, sayıları kontrol et.”

**CTA**
Carousel’i paylaşmadan önce canlı endpoint’i yeniden açın; rakamlar değişmişse tüm slaytları aynı yakalama zamanına güncelleyin.

**Görsel önerisi**
1080×1350; sayı slaytlarında minimum öğe. Son slayt gerçek endpoint screenshot. Her slaytta küçük “Snapshot: YYYY-MM-DD HH:mm TRT”.

**UTM**
https://ai-supply-chain-trust.aibim.ai/api/v1/metrics?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w04&utm_content=w04_carousel_public_metrics

## X post 1

**Hook**
LLM’nin “eminim” demesi evidence değildir.

**Body**
Bizde LLM output score’u doğrudan değiştiremez veya unavailable kaynağın yerine geçemez. Evidence lineage ayrı kalır.

**CTA**
Mimariyi inceleyin:

**Görsel önerisi**
LLM kutusundan score’a giden yol üzerinde “no direct write” işareti; evidence store ayrı.

**UTM**
https://github.com/aibim-ai/AI-Supply-Chain-Trust?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w04&utm_content=w04_x01_llm_boundary

## X post 2

**Hook**
%47 coverage’ı saklamak kolaydı. Yayınlamak daha kullanışlı.

**Body**
Çünkü incomplete evidence, approval koşulunu değiştirmeli. Missing data “nothing found” değildir.

**CTA**
Bir public raporda görün:

**Görsel önerisi**
Coverage bar + dört gerçek missing-evidence etiketi.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/firecrawl/firecrawl?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w04&utm_content=w04_x02_publish_limit

## X post 3

**Hook**
Build in public = feature log’u değil, evidence log’u.

**Body**
Ne çalışıyor? Ne eksik? Hangi karar rule-based? Hangi fallback devreye girdi? Hangi sayı yalnızca snapshot?

**CTA**
Source ve public metrics açık:

**Görsel önerisi**
Feature changelog ile evidence ledger karşılaştırması.

**UTM**
https://github.com/aibim-ai/AI-Supply-Chain-Trust?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w04&utm_content=w04_x03_evidence_log

## X thread — No invented evidence nasıl uygulanır?

**Hook / 1/8**
“No invented evidence” bir slogan değilse, sistemde hangi sınırlar olmalı? AI Supply Chain Trust’ta uyguladığımız 7 kontrol:

**Body**

**2/8** Evidence source zorunluluğu: commit SHA, advisory/CVE ID, scanner output veya versioned deterministic rule olmadan security claim üretme.
**3/8** Missing state’i first-class tut: unavailable, stale veya partial veriyi clean/pass’e map etme.
**4/8** LLM write boundary: model evidence yaratamaz ve score’u doğrudan set edemez.
**5/8** Deterministic fallback: model unavailable olduğunda sonucu uydurma; bounded rule sonucunu ve fallback reason’ını kaydet.
**6/8** Language boundary: “0 recorded CVEs” de; “vulnerability-free” deme. “Review lead” de; “validated finding” deme.
**7/8** Artifact lineage: web sonucu ile JSON/Markdown/MCP context aynı source ve version bilgisini taşısın.
**8/8** Public limitation: coverage, confidence, timestamp ve missing evidence’i score kadar görünür yap. Kullanıcı sonucu yeniden kontrol edebilsin.

**CTA**
Bu kontrollerden hangisi sizin agent pipeline’ınızda eksik? Source’u açıp issue bırakın.

**Görsel önerisi**
Yedi kontrollü “Evidence Integrity Checklist”; her madde repo dokümanındaki karşılığına bağlanır.

**UTM**
https://github.com/aibim-ai/AI-Supply-Chain-Trust?utm_source=x&utm_medium=organic_social&utm_campaign=trust_system_w04&utm_content=w04_thread_no_invented_evidence

## Gerçek ürün demosu — aynı raporda güçlü history ve zayıf coverage

**Hook**
Bir report aynı anda 43 tarihsel fix gösterebilir ve yalnızca %47 evidence coverage’a sahip olabilir.

**Body / kayıt akışı**

- **0–10 sn:** `firecrawl/firecrawl` public report’u, repo adı ve 14 Temmuz rapor tarihini aç.
- **10–24 sn:** 1.000 taranan commit ve 43 historical fix’i göster; bunun güncel açık sayısı olmadığını belirt.
- **24–38 sn:** Raporda 0 CVE referansı bulunduğunu göster; “CVE yok” çıkarımı kurma.
- **38–54 sn:** %47 coverage ve dört missing-evidence alanına geç; iki veri grubunun çelişmediğini anlat.
- **54–70 sn:** 15 review lead’den birini aç; evidence linki varsa gerçek commit’e git.
- **70–85 sn:** JSON/Markdown artifact’ı göster ve son cümleyi kur: “Bildiğimizi kullanıyoruz; bilmediğimizi approval’dan saklamıyoruz.”

**CTA**
Bir public repo seçin; history ile coverage’ı aynı ekranda değerlendirin.

**Görsel önerisi**
Gerçek UI kaydı. Videonun kapak karesi iki sayı taşır: “43 historical fixes” ve “47% evidence coverage”; araya eşittir veya tehlike işareti konmaz.

**UTM**
https://ai-supply-chain-trust.aibim.ai/r/firecrawl/firecrawl?utm_source=linkedin&utm_medium=organic_social&utm_campaign=trust_system_w04&utm_content=w04_demo_history_and_gaps

---

## 3. Üretim ve dağıtım SOP’si

### Pazartesi: evidence freeze (30 dakika)

1. O haftanın tüm public report ve metrics URL’lerini aç.
2. Değerleri `yakalama tarihi + head SHA varsa SHA` ile not et.
3. Copy’de geçen her sayıyı kaynağa karşı işaretle.
4. Rapor güncellendiyse eski screenshot ve sayıları birlikte değiştir.

### Salı: batch copy ve tasarım (90 dakika)

1. LinkedIn hook’larını ilk 210 karakterde tamamla.
2. X için hook + body + CTA’yı standard 280 karakter limitine göre son yayın composer’ında kontrol et; uzun URL’yi platformun t.co dönüşümüyle test et.
3. Carousel’de her slayta tek fikir koy; minimum 28pt metin ve tek şablon kullan.
4. Her statik ve videoya source/capture tarihi ekle.

### Cuma: demo doğrulama (30 dakika)

1. Demo, staging mockup değil gerçek public report ile çekilir.
2. Cache’den hazır rapor açılıyorsa “live re-scan” denmez; “cached public report” denir.
3. Scan gerçekten kuyruğa alınırsa bekleme veya progressive state kesilmeden gösterilir.
4. Token, cookie, internal endpoint, kişisel hesap veya private repository görünmediği kontrol edilir.

### Yayın sonrası engagement (günde 20–30 dakika)

- İlk 60 dakika gelen teknik sorulara kaynak linkiyle yanıt ver.
- “Bu repo güvenli mi?” sorusuna safety verdict verme; scope, timestamp, coverage ve next action’ı tekrar et.
- İtirazları içerik backlog’una taşı: score itirazı, missing-source isteği, agent policy sorusu, history false positive’i.
- Hedef kitleden 5–10 kişinin ilgili gönderilerine yeni kanıt veya uygulanabilir soru ekleyen yorumlar yap; ürün linkini yalnızca doğrudan ilgiliyse kullan.

## 4. Ölçüm ve dört hafta sonu kararı

### İzlenecek metrikler

| Amaç | Metrik | Neyi test eder? |
|---|---|---|
| Awareness | Nitelikli impression ve target-role follower artışı | Konu doğru kişilere ulaşıyor mu? |
| Relevance | LinkedIn save rate, X bookmark, profile visit | İçerik referans olarak değerli mi? |
| Conversation | Teknik yorum, nitelikli reply, DM | Mesaj gerçek bir review problemine temas ediyor mu? |
| Activation | UTM session → repo selected → scan queued → ready report viewed | İçerik üründe gerçek davranış üretiyor mu? |
| Product learning | Evidence gap açılımı, review lead tıklaması, JSON/Markdown/MCP kullanımı | Hangi değer teması activation yaratıyor? |

### İçerik etiketleri

Her yayında analytics notuna şu dört alan eklenir:

- `pillar`: `due_diligence`, `agent_mcp`, `incident`, `missing_evidence`, `oss_journey`
- `hook`: `contrarian`, `question`, `number`, `demo`, `principle`
- `proof`: `public_report`, `primary_source`, `live_metrics`, `source_code`
- `cta`: `scan`, `view_report`, `save`, `inspect_source`, `comment`

### Dört hafta sonu değerlendirme

1. En yüksek impression’ı değil, en yüksek **nitelikli activation** üreten iki sütunu koru.
2. Carousel’leri save rate ve completion ile; demoları ready-report view ve evidence-section engagement ile değerlendir.
3. “Safety verdict” isteyen yorum sayısını mesaj açıklığı sinyali olarak izle; yüksekse hook/body’de scope sınırını daha erken söyle.
4. Public-report sayıları değiştiğinde evergreen içerikleri yeniden yayımlamadan önce snapshot’ı yenile.
5. İlk müşteri görüşmeleri geldikçe proxy customer language’i birinci taraf ifadelerle değiştir; hiçbir proxy alıntıyı testimonial olarak kullanma.
