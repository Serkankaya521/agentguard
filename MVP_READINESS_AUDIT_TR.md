# AgentGuard MVP Teslim ve Hazırlık Denetimi

## Ürün hedefi

AgentGuard, bir kurumun AI ajanlarını ve MCP/tool akışlarını çalışma zamanında korur;
yetkili red-team kampanyalarıyla sürekli sınar; başarılı saldırı adaylarını mutasyon,
crossover ve cevap geri bildirimiyle geliştirir; deterministik saldırı kanıtlarını
bulguya ve tekrar çalıştırılabilir regresyon vakasına dönüştürür.

## Karar — 16 Eylül 2026

Tanımlanan ilk ürün kapsamı için **MVP implementasyonu tamamlandı ve yerel olarak
doğrulandı**. Bu karar canlı müşteri ortamına dağıtım veya production-readiness
onayı değildir. Desteklenen MVP hedefi OpenAI-compatible bir ajan endpoint'i,
`env://` ile sağlanan dış secret'lar, seri ve bütçeli kampanya yürütme ve target-side
canary kanıtıdır.

## Tamamlanan üç MVP zinciri

1. **Kalıcı kampanya kontrol düzlemi**
   - Tenant/workspace/environment kapsamlı campaign ve run tabloları.
   - Create/update, pause/activate/archive, run-now ve run history API'leri.
   - Deterministik schedule-slot kimlikleri, idempotency key, lease/retry/dead-letter
     ve worker restart sonrasında güvenli yeniden yürütme.
   - Request/mutation bütçeleri; MVP adapter'ında bilinçli olarak concurrency `1`.

2. **Deterministik kanıt → Finding → regression**
   - Response-aware genetik mutasyon; düşük fitness yanıtları dahil her isteğin
     lineage, fitness ve response hash kaydı.
   - Saldırı payload'ında bulunmayan target-side canary yanıtta görülürse `CONFIRMED`
     Finding. Heuristic skor tek başına Finding üretmez.
   - Ham yanıt veritabanına yazılmaz. Tenant-scoped evidence JSON nesnesi hashlenir,
     object store'a konur ve `evidence_objects` kaydıyla run'a bağlanır.
   - Aynı payload regression olarak replay edilir; sonuç `passed` veya `reopened`,
     Finding durumu ise `RESOLVED_VERIFIED` veya `REOPENED` olur.

3. **Tek ana operasyon konsolu**
   - Next.js konsolunda campaign oluşturma, zamanlama, pause/activate, run-now ve
     son run/evidence durumu.
   - Evidence ekranında üretilen regresyon vakaları ve replay eylemi.
   - Findings, policies, approvals, assets, operations ve workspaces aynı navigasyonda.

## Güvenlik sınırları

- API key ve canary değerleri API cevabına veya kampanya tablosuna yazılmaz;
  worker bunları çalışma zamanında `env://VARIABLE_NAME` referansından çözer.
- Worker yalnızca kayıtlı olduğu job türlerini claim eder. Genel platform worker'ı
  red-team veya regression işlerini alamaz.
- Schedule ve manual run idempotent'tır; tamamlanmış run yeniden kanıt/finding üretmez.
- Tenant tablolarında FORCE RLS vardır ve cross-tenant testleri migration 006'yı kapsar.
- Yetkisiz hedeflerde kullanım yasaktır; endpoint kaydı ürünün yetkilendirme beyanıdır.

## Doğrulama kanıtı

- Python: `182 passed, 14 skipped`.
- AEGIS red-team sözleşmesi: `15 passed`.
- Temiz geçici PostgreSQL üzerinde migration `001–006` ve platform uçtan uca testleri:
  `40 passed`.
- Next.js: typecheck başarılı, production build başarılı, `16` rota üretildi.
- npm audit: `0 vulnerabilities`.
- Kubernetes: `6` YAML dosyası parse edildi; security worker ve schedule materializer
  manifestleri dahil.
- Ana konsol ve campaign ekranı yerel tarayıcıda görsel olarak doğrulandı.

## MVP sonrasında kalan üretim işleri

- Gerçek müşteri ajanı üzerinde izinli pilot ve target-side canary enjeksiyonu.
- MCP, genel HTTP agent, LangGraph, CrewAI ve AutoGen adapterları.
- Vault/AWS/Azure/GCP secret resolver'ları; MVP yalnız `env://` destekler.
- Dağıtık in-flight kill switch, tool/resource side-effect observer ve concurrency > 1.
- Redis/broker/S3/ClickHouse production topolojisinde restart, noisy-neighbor ve 24 saat
  soak testleri; imzalı release, canary rollout ve geri dönüş tatbikatı.

Bu ayrım korunmalıdır: repository artık görüşülebilir ve pilotlanabilir bir MVP'dir;
henüz canlı prodüksiyon dağıtımı tamamlanmış bir ürün değildir.
