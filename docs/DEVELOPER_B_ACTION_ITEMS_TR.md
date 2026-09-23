# Developer B (Serkan) — Yapılacaklar

Bu belge, Developer A (core-security / AEGIS) tarafının `45dc5cb` sonrası tamamladığı
işleri, Serkan'ın inceleyip birleştirmesi gereken PR'ları, Serkan'ın **kendi kodunda**
düzeltmesi gereken güvenlik/doğruluk hatalarını ve süreç adımlarını listeler.

> Not: Aşağıdaki dosya:satır referansları `shared/main = 45dc5cb` içindir. "Ben (Dev A)
> doğruladım" diyenler kod okunarak veya çalıştırılarak teyit edildi. "İnceleme buldu"
> diyenler otomatik incelemeden gelir; düzeltmeden önce hızlıca teyit edilmeli.

---

## 1. İncelenecek ve birleştirilecek PR'lar (sırayla)

Her ikisi de `shared` remote'ta, kararlaştırdığımız akışa uygun. `main`'e doğrudan push yok.

1. **PR #9** (base `main`) — Dev A düzeltmeleri + iki entegrasyon.
   - `validation.py` `referencing` bağımlılığından kurtarıldı (jsonschema 4.10 + 4.26 uyumlu), hot-path p50 geri geldi.
   - Approval replay guard artık exception yerine fail-closed red veriyor.
   - Red-team RoE + kill-switch + safety-budget (secret sızdırma ve yetkisiz-hedef açığı kapatıldı).
   - CI'a test paketi + iki latency gate eklendi.
   - Approval-revoke tüketicisi + SecurityEvent → analytics producer.
2. **PR #10** (base = PR #9 dalı, yani #9'un üzerine "stacked") — kalan Dev A işleri.
   - Kaynak adapter'ları (MCP JSON-RPC + sdk/agent_framework/tool_wrapper/message_integration).
   - Tool/resource side-effect gözlemcisi (kanıt tabanlı, "blocked ≠ executed").
   - Dağıtık in-flight kill-switch.
   - AEGIS corpus / vulnerability-DNA promotion policy + `deep_analysis`'e bağlanması.

**Merge sırası: önce #9, sonra #10.** (#10, #9'un üzerine kurulu; #9 merge edilince #10'un
base'i otomatik `main`'e döner.)

**Dev A tarafında doğrulama:** 275 pytest + stdlib runner yeşil, iki latency gate yeşil,
`compileall` temiz. Atlanan 14 test PostgreSQL istiyor (CI'da PG servisi var, orada koşar).

### Bu PR'ların Serkan'ın alanına değdiği yerler (inceleme noktaları)
- `apps/worker/src/config.py`: yeni worker rolü `revoke`.
- `apps/worker/src/main.py`: `revoke` rolü dispatch'i.
- `infra/kubernetes/platform-workers.yaml`: yeni `agentguard-approval-revoke-worker` deployment'ı (deployment topolojisi Serkan'ın alanı — gözden geçir).
- Yeni tüketiciler mevcut altyapıyı varsayıyor: `KAFKA_BOOTSTRAP_SERVERS`, `REDIS_URL`, ve **her event türünün kendi topic'i olması** (outbox `event_type`'ı topic olarak kullanıyor; revoke tüketicisi `approval.revoked` topic'ini dinliyor).
- Paylaşılan şema değişmedi. Sadece Dev A enum'u `RedTeamReason`'a `ROE_SECRET_UNAUTHORIZED` eklendi.

---

## 2. Serkan'ın KENDİ kodunda düzeltmesi gereken hatalar (önem sırasına göre)

Bunlar inceleme sırasında Serkan'ın alanında (`apps/control-api`, `migrations`, `apps/worker`
platform işleri, `apps/web-console`) bulundu. Kritikler yayından önce kapatılmalı.

### KRİTİK
1. **Secret sızdırma — `apps/control-api/src/campaigns.py:42`** *(Ben doğruladım)*
   `api_base` kontrolü sadece başlangıca bakıyor; `http://localhost.attacker.example` gibi
   sahte hostlar geçiyor ve `secret_ref=env://<herhangi_bir_isim>` kabul ediliyor.
   Dev A tarafı (worker RoE + ScopedSecretResolver, PR #9) bunu **RoE tanımlıysa** durduruyor;
   yine de kaynakta da kapatılmalı: tam-origin doğrulaması + tenant'a atanmış secret allowlist'i.

### YÜKSEK
2. **`credentials` tablosunda RLS yok + SCIM tenant filtresiz iptal** *(Ben doğruladım)*
   `migrations/postgresql/001_tenancy.up.sql`: `platform.credentials` FORCE RLS listesinde değil;
   `apps/control-api/src/p2_enterprise.py:122` SCIM deaktivasyonu `UPDATE ... credentials ...
   WHERE identity_id=%s` — tenant filtresi yok. Bir tenant, başka tenant'ın identity UUID'sini
   tahmin edip onun kimlik bilgilerini iptal edebilir. → `credentials`'a RLS ekle, SCIM sorgusuna
   `tenant_id` predicate'i koy.
3. **Kilitlenen işler — `apps/worker/src/queues/repository.py`** *(Ben doğruladım)*
   `claim` yalnız `queued`/`retry` seçiyor; worker çökerse `running`'de kalan iş lease süresi
   dolsa bile bir daha alınmıyor (lease mekanizması fiilen çalışmıyor). → süresi dolmuş `running`
   işleri toplayan bir "reaper" ekle (ör. `lease_until < now()` olanları `retry`'a çek).
4. **İki-onay kuralı aşılabiliyor** *(İnceleme buldu — teyit et)*
   `apps/control-api/src/enterprise.py:235`: admin herhangi bir identity için token üretebiliyor;
   kendi yüksek riskli isteğini iki "sahte onaylayan" ile onaylayabiliyor. → token üretimini
   sınırla / self-approval + iki-kişi kuralını gerçek onaylayan kimliğe bağla.
5. **Evidence yazma yetkisi ve hash doğrulaması** *(İnceleme buldu — teyit et)*
   `enterprise.py:657,675`: evidence upload/register sadece `evidence.read` istiyor (okuma yetkisi
   olan yazabiliyor). `object_store.py`: hash, istemcinin kendi beyanıyla karşılaştırılıyor (S3
   gerçek içeriği doğrulamıyor). → yazma için ayrı yetki; hash'i sunucu/depolama tarafında doğrula.

### ORTA
6. **Outbox sadece statik tenant listesini yayınlıyor** *(İnceleme buldu — Dev A işini etkiler)*
   `apps/control-api/src/outbox_main.py`: `PLATFORM_TENANT_IDS` env'indeki tenant'lar işleniyor.
   **Yeni bir tenant eklenirse `approval.revoked` ve `cache.invalidation` olayları hiç yayınlanmaz**
   → benim yeni revoke tüketicim o tenant için hiç olay görmez. → tenant listesini dinamikleştir.
7. **Analytics tüketicisinde DLQ yok** *(İnceleme buldu — Dev A işini etkiler)*
   `apps/worker/src/analytics_main.py`: bozuk tek bir mesaj tüketiciyi sonsuz döngüye sokar ve
   partition'ı bloklar → benim SecurityEvent producer'ımın verisi durur. → poison-message/DLQ yolu ekle.
8. **ABAC ortam kısıtı sadece "create" yollarında** *(İnceleme buldu — teyit et)*
   `publish_policy`, `rollback_policy`, `decide_approval`, `transition_finding`, `put_campaign`,
   `run_now` çağrılarında `environment_kind` kontrol edilmiyor → "test" ortamına kısıtlı biri
   production policy'yi aktifleştirebilir/onaylayabilir.
9. **SCIM yeniden POST'u `attributes`'ı siliyor** *(İnceleme buldu — teyit et)*
   `p2_enterprise.py:93`: IdP tekrar senkronda ortam kısıtları silinir; ABAC yokluğunda her şeye
   izin verdiği için açık kalır.
10. **DENY edilen onay token'ları iptal etmiyor** *(İnceleme buldu — teyit et)*
    `enterprise.py:447`: onaylanmış istek sonradan DENY edilince önceden verilmiş token'lar geçerli
    kalıyor (yalnız REVOKE iptal ediyor). → DENY'de de token iptali + `approval.revoked` yayınla.
11. **Audit zinciri yarış + timezone bağımlı hash** *(İnceleme buldu — teyit et)*
    `migrations/postgresql/002_platform_foundation.up.sql:262`: eşzamanlı insert'lerde zincir sırası
    bozulabilir; hash `occurred_at`'i metin olarak alıyor (session TimeZone'a bağlı) → doğrulayıcı
    sağlam logda "tampering" raporlayabilir.
12. **Down-migration'lar FORCE RLS altında boş tablo görüyor** *(İnceleme buldu — teyit et)*
    Dolu tabloları koruyan "boş değilse reddet" kontrolleri owner rolünde 0 satır görür → dolu
    tablo CASCADE ile düşebilir. → down-migration'ları BYPASSRLS/superuser bağlamında çalıştır veya
    kontrolleri ona göre yaz.
13. **Web-console proxy `..` atlatması** *(Ben doğruladım — düşük etki)*
    `apps/web-console/src/app/api/control/[...path]/route.ts:7`: segment regex'i `..` kabul ediyor,
    `v1` dışına çıkılabiliyor (control-api yine yetki kontrol ettiği için etki sınırlı). → `..` reddet.
14. **Küçük temizlikler** *(İnceleme buldu)*: üretilmiş dosyalar repoya commit'lenmiş
    (`tests/test_report.json`, `tests/fuzzer_bypasses.json`); P1 belgesindeki "tüm kayıtlar RLS
    altında" iddiası (bkz. madde 2) düzeltilmeli; tenant kotaları tenant admini tarafından
    değiştirilebiliyor / kampanya sayısı sınırsız (noisy-neighbor).

---

## 3. Entegrasyon işleri (Dev A hazır, Serkan'ın tarafına bağlanacak)

1. **Promotion policy → kampanya bulguları.** Dev A `CorpusPromotionPolicy`'yi hazırladı ve kendi
   `deep_analysis` job'ına bağladı (PR #10). Serkan'ın `apps/worker/src/jobs/campaigns.py`
   CONFIRMED bir finding ürettiğinde `DeepAnalysisJob(..., corpus_policy=...).analyze_finding(finding)`
   çağrısını tetiklemesi yeter; DB akışı onun alanı olduğu için birlikte bakalım.
2. **Revoke tüketicisi dağıtımı.** `AGENTGUARD_WORKER_ROLE=revoke` + `REDIS_URL`/`KAFKA_...`
   ortamı; k8s deployment'ı PR #9'da mevcut, gözden geçir.
3. **SecurityEvent forwarder.** Runtime, analytics kayıtlarını `security.events`'e `tenant_id`
   header'ıyla yayınlamaya hazır (PR #9). Gateway sürecinde `BackgroundForwarder` + Kafka
   producer'ı başlatmak dağıtım tarafı — birlikte bağlayalım.

---

## 4. Süreç (önemli)

- **`main`'e branch protection ekle:** force-push yasak + en az 1 PR onayı zorunlu. `45dc5cb`
  bir force-push'tu ve A1–A7 PR geçmişini `shared/main`'den sildi (kod korundu; eski geçmiş
  `origin/main = 006cafa` ve `feat/dev-a-sprint-a*` dallarında duruyor). Bunu repo sahibi olarak
  Serkan açmalı ki tekrarlanmasın.
- Bundan sonra herkes feature dalı → PR → karşı taraf inceler akışını izlesin.
