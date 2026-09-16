# Sprint B1 — İlk dilim teslimi

> **Tarihsel belge:** Bu dosya ilk B1 dilimini anlatır. Güncel tamamlanma durumu
> `P0_CLOSEOUT_TR.md` ve kökteki `MVP_READINESS_AUDIT_TR.md` içinde yer alır.

Amaç:
Organization → Workspace → Environment hiyerarşisini tenant-safe PostgreSQL, Control API, authorization, audit ve güvenlik testleriyle çalıştırmak.

Tamamlananlar:
Kanıta dayalı B1 gap analizi; tenant-scoped PostgreSQL tabloları ve FORCE RLS; composite FK/unique constraint; admin/reader yetkilendirmesi; hash olarak saklanan, expiry/revoke kontrollü servis tokenları; versioned CRUD API; bounded pagination/payload; idempotent create; optimistic concurrency; immutable audit; migration runner; platform CI tanımı.

Değiştirilen dosyalar:
ZIP dosyaları `agentguard-main/` altına açıldı. Orijinal ZIP ile byte karşılaştırmasında yalnız `apps/control-api/src/main.py` değişti; hiçbir orijinal dosya eksilmedi. Eklenenler:
- `apps/control-api/src/foundation.py`
- `apps/control-api/tests/test_foundation.py`
- `apps/control-api/requirements.txt` ve `requirements.lock.txt`
- `apps/control-api/README.md`, `B1_GAP_ANALYSIS.md`, `B1_DELIVERY_TR.md`
- `migrations/postgresql/001_tenancy.up.sql`, `001_tenancy.down.sql`, `migrate.py`
- `.github/workflows/platform-b1.yml`
Çalışma alanı köküne geçici sanal ortam/cache dosyalarını hariç tutan `.gitignore` eklendi.

Migration'lar:
001 upgrade; tekrar uygulama güvenliği; checksum ledger ve transaction advisory lock. Empty up/down/up gerçek PostgreSQL üzerinde geçti. Nonempty down reddedildi; audit korunuyor. `ag_control` rolü migration öncesi operator tarafından hazırlanır.

Contract/schema version'ları:
TenantContext 1.0.0 değişmedi. API /v1; OpenAPI 1.0.0 uygulama sürümü. Blank shared Control API schema değiştirilmedi. Yeni administrative resource DTO'ları runtime TenantContext kopyası değildir.

Tenant ve authorization etkisi:
Tenant ve rol authenticated token kaydından gelir. Payload tenant/role alanları reddedilir. RLS tüm domain/audit sorgularını tenant'a sınırlar. Admin yazabilir, reader okuyabilir. API owner/superuser/BYPASSRLS bağlantısını reddeder. Workspace bazlı ABAC ve kullanıcı üyelikleri henüz yoktur.

Policy/approval etkisi:
Policy/approval contract veya davranışı değişmedi; runtime evaluator eklenmedi.

Event/cache etkisi:
Bu dilimde cache veya broker bağımlılığı yok. Hiyerarşi PostgreSQL'den okunur. Runtime context dağıtımı ve versioned invalidation sonraki entegrasyon işidir.

Audit/observability:
İş değişikliği ve audit aynı transaction'da. Audit UPDATE/DELETE/TRUNCATE uygulama rolüne kapalı; trigger ek koruma sağlar. Correlation UUID, HTTP status ve duration loglanır; body, token ve customer name loglanmaz. OTel exporter ve kalıcı authorization-denial audit akışı tamamlanmadı. DB administrator'üne karşı WORM/kriptografik anchoring iddiası yoktur.

Çalıştırılan testler ve sonuçları:
2026-09-14: gerçek yerel PostgreSQL ile `python -m pytest apps/control-api/tests tests/contracts/test_contracts.py -q`: 18 passed, 0 skipped, 6.15 saniye.
6 Control API test fonksiyonu; 12 mevcut contract testi. API testleri çoklu senaryo içerir: cross-tenant CRUD/IDOR; direkt SQL RLS/FK; reader write/delete bypass; expiry/revoke; immutable audit; audit insert başarısızken iş kaydının rollback'i; unsafe DB role; idempotent create race; optimistic update race; payload/pagination ve sanitized DB failure; migration up/down/up ve nonempty rollback refusal.
Python compileall başarılı. ZIP karşılaştırması Developer A ve legacy dosyalarının korunduğunu doğruladı.
Test uyarıları: FastAPI/Starlette test istemcisi ve mevcut jsonschema RefResolver deprecation uyarıları; sandbox dışı çalıştırmada pytest cache yazma izni uyarısı. Testler başarısız olmadı. Hazırlanan GitHub Actions işi uzakta çalıştırılmadı.

Load/failure doğrulaması:
DB erişim hatası, audit yazma hatası ve concurrent write senaryoları geçti. 1K/10K req/s, PostgreSQL slowdown yük ölçümü, Redis/broker outage, cold cache, invalidation storm ve noisy-neighbor çalıştırılmadı. Performans SLO iddiası yok.

Deployment etkisi:
Production deployment/commit yapılmadı. İzole Python ortamı ve resmi PostgreSQL Windows binary paketi yerel test için kullanıldı. Test sunucusu kapatıldı. Production için secret manager, TLS ingress, request deadlines/admission limits ve sınırlı DB rolü gereklidir. Bağımlılıkların bu testte kullanılan tam sürümleri requirements.lock.txt dosyasındadır.

Rollback adımları:
Boş kurulumda owner DSN ile `python migrations/postgresql/migrate.py down`. Veri/audit oluşmuşsa API'yi durdurup önceki uygulama sürümüne dön; additive tabloları ve audit kayıtlarını koru. Down mevcut veriyi silmeyi reddeder.

Bilinen sınırlamalar:
Sprint B1 tamamlanmış değildir. Users/memberships, workspace ABAC, token provisioning/rotation endpoint'leri, OIDC/SSO, OTel exporter, bounded DB pool/admission control ve external audit retention eksik. Mevcut rol kapsamı organization geneli. PostgreSQL kimliği ve uygulama güvenilir sunucu sınırıdır; doğrudan DB kimliği müşterilere verilmez. İstenen README_DEVELOPER_B_v3.1_TR.md ZIP'te yok; mevcut README_DEVELOPER_B.md okundu ve çelişki görülmedi.

Developer A'dan beklenen entegrasyon:
Environment kayıtlarını validated TenantContext 1.0.0'a bağlayan adapter ile identity mapping/revocation ve invalidation teslim semantiği birlikte kararlaştırılmalı. Shared contract değişikliği yapılmadığı için version/migration bildirimi gerektiren bir değişiklik yok. Bu dosya handoff notudur; başka kişiye mesaj gönderilmedi.

Sonraki önerilen görev:
Users/memberships ve workspace-scoped RBAC/ABAC; operatörün servis identity provisioning/revocation akışını auditli hale getirme; ardından runtime context dağıtımı.
