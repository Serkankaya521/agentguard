# Developer B → Developer A handoff

## Teslim durumu

Developer B'nin tenant-aware platform, persistence, enterprise workflow, operasyon ve
Web Console kapsamı yerel release-candidate/MVP düzeyinde tamamlandı. Canlı production
rollout yapılmadı.

## Migration ve sözleşmeler

- PostgreSQL migration zinciri `001–006`; `/health/ready` tam olarak bu zinciri ister.
- `006_continuous_campaigns` campaign, run, candidate ve regression tablolarını FORCE RLS
  altında ekler; dolu tablolarda down migration bilinçli olarak reddedilir.
- Finding ve JobEnvelope sözleşmeleri `1.0.0` olarak kaldı. OpenAPI additive genişledi.
- Target adapter MVP sınırı `openai_compatible`, secret resolver sınırı `env://`, kontrollü
  concurrency sınırı `1`dir.

## Tenant ve authorization

- Tüm yeni kayıtlar tenant context taşır; campaign parent'ları workspace/environment
  composite ilişkileriyle doğrulanır.
- Campaign mutation ve execution `campaign.manage`; okuma `tenant.read` gerektirir.
- Secret ve canary değerleri API response'una veya campaign tablosuna yazılmaz.
- Migration 006 tabloları cross-tenant FORCE RLS testine dahildir.

## Event, cache ve worker etkisi

- Scheduler due campaign'i deterministik schedule-slot ID ile P3 `red_team.execute` işine çevirir.
- Security worker yalnız `red_team.execute` ve `regression.execute` işlerini claim eder;
  platform worker bu işleri alamaz.
- Runtime hot path, policy cache ve cache invalidation sözleşmesi değişmedi.
- Retry/dead-letter sonrası son hata campaign run'ı `failed` durumuna geçirir.

## Evidence ve gözlemlenebilirlik

- Her target isteğinin lineage, fitness ve response hash'i tenant-scoped kaydedilir.
- Ham target yanıtı veritabanına yazılmaz. Evidence JSON object store'a yazılır, SHA-256
  ile doğrulanır ve `evidence_objects` üzerinden run'a bağlanır.
- Payload'da bulunmayan target-side canary yanıtta görülürse Finding `CONFIRMED` olur.
- Regression sonucu Finding'i `RESOLVED_VERIFIED` veya `REOPENED` durumuna taşır.
- Control API correlation/audit zinciri korunur; campaign write/status/run talepleri auditlenir.

## Doğrulama

- AEGIS red-team contract: `15 passed`.
- Tam Python repository: `182 passed, 14 skipped`.
- Temiz PostgreSQL, migration 001–006 ve platform E2E: `40 passed`.
- Web Console typecheck/build: başarılı, `16` rota; npm audit: `0 vulnerabilities`.
- Kubernetes YAML parse ve security worker import smoke: başarılı.

## Deployment ve rollback

- Sıra: migration 001–006 → Control API readiness → object store/Redis/broker → platform
  worker'lar → security worker → schedule materializer → Web Console.
- Uygulama rollback'i önceki immutable image'a döner. Migration 006 yalnız ilgili tablolar
  boşsa down edilir; veri varsa additive şema yerinde bırakılır.
- Ayrıntılar `infra/runbooks/PLATFORM_OPERATIONS.md` içindedir.

## Bilinen sınırlar ve Developer A bağımlılıkları

- Canlı IdP, Kafka/Redpanda, Redis HA, S3/MinIO ve ClickHouse cluster testi bu hostta yapılmadı.
- Developer A'nın sonraki entegrasyonları: MCP ve framework adapterları, tool/resource side-effect
  observer, dağıtık in-flight kill switch, canlı target authorization/RoE ve response-aware
  motorun AEGIS corpus/vulnerability-DNA promotion politikası.
- Shared SecurityEvent producer production Kafka ACL altında tenant header göndermeli;
  approval revoke consumer shared Redis replay guard'a bağlanmalıdır.
