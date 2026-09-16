# Developer B P1 — Operasyon ve kurumsal kullanım planı

Ana prompt P1 için numaralı bir backlog tanımlamıyor. Bu plan, `README_DEVELOPER_B.md`
sahiplikleri ve master mimarinin Control Plane sorumluluklarından türetilmiştir.

1. Tenant kotaları, retention ve operasyon kontrolleri.
2. Secret-reference kullanan kurumsal entegrasyon kayıtları ve teslim worker'ları.
3. P4 izole kuyruğunda asenkron raporlama ve S3-compatible çıktı saklama.
4. ClickHouse telemetry/analytics ingest ve tenant-scoped sorgu API'si.
5. Control API'yi kullanan, karar üretmeyen Web Console.
6. Production CI/CD, backup/restore, retention ve failure runbook'ları.

P1 hiçbir normal runtime isteğini PostgreSQL, ClickHouse, rapor üretimi veya dış
entegrasyonla senkron olarak bağlamaz. Ortak contract değişiklikleri ayrıca
versionlanır; bu ilk dilim mevcut JobEnvelope 1.0.0 semantiğini kullanır.
