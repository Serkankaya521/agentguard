# AgentGuard yerel MVP çalıştırma

## Tam servis kümesi

Tam küme yalnızca loopback portlarına açılır:

- PostgreSQL: 127.0.0.1:55433
- Redis: 127.0.0.1:56379
- Redpanda/Kafka: 127.0.0.1:59092
- MinIO API/konsol: 127.0.0.1:59000 / 59002
- ClickHouse HTTP/native: 127.0.0.1:58123 / 59001

Windows'ta ilk kez WSL özelliği yönetici PowerShell ile
".\\scripts\\enable_wsl_admin.ps1" komutuyla etkinleştirilmelidir. Bilgisayar yeniden başladıktan
ve Docker veya Podman WSL arka ucu kurulduktan sonra
".\\scripts\\local_stack.ps1 start" ve
".\\scripts\\local_stack.ps1 status" komutları çalıştırılır.

Parolalar ilk çalıştırmada kriptografik olarak üretilir,
infra/docker/secrets altında kalır ve Git tarafından yok sayılır.

## Yetkili uçtan uca kampanya

Kalıcı yerel PostgreSQL'i ve yalnızca 127.0.0.1 üzerinde açılan proje hedef
ajanını kullanır. Betik RoE kaydını hedef origin ve iki test secret'ıyla sınırlar.

Çalıştırma:

1. ..\\.venv\\Scripts\\python.exe scripts\\local_postgres.py start
2. ..\\.venv\\Scripts\\python.exe scripts\\run_authorized_e2e.py

Başarılı çıktı zinciri:

HTTP target -> mutations -> sealed evidence -> confirmed finding -> hardening ->
regression -> RESOLVED_VERIFIED

Kanıt içeriği .local/evidence altında, sorgulanabilir kayıtlar yerel PostgreSQL
platform şemasında tutulur.
