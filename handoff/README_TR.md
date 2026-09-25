# Batuhan veritabanı devri

agentguard-batuhan.bundle şifrelenmiş bir pakettir. Paket şunları içerir:

- PostgreSQL host/IP ve port bilgileri
- postgres owner kullanıcısının parolası
- ag_control uygulama kullanıcısının parolası
- Güncel AgentGuard PostgreSQL yedeği

Şifre çözme anahtarı güvenlik nedeniyle GitHub'a konulmaz. Serkan anahtarı
Batuhan'a ayrı ve özel bir kanaldan iletir.

Batuhan'ın çalıştıracağı komut:

    python scripts/decrypt_db_handoff.py --key "SERKAN_DAN_GELEN_ANAHTAR"

Komut BATUHAN_DB_HANDOFF.zip dosyasını oluşturur. Aynı canlı PostgreSQL
sunucusuna doğrudan bağlanmak için iki bilgisayarın aynı özel ağda veya bir VPN
üzerinde olması gerekir. Yedeği kendi bilgisayarına geri yüklemek için aynı ağ
gerekmez.
