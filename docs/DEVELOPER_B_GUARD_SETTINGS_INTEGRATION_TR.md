# Batu — Çıkış koruması modunu konsol ayarından oku

Konsol tarafında ortam bazında **koruma modu** artık ayarlanabiliyor ve saklanıyor:
`platform.runtime_guard_settings` (tenant + environment + guard için tek satır).

Alanlar:
- `mode` — `off` | `shadow` | `enforce` (varsayılan `shadow`)
- `action` — `mask` | `stop` (yalnızca `enforce`'ta anlamlı, varsayılan `mask`)
- `version`, `updated_by`, `updated_at`

## Senden beklenen tek şey

`guard_egress(...)` çağrısındaki sabit `mode`/`action` yerine, ilgili ortamın bu
tablodaki satırını oku:

- Satır yoksa → `mode='shadow'`, `action='mask'` (güvenli varsayılan; asla sessizce
  `off` ya da `enforce` olma).
- `mode='off'` → egress taramasını atla.
- `mode='shadow'` / `enforce` → bugünkü davranış; `enforce`'ta `action` belirler
  (mask / stop).

Hot-path kuralı: bu değeri her istekte DB'den çekme. Derlenmiş politikaya (compiled
policy) gömülüp cache'den okunması en temizi; ya da ortam başına L1 cache + olay
tabanlı invalidation. Ayarın okunması senin alanın (runtime); yazılması + arayüzü
bende (kontrol düzlemi), bitti.

Not: Tablo tenant-kapsamlı (FORCE RLS). Sır değeri burada da tutulmuyor; yalnızca mod.
