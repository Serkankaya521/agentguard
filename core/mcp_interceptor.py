import re
from typing import Dict, Any, Tuple
from pydantic import BaseModel

class MCPActionVerdict(BaseModel):
    """Gümrük kapısının verdiği resmi karar belgesi."""
    is_allowed: bool
    status: str  # ALLOWED (Geçti) veya BLOCKED (Engellendi)
    tool_name: str
    risk_level: str  # LOW, HIGH, CRITICAL
    reason: str
    detected_pattern: str

class MCPSecurityInterceptor:
    """
    AgentGuard MCP Canlı Güvenlik Kalkanı.
    Ajanın dış sistemleri çağıran MCP isteklerini çalıştırmadan önce yakalar ve denetler.
    """

    def __init__(self):
        # Yıkıcı ve tehlikeli SQL kalıpları
        self.sql_danger_patterns = [
            (r"\bdrop\s+table\b", "Veritabanı tablosunu tamamen silme girişimi (DROP TABLE)"),
            (r"\bdelete\s+from\b", "Toplu veri silme girişimi (DELETE FROM)"),
            (r"\btruncate\b", "Tabloyu sıfırlama girişimi (TRUNCATE)"),
            (r"\bunion\s+select\b", "SQL Enjeksiyonu ile yetkisiz veri çekme (UNION SELECT)"),
            (r";\s*drop", "Çoklu sorgu ile gizli silme komutu enjekte etme"),
            (r"or\s+1\s*=\s*1", "Kimlik doğrulama baypas SQL enjeksiyonu")
        ]

        # Hassas dosya ve dizin atlama desenleri
        self.file_danger_patterns = [
            (r"\.\./|\.\.\\", "Dizin atlama ile sistem klasörlerine sızma (Path Traversal)"),
            (r"id_rsa|id_dsa|\.ssh", "SSH gizli anahtarlarını çalma girişimi"),
            (r"\.env|config\.json", "Ortam şifrelerini ve API anahtarlarını okuma girişimi"),
            (r"/etc/passwd|/etc/shadow", "İşletim sistemi kullanıcı listesini okuma girişimi"),
            (r"windows/system32", "Kritik Windows sistem dosyalarına müdahale")
        ]

        # Dışarıya veri kaçırma / SSRF desenleri
        self.network_danger_patterns = [
            (r"169\.254\.169\.254", "Bulut sunucu AWS/GCP kimlik metadata servisine erişim (SSRF)"),
            (r"localhost|127\.0\.0\.1|0\.0\.0\.0", "Şirket içi kapalı ağ servislerini tarama (Local SSRF)"),
            (r"attacker|leak|webhook\.site", "Yetkisiz harici sunucuya veri kaçırma şüphesi")
        ]

    def _inspect_sql(self, args: Dict[str, Any]) -> Tuple[bool, str, str, str]:
        """SQL çağıran araçların argümanlarını inceler."""
        query = str(args.get("query", "") or args.get("sql", "")).lower()
        
        for pattern, desc in self.sql_danger_patterns:
            if re.search(pattern, query):
                return False, "CRITICAL", desc, pattern
                
        return True, "LOW", "SQL sorgusu güvenlik analizinden geçti.", "NONE"

    def _inspect_file(self, args: Dict[str, Any]) -> Tuple[bool, str, str, str]:
        """Dosya okuma/yazma araçlarının argümanlarını inceler."""
        path = str(args.get("path", "") or args.get("file_name", "") or args.get("filepath", "")).lower()
        
        for pattern, desc in self.file_danger_patterns:
            if re.search(pattern, path):
                return False, "CRITICAL", desc, pattern
                
        return True, "LOW", "Dosya yolu erişim için güvenli.", "NONE"

    def _inspect_network(self, args: Dict[str, Any]) -> Tuple[bool, str, str, str]:
        """Dış internete / API'ye istek atan araçları inceler."""
        url = str(args.get("url", "") or args.get("endpoint", "") or args.get("host", "")).lower()
        
        for pattern, desc in self.network_danger_patterns:
            if re.search(pattern, url):
                return False, "HIGH", desc, pattern
                
        return True, "LOW", "Ağ çağrısı ve hedef URL güvenli.", "NONE"

    def intercept(self, tool_name: str, arguments: Dict[str, Any]) -> MCPActionVerdict:
        """
        Ajanın çağırdığı MCP aracını yakalar, inceler ve onay/ret kararı döner.
        """
        t_name = tool_name.lower()
        allowed = True
        risk = "LOW"
        reason = "İşlem güvenli bulundu."
        pattern_hit = "NONE"

        # 1. SQL Araçları (Postgres, SQLite vb.)
        if any(k in t_name for k in ["sql", "query", "database", "db"]):
            allowed, risk, reason, pattern_hit = self._inspect_sql(arguments)

        # 2. Dosya Sistemi Araçları (Filesystem MCP)
        elif any(k in t_name for k in ["file", "read", "write", "fs"]):
            allowed, risk, reason, pattern_hit = self._inspect_file(arguments)

        # 3. HTTP & Dış Ağ Araçları (Fetch / Webhook MCP)
        elif any(k in t_name for k in ["http", "fetch", "api", "request", "webhook"]):
            allowed, risk, reason, pattern_hit = self._inspect_network(arguments)

        return MCPActionVerdict(
            is_allowed=allowed,
            status="ALLOWED" if allowed else "BLOCKED",
            tool_name=tool_name,
            risk_level=risk,
            reason=reason,
            detected_pattern=pattern_hit
        )