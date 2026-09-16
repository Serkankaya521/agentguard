import re
from typing import Dict, Any, List, Tuple

class AgentGuardFirewall:
    """
    AgentGuard Çalışma Zamanı (Runtime) Güvenlik Kalkanı.
    Ajanın çağırdığı araçları (Tool / Function Calling) çalıştırmadan önce yakalar
    ve parametrelerdeki yetki aşımı, tehlikeli komut ve veri sızıntısı girişimlerini engeller.
    """

    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.blocked_calls_log = []

    def _inspect_sql_tool(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        """SQL sorgusu çalıştıran araçları denetler"""
        query = str(args.get("query", "")).lower()
        
        # Kritik SQL Injection ve Yıkıcı Komut Desenleri
        forbidden_patterns = [
            r"\bdrop\s+table\b",
            r"\bdelete\s+from\b",
            r"\btruncate\b",
            r"\bunion\s+select\b",
            r"\balter\s+table\b",
            r"--",
            r";\s*drop",
            r"or\s+1\s*=\s*1"
        ]
        
        for pattern in forbidden_patterns:
            if re.search(pattern, query):
                return False, f"Yıkıcı SQL komutu veya Enjeksiyon tespit edildi: '{pattern}'"
        
        return True, "SQL güvenli onaylandı."

    def _inspect_file_tool(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        """Dosya okuma/yazma araçlarını denetler (Path Traversal engelleme)"""
        path = str(args.get("path", "") or args.get("file_name", "")).lower()
        
        # Hassas dosya erişimleri ve dizin atlama desenleri
        if "../" in path or "..\\" in path:
            return False, "Path Traversal (Dizin Atlama) girişimi tespit edildi."
            
        sensitive_files = ["/etc/passwd", "id_rsa", ".env", "config.json", "windows/system32"]
        for sensitive in sensitive_files:
            if sensitive in path:
                return False, f"Hassas sistem dosyasına erişim engellendi: '{sensitive}'"
                
        return True, "Dosya erişimi onaylandı."

    def _inspect_api_tool(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        """Dış API veya Webhook çağıran araçları denetler (SSRF & Veri Kaçırma)"""
        url = str(args.get("url", "") or args.get("endpoint", "")).lower()
        
        # SSRF (İç ağ tarama) ve yetkisiz dış aktarım kontrolü
        blocked_domains = ["localhost", "127.0.0.1", "169.254.169.254", "internal.corp"]
        for domain in blocked_domains:
            if domain in url:
                return False, f"İç ağa veya metadata servisine SSRF çağrısı engellendi: '{domain}'"
                
        return True, "API çağrısı onaylandı."

    def inspect_tool_call(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ajanın çağırmak istediği aracı inceler.
        Geriye: {'allowed': True/False, 'action': 'ALLOW'/'BLOCK', 'reason': '...'} döner.
        """
        tool_lower = tool_name.lower()
        allowed = True
        reason = "Güvenlik onayından geçti."

        if "sql" in tool_lower or "database" in tool_lower or "db" in tool_lower:
            allowed, reason = self._inspect_sql_tool(tool_args)
        elif "file" in tool_lower or "read" in tool_lower or "write" in tool_lower:
            allowed, reason = self._inspect_file_tool(tool_args)
        elif "api" in tool_lower or "http" in tool_lower or "webhook" in tool_lower:
            allowed, reason = self._inspect_api_tool(tool_args)

        action = "ALLOW" if allowed else "BLOCK"
        
        log_entry = {
            "tool": tool_name,
            "args": tool_args,
            "action": action,
            "reason": reason
        }
        
        if not allowed:
            self.blocked_calls_log.append(log_entry)

        return log_entry