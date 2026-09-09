import re
from typing import Dict, Any, Tuple
from pydantic import BaseModel

class InterceptionResult(BaseModel):
    allowed: bool
    action: str  # ALLOW / BLOCK
    tool_name: str
    arguments: Dict[str, Any]
    violation_reason: str
    rule_triggered: str

class AgentGuardInterceptor:
    def __init__(self, block_destructive_sql: bool = True, block_ssrf: bool = True):
        self.block_destructive_sql = block_destructive_sql
        self.block_ssrf = block_ssrf

    def _check_sql(self, query: str) -> Tuple[bool, str, str]:
        q_lower = query.lower()
        patterns = [
            (r"\bdrop\s+table\b", "DROP TABLE komutu tespit edildi."),
            (r"\bdelete\s+from\b", "DELETE komutu tespit edildi."),
            (r"\btruncate\b", "TRUNCATE işlemi tespit edildi."),
            (r"\bunion\s+select\b", "SQL Injection (UNION SELECT) tespit edildi."),
            (r";\s*drop", "Çoklu sorgu enjeksiyonu tespit edildi.")
        ]
        for pattern, reason in patterns:
            if re.search(pattern, q_lower):
                return False, reason, pattern
        return True, "SQL denetimi başarılı.", "NONE"

    def _check_path(self, path: str) -> Tuple[bool, str, str]:
        p_lower = path.lower()
        if "../" in p_lower or "..\\" in p_lower:
            return False, "Path Traversal (Dizin Atlama) tespit edildi.", "PATH_TRAVERSAL"
        sensitive_targets = ["/etc/passwd", "id_rsa", ".env", "windows/system32", "sam"]
        for target in sensitive_targets:
            if target in p_lower:
                return False, f"Hassas sistem dosyasına erişim engellendi: {target}", "SENSITIVE_FILE_ACCESS"
        return True, "Dosya yolu güvenli.", "NONE"

    def _check_network(self, url: str) -> Tuple[bool, str, str]:
        u_lower = url.lower()
        ssrf_targets = ["localhost", "127.0.0.1", "169.254.169.254", "0.0.0.0", "internal.corp"]
        for target in ssrf_targets:
            if target in u_lower:
                return False, f"SSRF / İç ağ metadata erişimi engellendi: {target}", "SSRF_ATTEMPT"
        return True, "Ağ çağrısı güvenli.", "NONE"

    def inspect(self, tool_name: str, arguments: Dict[str, Any]) -> InterceptionResult:
        name_lower = tool_name.lower()
        allowed = True
        reason = "Tüm güvenlik filtrelerinden onay alındı."
        rule = "NONE"

        if "sql" in name_lower or "db" in name_lower or "query" in name_lower:
            query_val = str(arguments.get("query", "") or arguments.get("sql", ""))
            allowed, reason, rule = self._check_sql(query_val)

        elif "file" in name_lower or "read" in name_lower or "write" in name_lower:
            path_val = str(arguments.get("path", "") or arguments.get("file_name", ""))
            allowed, reason, rule = self._check_path(path_val)

        elif "api" in name_lower or "http" in name_lower or "webhook" in name_lower or "fetch" in name_lower:
            url_val = str(arguments.get("url", "") or arguments.get("endpoint", ""))
            allowed, reason, rule = self._check_network(url_val)

        return InterceptionResult(
            allowed=allowed,
            action="ALLOW" if allowed else "BLOCK",
            tool_name=tool_name,
            arguments=arguments,
            violation_reason=reason,
            rule_triggered=rule
        )