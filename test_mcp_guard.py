from core.mcp_interceptor import MCPSecurityInterceptor

def main():
    print("[*] AgentGuard MCP Canlı Güvenlik Kalkanı Test Ediliyor...\n" + "="*70)
    guard = MCPSecurityInterceptor()

    # Senaryo 1: Masum bir müşteri sorgusu
    print("\n--- 🧪 TEST 1: Masum Müşteri Arama İsteği ---")
    req1_tool = "postgres_query"
    req1_args = {"query": "SELECT name, email FROM customers WHERE id = 104;"}
    res1 = guard.intercept(req1_tool, req1_args)
    print(f"Araç: {res1.tool_name} | Argüman: {req1_args}")
    print(f"Karar: [{'✅ ' + res1.status if res1.is_allowed else '❌ ' + res1.status}] -> {res1.reason}")

    # Senaryo 2: Hacklenmiş ajanın veritabanını silmeye çalışması
    print("\n--- 🧪 TEST 2: Hacklenmiş Ajan (Tablo Silme Saldırısı) ---")
    req2_tool = "postgres_query"
    req2_args = {"query": "SELECT * FROM users; DROP TABLE customers; --"}
    res2 = guard.intercept(req2_tool, req2_args)
    print(f"Araç: {res2.tool_name} | Argüman: {req2_args}")
    print(f"Karar: [{'✅ ' + res2.status if res2.is_allowed else '❌ ' + res2.status}] -> {res2.reason}")
    print(f"Risk Seviyesi: {res2.risk_level} | Yakalanan Kural: {res2.detected_pattern}")

    # Senaryo 3: Ajanın şifre dosyasını çalmaya çalışması
    print("\n--- 🧪 TEST 3: Şifre Dosyası Çalma Girişimi (Path Traversal) ---")
    req3_tool = "read_file"
    req3_args = {"path": "../../etc/passwd"}
    res3 = guard.intercept(req3_tool, req3_args)
    print(f"Araç: {res3.tool_name} | Argüman: {req3_args}")
    print(f"Karar: [{'✅ ' + res3.status if res3.is_allowed else '❌ ' + res3.status}] -> {res3.reason}")
    print(f"Risk Seviyesi: {res3.risk_level} | Yakalanan Kural: {res3.detected_pattern}")

    print("\n" + "="*70 + "\n[+] MCP Güvenlik Kalkanı Testleri Başarıyla Tamamlandı!")

if __name__ == "__main__":
    main()