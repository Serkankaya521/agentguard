import streamlit as st
from core.engine import AdversarialEngine
from core.interceptor import AgentGuardInterceptor
from core.audit_pdf import AuditPDFGenerator

st.set_page_config(page_title="AgentGuard Enterprise", page_icon="🛡️", layout="wide")

st.title("🛡️ AgentGuard: Otonom Ajan Güvenlik & Denetim Platformu")
st.caption("EU AI Act Madde 15 & OWASP Standartlarında AI Red-Teaming ve Runtime WAF")

tab_redteam, tab_waf = st.tabs(["🎯 1. Otomatik Red-Teaming (Denetim)", "🧱 2. Runtime Tool Interceptor (WAF)"])

with tab_redteam:
    c1, c2 = st.columns([1, 2])
    
    with c1:
        st.subheader("⚙️ Hedef Yapılandırması")
        model_choice = st.selectbox(
            "Hedef Model / Endpoint",
            ["mock-agent (Simülasyon)", "gpt-4o", "claude-3-5-sonnet", "ollama/llama3"]
        )
        api_key_input = st.text_input("Model API Key (Simülasyonda gerekmez)", type="password")
        api_base_input = st.text_input("Özel API Base URL (İsteğe bağlı)", placeholder="http://localhost:11434")
        
        run_btn = st.button("🚀 Kapsamlı Güvenlik Denetimini Başlat", type="primary", use_container_width=True)

    with c2:
        st.subheader("📊 Denetim Çıktıları")
        if run_btn:
            engine = AdversarialEngine(model_name=model_choice, api_key=api_key_input, api_base=api_base_input)
            progress = st.progress(0)
            status = st.empty()
            
            def on_progress(pct, msg):
                progress.progress(pct)
                status.text(msg)

            report = engine.run_full_audit(progress_callback=on_progress)
            st.session_state["report_data"] = report
            st.success(f"Denetim tamamlandı! Süre: {report.execution_time_seconds}s")

    if "report_data" in st.session_state:
        rep = st.session_state["report_data"]
        st.divider()
        
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Test Sayısı", rep.total_vectors_tested)
        m2.metric("Tespit Edilen Açık", rep.vulnerabilities_detected)
        m3.metric("Risk Skoru", f"%{rep.risk_score_percentage}")
        
        status_color = "red" if rep.compliance_status == "FAILED" else "green"
        m4.markdown(f"**EU AI Act Uyumu**\n### :{status_color}[{rep.compliance_status}]")

        st.subheader("🔍 Zafiyet Dökümü")
        for f in rep.findings:
            with st.expander(f"🔴 [{f.severity.value}] {f.vector_id} - {f.vector_name}"):
                st.markdown(f"**Kategori:** `{f.category.value}`")
                st.markdown("**Saldırı Yükü:**")
                st.code(f.attack_payload, language="text")
                st.markdown("**Ajanın Sızdırdığı Yanıt:**")
                st.error(f.response_text)
                st.markdown(f"**💡 Çözüm / Savunma Tavsiyesi:** {f.mitigation_advice}")

        pdf_bytes = AuditPDFGenerator.build(rep)
        st.download_button(
            label="📄 Resmi EU AI Act Denetim Raporunu İndir (PDF)",
            data=pdf_bytes,
            file_name="AgentGuard_Audit_Report.pdf",
            mime="application/pdf",
            use_container_width=True
        )

with tab_waf:
    st.subheader("🧱 Pre-Execution Tool-Calling Güvenlik Kalkanı")
    st.write("Ajanın arka planda tetiklemek istediği fonksiyon çağrılarını (Tool Calls) çalıştırmadan önce yakalayın.")

    interceptor = AgentGuardInterceptor()
    
    col_w1, col_w2 = st.columns(2)
    with col_w1:
        tool_type = st.selectbox("Test Edilecek Araç Türü", ["Veritabanı (SQL)", "Dosya Sistemi", "Dış API / Webhook"])
        
        if tool_type == "Veritabanı (SQL)":
            tool_name = "execute_sql_query"
            sql_input = st.text_area("SQL Sorgusu", "SELECT id, email FROM users WHERE role='admin'; DROP TABLE logs;--")
            args = {"query": sql_input}
        elif tool_type == "Dosya Sistemi":
            tool_name = "read_local_file"
            path_input = st.text_input("Dosya Yolu", "../../etc/passwd")
            args = {"path": path_input}
        else:
            tool_name = "http_request"
            url_input = st.text_input("İstek URL", "http://169.254.169.254/latest/meta-data/")
            args = {"url": url_input}

        inspect_btn = st.button("🛡️ Tool Çağrısını İncele", use_container_width=True)

    with col_w2:
        if inspect_btn:
            result = interceptor.inspect(tool_name, args)
            if result.action == "BLOCK":
                st.error(f"❌ **EYLEM BLOKE EDİLDİ!**\n\n**Gerekçe:** {result.violation_reason}\n\n**Kural:** `{result.rule_triggered}`")
            else:
                st.success(f"✅ **EYLEME İZİN VERİLDİ.**\n\n**Durum:** {result.violation_reason}")
            st.json(result.dict())