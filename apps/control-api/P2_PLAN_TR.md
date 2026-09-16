# Developer B P2 planı

Ana çalışma promptu P2 için numaralı backlog vermediğinden bu sıra master architecture
ve Developer B sahipliklerinden türetilmiştir:

1. Tenant-safe SCIM provisioning ve OIDC tenant mapping yönetimi.
2. Jira, ServiceNow, Slack, Teams, SIEM ve source-control payload adapter'ları.
3. Scheduled report templates ve billing provider export.
4. Local prototype senaryoları ile production adapter contract parity testleri.
5. Production environment chaos, backup/restore ve recovery drill otomasyonu.

İlk dilim SCIM user provisioning'dir. Tenant hiçbir SCIM payload'ından kabul edilmez;
authenticated service identity context'inden türetilir.
