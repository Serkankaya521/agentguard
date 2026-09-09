# AgentGuard Enterprise v3.1
## Master Architecture + Claude / ChatGPT Handoff Guide

> Bu dosya AgentGuard Enterprise v3.1 için ana mimari kaynaktır.
> İnsan geliştiriciler ve Claude/ChatGPT gibi coding-agent'lar işe başlamadan önce bu dosyayı okumalıdır.

---

# 1. Vizyon

AgentGuard; AI ajanları, MCP sunucuları, tool çağrıları, model trafiği ve çok-adımlı agent davranışları için:

- Runtime Defense
- Autonomous Red Team
- Adaptive Attack Amplification
- Continuous Learning
- Attack Knowledge Graph
- Vulnerability Memory
- Remediation Verification
- Enterprise Governance
- Evidence & Reporting

özelliklerini tek platformda birleştiren bir **AI Agent Security Platform** olacaktır.

Hedef basit bir prompt scanner veya statik güvenlik aracı değildir.

Hedef:

> AI ajanlarına çalışma anında güvenlik sınırı koyan, izinli ortamlarda sürekli saldıran, her testten öğrenen, yeni saldırı hipotezleri geliştiren ve her kritik yetki artışını insan onayından geçiren bir güvenlik zekâsı.

---

# 2. Temel Güvenlik İlkesi

AgentGuard'ın öğrenmesi sürekli olacaktır.

Ancak:

**Learning autonomy != privilege autonomy**

AEGIS:

- yeni saldırı varyasyonları üretebilir,
- yeni hipotezler çıkarabilir,
- geçmiş saldırılardan öğrenebilir,
- yeni detector/policy adayları önerebilir,
- yeni test senaryoları geliştirebilir,
- kendi performansını ölçebilir,

fakat insan onayı olmadan:

- production yetkisini artıramaz,
- secret erişimi açamaz,
- tenant sınırını genişletemez,
- destructive test açamaz,
- policy'yi gevşetemez,
- kendi kodunu production'a deploy edemez,
- audit log silemez veya değiştiremez.

Production değişiklik akışı:

Proposal
→ Tests
→ Historical Evaluation
→ Sandbox
→ Shadow Mode
→ Canary
→ Human Approval
→ Signed Release
→ Production

---

# 3. Ana Sistem Mimarisi

```text
                         AGENTGUARD ENTERPRISE V3
                                  |
              +-------------------+-------------------+
              |                                       |
         CONTROL PLANE                          SECURITY DATA PLANE
              |                                       |
   Tenant / Workspace / SSO                   Runtime Gateway
   Asset Registry                             MCP Gateway
   Policy Studio                              Policy Enforcement
   Findings                                   Trajectory Engine
   Approvals                                  Evidence Capture
   Reports                                    Runtime Detectors
   Integrations                               HITL / Execution Gate
              |                                       |
              +-------------------+-------------------+
                                  |
                           AEGIS SECURITY BRAIN
                                  |
      +---------------------------+---------------------------+
      |               |               |                     |
   Memory         Attack Graph      Planner            Learning Engine
      |               |               |                     |
      +---------------------------+---------------------------+
                                  |
                      EVOLUTIONARY RED TEAM ENGINE
                                  |
              Mutation / Crossover / Chain Explorer
                                  |
                    Isolated Execution Workers
                                  |
                               Evidence
                                  |
                          Finding / Regression
```

---

# 4. Dağıtım Birimleri

İlk aşamada gereksiz mikroservis çoğalması yapılmayacaktır.

Başlangıç deployable birimleri:

```text
apps/
  control-api/
  runtime-gateway/
  worker/
  web-console/

packages/
  domain/
  contracts/
  policy/
  detectors/
  aegis/
  attack-graph/
  evidence/
  auth/
  observability/

schemas/
  events/
  api/
  findings/
  policies/
```

Trafik büyüdüğünde aşağıdaki bileşenler bağımsız servis olabilir:

- Runtime Policy Service
- Trajectory Service
- Attack Graph Service
- AEGIS Planner
- Red Team Worker Fleet
- Evidence Service
- Reporting Service

---

# 5. Runtime Security Pipeline

```text
Agent / MCP Client
        |
        v
Runtime Gateway
        |
        v
Normalize SecurityEvent
        |
        v
Identity + Tenant + Environment Context
        |
        v
Capability Registry
        |
        v
Policy Decision Point
        |
        +--> deterministic detectors
        +--> trajectory risk
        +--> behavioral signals
        +--> AEGIS recommendation
        |
        v
Decision
 ALLOW
 BLOCK
 REQUIRE_APPROVAL
 SANDBOX
 REDACT
 STEP_UP_AUTH
        |
        v
Execution Gate
        |
        v
Tool / MCP / API / Resource
        |
        v
Evidence + Telemetry + Learning Event
```

---

# 6. Tool Capability Registry

Tool adından yetki tahmini yapılmayacaktır.

Her tool açık capability metadata ile kayıt edilir.

Örnek:

```json
{
  "tool_id": "postgres_read_table",
  "capabilities": ["database.read"],
  "resource_patterns": ["crm.*"],
  "side_effect": "none",
  "data_classes": ["PII"],
  "risk": "high",
  "approval_mode": "conditional"
}
```

Ana capability aileleri:

```text
database.read
database.write
database.delete
filesystem.read
filesystem.write
network.egress
network.admin
email.send
payment.execute
identity.read
identity.admin
secret.read
code.execute
shell.execute
mcp.invoke
agent.delegate
```

Unknown capability kritik bağlamda varsayılan olarak güvenilir sayılmaz.

---

# 7. Policy Engine

PEP/PDP ayrımı kullanılacaktır.

PEP:
- enforcement noktasıdır.

PDP:
- karar üretir.

Kararda dikkate alınacaklar:

- tenant
- user / service identity
- role
- agent identity
- environment
- capability
- target resource
- data sensitivity
- prior trajectory
- runtime detector signals
- approval status
- risk budget
- time/context constraints

---

# 8. AEGIS — Evolving Intelligence Core

AEGIS sistemin öğrenen güvenlik beynidir.

## 8.1 Dört Hafıza

### Episodic Memory
Geçmiş saldırılar ve sonuçları.

### Semantic Memory
OWASP, MITRE ATLAS, CWE, CVE, vendor advisories, araştırmalar ve internal knowledge.

### Procedural Memory
Belirli güvenlik problemlerinde hangi test stratejilerinin uygulanacağı.

### Strategic Memory
Hangi mimaride hangi saldırı ailesinin daha başarılı olduğu.

---

# 9. Öğrenme Katmanları

## Hot Learning
Anında:

Attack
→ Result
→ Memory
→ Strategy score
→ Attack Graph update

Model ağırlıkları değişmez.

## Warm Learning
Saatlik/günlük:

- yeni attack template adayları
- yeni detector adayları
- yeni policy önerileri
- false-positive analizi
- risk model güncellemeleri

## Cold Learning
Kontrollü model eğitimi:

Curated Dataset
→ Poisoning Check
→ Deduplication
→ Training
→ Offline Evaluation
→ Human Gate
→ Versioned Security Model

---

# 10. Adaptive Attack Amplification

Bir finding bulunduğunda test bitmez.

```text
Finding
  |
  v
Root Cause Analysis
  |
  v
Vulnerability DNA
  |
  v
Variant Generation
  |
  +--> syntax/context variations
  +--> state variations
  +--> role variations
  +--> capability variations
  +--> chain variations
  +--> tool/MCP route variations
  |
  v
Controlled 2X / 5X / 10X / 20X / 50X Exploration
  |
  v
Saturation / Safety Budget Check
  |
  v
Evidence-backed Findings
```

50X aynı payload'ı 50 kere yollamak değildir.
Amaç saldırı uzayını daha akıllı araştırmaktır.

---

# 11. Evolutionary Adversarial Search

Mevcut genetic fuzzer ileri taşınacaktır.

Attack Genome örneği:

```text
G1 technique
G2 context strategy
G3 prompt structure
G4 encoding family
G5 agent state
G6 target capability
G7 timing
G8 chain depth
G9 privilege context
G10 memory state
```

Fitness sinyalleri:

- boundary crossing
- behavioral deviation
- policy evasion
- chain depth
- reproducibility
- evidence quality

Mutation ve crossover yalnızca yetkili kapsamda çalışır.

---

# 12. Attack Knowledge Graph

Temel düğümler:

```text
Tenant
Asset
Agent
Model
Tool
MCP Server
Capability
Resource
Identity
Policy
Attack
Technique
Finding
Evidence
Fix
Regression
```

Temel ilişkiler:

```text
AGENT USES TOOL
TOOL HAS CAPABILITY
TOOL ACCESSES RESOURCE
ATTACK TARGETS AGENT
ATTACK TRIGGERS TOOL
FINDING AFFECTS ASSET
FIX RESOLVES FINDING
REGRESSION VALIDATES FIX
```

Bu graph gelecekte AgentGuard'ın en önemli veri/IP avantajlarından biri olacaktır.

---

# 13. Vulnerability DNA

Her confirmed finding aşağıdaki fingerprint'i üretir:

```text
root cause
affected architecture
model family
agent type
tool capability
permission topology
MCP topology
required preconditions
successful mutations
failed mutations
side effects
evidence pattern
remediation
regression fingerprint
```

Yeni sistemlerde similarity matching ile test önceliği belirlenir.

---

# 14. Evidence Standardı

LLM'nin "başarılı saldırı" demesi tek başına yeterli değildir.

Tercih edilen evidence:

- deterministic response
- database state
- permission change
- file hash/state
- policy trace
- tool output
- outbound connection event
- token scope
- agent state
- telemetry trace

Finding statüleri:

```text
SUSPECTED
VALIDATING
CONFIRMED
FIX_PROPOSED
RETESTING
RESOLVED_VERIFIED
REOPENED
FALSE_POSITIVE
```

---

# 15. Regression Memory

Her resolved finding kalıcı bir regression testine dönüşür.

```text
Finding discovered
→ fix deployed
→ original exploit replay
→ amplified variants
→ attack-chain replay
→ PASS
→ RESOLVED_VERIFIED

Future deploy
→ regression suite
→ old weakness returns
→ REOPENED
```

---

# 16. Self-Improvement Governance

AEGIS yeni detector veya strategy üretebilir.

Ancak production deploy edemez.

```text
AEGIS Proposal
→ Unit Tests
→ Historical Corpus Evaluation
→ False-positive Evaluation
→ Performance Evaluation
→ Sandbox
→ Shadow
→ Canary
→ Human Approval
→ Signed Artifact
→ Production
```

Ayrıca tüm versiyonlar rollback edilebilir olmalıdır.

---

# 17. AgentGuard-vs-AgentGuard

Her release AgentGuard'ın kendi red-team twin'i tarafından test edilir.

Test alanları:

- sandbox escape
- policy bypass
- cross-tenant access
- approval bypass
- memory poisoning
- audit tampering
- secret access
- privilege escalation
- unsafe self-modification

---

# 18. Veri Katmanı

Önerilen başlangıç:

```text
PostgreSQL
- tenant
- users
- assets
- policies
- findings
- approvals
- config

Redis
- runtime cache
- rate limits
- active trajectories
- distributed locks

Redpanda/Kafka
- security event backbone
- learning events
- worker jobs

ClickHouse
- yüksek hacimli telemetry
- runtime analytics

S3-compatible storage
- evidence
- reports
- artifacts
- dataset snapshots
```

---

# 19. Multi-Tenant Model

Minimum hierarchy:

```text
Organization
  Workspace
    Environment
      Asset
        Agent
        Model
        MCP Server
        Tool
```

Tüm persistent kayıtlarda tenant context zorunlu olmalıdır.

Cross-tenant testleri CI'da zorunlu güvenlik testi olmalıdır.

---

# 20. Control Plane

Control Plane sorumlulukları:

- organizations
- workspaces
- environments
- users
- RBAC/ABAC
- assets
- capability registry UI
- policy management
- approvals
- findings
- reports
- billing hooks
- integrations
- audit access
- API keys/service identities

---

# 21. Enterprise Integrations

Planlanan entegrasyon aileleri:

```text
Jira
ServiceNow
Slack
Microsoft Teams
Email
Webhook
SIEM
SOC tools
GitHub/GitLab
CI/CD
SSO
SCIM
```

---

# 22. Observability

Her runtime kararında mümkünse:

```text
trace_id
tenant_id
agent_id
session_id
trajectory_id
event_id
policy_decision_id
finding_id
```

ilişkilendirilebilir olmalıdır.

OpenTelemetry kullanılması önerilir.

---

# 23. Threat Research Brain

Sistem yeni tehdit bilgisini alabilir:

- CVE
- CWE
- MITRE ATLAS
- OWASP
- vendor advisories
- security research
- MCP ekosistemi
- agent framework advisories

Yeni bilgi doğrudan "truth" kabul edilmez.

```text
Incoming Knowledge
→ Trust Scoring
→ Source Validation
→ Cross-validation
→ Sandbox Reproduction
→ Knowledge Promotion
```

Bu, knowledge poisoning riskini azaltır.

---

# 24. Güvenli Red-Team Sınırları

Her campaign için Rules of Engagement kaydı olmalıdır:

```text
authorized targets
domains
IP/CIDR
environment
time window
max concurrency
request budget
data handling rules
destructive permissions
kill switch
```

Default:

```text
NON_DESTRUCTIVE
```

Yazılı izin dışındaki üçüncü taraflara agresif test uygulanmaz.

---

# 25. Repository Sözleşmesi

Her iki geliştirici aynı domain contract'larını kullanmalıdır.

Ana shared contract'lar:

```text
schemas/events/security_event.*
schemas/events/learning_event.*
schemas/findings/finding.*
schemas/policies/policy_decision.*
schemas/capabilities/tool_capability.*
schemas/evidence/evidence.*
```

Bir taraf contract değiştirirse:

1. version increment,
2. migration note,
3. backward compatibility,
4. diğer geliştiriciye bildirim

zorunludur.

---

# 26. İki Kişilik Görev Dağılımı

## Developer A — CORE SECURITY / AEGIS
Ürünün en kritik IP'si.

Sahiplik:

- Runtime Gateway
- Capability Registry enforcement
- Policy decision pipeline
- Trajectory v2
- AEGIS Memory
- Attack Planner
- 50X Adaptive Attack Engine
- Evolutionary Fuzzer
- Attack Knowledge Graph
- Vulnerability DNA
- Evidence Validation
- Regression Engine
- Self-improvement governance
- AgentGuard-vs-AgentGuard
- Safety budget / kill switch

## Developer B — PLATFORM / ENTERPRISE
Ürünün işletilebilir ve satılabilir platform katmanı.

Sahiplik:

- Control API
- tenant/workspace/environment
- users / RBAC / SSO / SCIM groundwork
- asset registry
- policy management UI/API
- findings workflow
- approval workflow
- persistent storage
- event backbone
- observability
- web console
- integrations
- reporting
- deployment
- platform CI/CD

Detaylı planlar ayrı README dosyalarındadır.

---

# 27. Birleşme Noktaları

İki geliştiricinin kritik entegrasyon noktaları:

```text
1. SecurityEvent contract
2. PolicyDecision contract
3. Capability contract
4. Finding contract
5. Evidence contract
6. LearningEvent contract
7. TenantContext
8. ApprovalRequest / ApprovalDecision
```

Core Security hiçbir zaman tenant bilgisini tahmin etmez.
Control Plane hiçbir zaman runtime risk kararını kendi UI logic'i ile üretmez.

---

# 28. Definition of Done — AgentGuard Enterprise v3 Foundation

Aşağıdakiler tamamlandığında v3 foundation başarılı kabul edilir:

- Multi-tenant persistent platform çalışıyor.
- Runtime Gateway yatay ölçeklenebilir.
- Tool capability metadata zorunlu.
- Policy pipeline deterministic + explainable.
- Trajectory process-memory'den çıkmış.
- AEGIS dört hafızayı kullanıyor.
- Red-team durable worker üzerinde çalışıyor.
- Açık sonrası adaptive test genişlemesi var.
- Evidence-backed finding üretimi var.
- Vulnerability DNA çıkarılıyor.
- Attack Graph güncelleniyor.
- Resolved finding regression testine dönüşüyor.
- Yeni detector/strategy sadece governance gate ile production'a alınabiliyor.
- Cross-tenant izolasyon testleri geçiyor.
- Audit/evidence immutable veya tamper-evident tasarlanmış.
- Kill switch mevcut.
- Dashboard ve API'ler iki tarafın ürettiği veriyi birleştiriyor.

---

# 29. AI Assistant'a Son Talimat

Bu repository üzerinde çalışırken hedef yalnızca "kod çalışsın" değildir.

Her değişiklik şu dört soruya cevap vermelidir:

1. Güvenlik sınırı güçlendi mi?
2. Öğrenme verisi üretildi mi?
3. Evidence ve audit üretildi mi?
4. Sistem yatay ölçeklenebilir ve tenant-safe mi?

Bu dosyadaki mimari ilkeleri gevşetme.


---

# 30. ULTRA-LOW-LATENCY RUNTIME ARCHITECTURE

Bu bölüm AgentGuard v3 mimarisinin zorunlu performans katmanıdır.

## 30.1 Temel kural

SECURITY INTELLIGENCE IS ASYNCHRONOUS.
SECURITY ENFORCEMENT IS REAL-TIME.

NO BLOCKING AI ON THE RUNTIME HOT PATH.

Normal runtime isteğini aşağıdakiler bekletemez:

- AEGIS LLM reasoning
- 50X Red Team
- Attack Graph full traversal
- Threat Research
- model training
- Warm/Cold Learning
- ClickHouse analytics
- büyük PostgreSQL sorguları
- rapor/PDF üretimi

## 30.2 Runtime latency SLO

Başlangıç mühendislik hedefleri:

```text
p50 < 2 ms
p95 < 5 ms
p99 < 10 ms
normal production load critical maximum target < 20 ms
```

Bunlar benchmark ile doğrulanacak SLO hedefleridir.

## 30.3 Hot Path / Intelligence Path

```text
REQUEST
  |
  v
ULTRA FAST HOT PATH
  |
  +--> L1 local cache
  +--> compiled policy
  +--> fast deterministic detectors
  +--> incremental trajectory state
  +--> precomputed AEGIS risk
  |
  v
ALLOW / BLOCK / REQUIRE_APPROVAL / SANDBOX
  |
  v
TOOL EXECUTION
  |
  +--------------------> ASYNC EVENT BUS
                           |
               +-----------+-----------+
               |           |           |
             AEGIS      Learning     Analytics
               |
          50X / Red Team
```

## 30.4 Fast path içinde izin verilen işlemler

- identity/tenant context lookup
- capability lookup
- compiled policy evaluation
- bounded deterministic detectors
- incremental trajectory update
- precomputed risk lookup
- approval token lookup
- bounded CPU calculation

## 30.5 Üç katmanlı cache

```text
L1 = Runtime process-local memory
L2 = Redis
L3 = PostgreSQL/source of truth
```

Normal request mümkün olduğunca L1 hit ile tamamlanmalıdır.
L3 normal hot-path bağımlılığı değildir.

Cache invalidation event-driven olmalıdır.

## 30.6 Policy pre-compilation

Policy kaydedildiğinde:

```text
Validate
→ Version
→ Compile
→ Optimize
→ Hash/Sign
→ Publish
→ Runtime Cache
```

Runtime policy JSON parse etmemeli; compiled artifact kullanmalıdır.

## 30.7 Incremental Trajectory

Her request'te tüm geçmiş DB'den okunmaz.

Runtime yalnız:

```text
current trajectory state + new signal
```

üzerinden bounded update yapar.

Full recomputation asenkron yapılır.

## 30.8 Precomputed AEGIS Intelligence

AEGIS arka planda üretir:

- agent risk profile
- tool risk profile
- MCP risk profile
- behavioral baseline
- Vulnerability DNA similarity
- watch flags

Runtime yalnız cache'den okur.

## 30.9 Slow path

Ağır AI reasoning gerekirse normal request'i bekletmek yerine uygun policy ile:

- REQUIRE_APPROVAL
- SANDBOX
- STEP_UP_AUTH
- ASYNC_DEEP_ANALYSIS

kullanılır.

## 30.10 Stateless Runtime Gateway

Runtime Gateway persistent state taşımaz ve yatay ölçeklenebilir:

```text
Load Balancer
  +--> Runtime 1
  +--> Runtime 2
  +--> Runtime 3
  +--> Runtime N
```

## 30.11 Priority sınıfları

```text
P1 Runtime Enforcement
P2 Critical Evidence/Audit
P3 Learning
P4 Analytics
P5 Red-Team background expansion
```

AEGIS/Red-Team runtime kaynaklarını tüketemez.

## 30.12 Backpressure

- bounded queues
- batching
- DLQ
- adaptive sampling
- load shedding
- priority queues
- broker lag alerts

Runtime broker yavaşlığı yüzünden durmamalıdır.

## 30.13 Circuit Breaker ve fail mode

Hot-path bağımlılıkları strict timeout kullanmalıdır.

Capability bazlı fail mode:

```text
low risk       -> policy-defined fail-open mümkün
payment.execute -> fail-closed
secret.read     -> fail-closed
identity.admin  -> fail-closed
shell.execute   -> fail-closed
```

## 30.14 Data locality

Runtime mümkünse:

```text
same process / sidecar
same node
same cluster
same VPC
same region
```

çalışmalıdır.

## 30.15 Efficient serialization

- büyük payload inline taşınmaz
- payload reference/hash kullanılır
- gereksiz JSON parse azaltılır
- compact wire formatlar benchmark edilir

## 30.16 Bounded detectors

Fast detector:

- deterministic
- bounded execution time
- external network bağımsız
- LLM bağımsız
- ReDoS-safe
- büyük DB sorgusu içermez

olmalıdır.

## 30.17 Performance release gate

Her release ölçer:

```text
p50
p95
p99
max
throughput
CPU/request
memory/request
L1 hit rate
Redis hit rate
policy evaluation latency
trajectory update latency
```

Performance regression threshold aşılırsa release bloklanır.

## 30.18 Minimum load/failure testleri

- 1K req/s
- 10K req/s
- burst
- cold cache
- Redis latency/loss
- broker outage
- PostgreSQL slowdown
- policy invalidation storm
- noisy neighbor
- paralel red-team campaign

## 30.19 Noisy Neighbor Isolation

Bir tenant'ın red-team, report veya telemetry yükü diğer tenant'ın runtime latency'sini bozamaz.

## 30.20 Runtime Decision metadata

Her karar minimum:

```text
decision_id
policy_version
policy_hash
runtime_version
risk_score
reason_codes
cache_source
latency_us
trajectory_version
```

taşımalıdır.

---

# 31. Güncellenmiş zorunlu mimari ayrımı

```text
REAL-TIME SECURITY DATA PLANE
- ultra-low latency
- deterministic
- bounded
- horizontally scalable

INTELLIGENCE / LEARNING PLANE
- AEGIS
- Attack Graph
- 50X
- research
- continuous learning
- model training
- analytics/reporting
```

Bu ayrım AgentGuard Enterprise v3.1'in temel mimari yasasıdır.
