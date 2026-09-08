from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AttackCategory(str, Enum):
    PROMPT_INJECTION = "Direct / Indirect Prompt Injection"
    SYSTEM_LEAK = "System Prompt & Secrets Extraction"
    UNAUTHORIZED_TOOL = "Excessive Agency & Unauthorized Tool Invocation"
    DATA_EXFILTRATION = "Data Exfiltration & SSRF"
    JAILBREAK = "Safety Policy Roleplay & Jailbreak"

class ToolCallPayload(BaseModel):
    name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)

class AttackVector(BaseModel):
    id: str
    category: AttackCategory
    severity: SeverityLevel
    name: str
    description: str
    payload: str
    target_tool_trigger: Optional[str] = None

class VulnerabilityFinding(BaseModel):
    vector_id: str
    vector_name: str
    category: AttackCategory
    severity: SeverityLevel
    attack_payload: str
    response_text: str
    intercepted_tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    mitigation_advice: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class SecurityAuditReport(BaseModel):
    target_system: str
    model_name: str
    execution_time_seconds: float
    total_vectors_tested: int
    vulnerabilities_detected: int
    risk_score_percentage: float
    compliance_status: str  # PASSED / FAILED
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)