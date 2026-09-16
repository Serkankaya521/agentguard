"""Fail-fast worker process configuration."""
from dataclasses import dataclass
import os

@dataclass(frozen=True)
class WorkerSettings:
    role:str
    @classmethod
    def from_env(cls):
        role=os.environ.get('AGENTGUARD_WORKER_ROLE','platform')
        if role not in ('platform','analytics','retention','scheduler','security'):raise RuntimeError('invalid AGENTGUARD_WORKER_ROLE')
        return cls(role)
