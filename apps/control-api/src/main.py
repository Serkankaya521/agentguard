from config import Settings
from foundation import create_app

settings = Settings.from_env()
app = create_app(settings.database_url,
                 policy_signing_key=settings.policy_signing_key,
                 approval_signing_key=settings.approval_signing_key,
                 evidence_signing_key=settings.evidence_signing_key)
