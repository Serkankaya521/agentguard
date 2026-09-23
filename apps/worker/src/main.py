"""Unified platform-owned worker entrypoint."""
from config import WorkerSettings

def main():
    role=WorkerSettings.from_env().role
    if role=='platform':from platform_main import main as run
    elif role=='analytics':from analytics_main import main as run
    elif role=='retention':from retention_main import main as run
    elif role=='scheduler':from schedule_main import main as run
    elif role=='revoke':from revoke_main import main as run
    else:from security_main import main as run
    run()
if __name__=='__main__':main()
