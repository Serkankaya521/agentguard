"""Create a local-only PostgreSQL handoff bundle without printing credentials."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess

from psycopg.conninfo import conninfo_to_dict


ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
PG_DUMP = ROOT.parent / ".venv/pgminimal/pgsql/bin/pg_dump.exe"


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (LOCAL / "postgres.env").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="Host/IP Batuhan will use")
    parser.add_argument("--port", type=int, default=55432)
    args = parser.parse_args()
    values = read_env()
    owner = conninfo_to_dict(values["MIGRATION_DATABASE_URL"])
    app = conninfo_to_dict(values["CONTROL_DATABASE_URL"])
    dump_path = LOCAL / "agentguard-batuhan.dump"
    handoff_path = LOCAL / "BATUHAN_DB_HANDOFF.txt"

    process_env = dict(os.environ)
    process_env["PGPASSWORD"] = owner["password"]
    subprocess.run([
        str(PG_DUMP), "--format=custom", "--no-owner", "--no-privileges",
        "--host", owner["host"], "--port", owner["port"], "--username", owner["user"],
        "--dbname", owner["dbname"], "--file", str(dump_path),
    ], env=process_env, check=True)

    handoff_path.write_text(
        "AgentGuard PostgreSQL handoff (SECRET - send through a private channel)\n"
        f"host={args.host}\nport={args.port}\ndatabase={owner['dbname']}\n"
        f"owner_user={owner['user']}\nowner_password={owner['password']}\n"
        f"app_user={app['user']}\napp_password={app['password']}\n"
        f"backup_file={dump_path}\n"
        "direct_connection_requires=Serkan and Batuhan on the same private network "
        "or a private VPN; PostgreSQL LAN sharing must be enabled first.\n",
        encoding="utf-8",
    )
    os.chmod(handoff_path, 0o600)
    print(f"Handoff credentials: {handoff_path}")
    print(f"Database backup: {dump_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
