"""Run the PostgreSQL integration suite against an isolated local instance."""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import shutil

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo


ROOT=Path(__file__).resolve().parents[1]
PG_BIN=ROOT.parent/'.venv/pgminimal/pgsql/bin'
DATA=ROOT/'.local'/('postgres-test-'+secrets.token_hex(6))
LOG=ROOT/'.local'/'postgres-test.log'


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def main() -> int:
    if not (PG_BIN/'initdb.exe').exists():
        raise RuntimeError(f'portable PostgreSQL is missing: {PG_BIN}')
    DATA.parent.mkdir(exist_ok=True)
    port,password=free_port(),secrets.token_urlsafe(48)
    password_file=DATA.parent/('pw-'+secrets.token_hex(6))
    password_file.write_text(password,encoding='utf-8')
    try:
        subprocess.run([str(PG_BIN/'initdb.exe'),'-D',str(DATA),'-U','postgres',
            '--auth=scram-sha-256','--pwfile='+str(password_file),'--encoding=UTF8','--locale=C'],check=True)
    finally:
        password_file.unlink(missing_ok=True)
    subprocess.run([str(PG_BIN/'pg_ctl.exe'),'-D',str(DATA),'-l',str(LOG),
                    '-o',f'-h 127.0.0.1 -p {port}','-w','start'],check=True)
    try:
        owner=make_conninfo(host='127.0.0.1',port=port,dbname='postgres',user='postgres',password=password)
        with psycopg.connect(owner,autocommit=True) as conn:
            conn.execute(sql.SQL('CREATE ROLE ag_control LOGIN NOSUPERUSER NOBYPASSRLS '
                                 'NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD {}').format(sql.Literal(password)))
            conn.execute('CREATE DATABASE agentguard_test')
        env=dict(os.environ)
        env['B1_TEST_OWNER_DSN']=make_conninfo(owner,dbname='agentguard_test')
        env['B1_TEST_APP_DSN']=make_conninfo(owner,dbname='agentguard_test',user='ag_control')
        return subprocess.run([sys.executable,'-m','pytest','-q'],cwd=ROOT,env=env).returncode
    finally:
        subprocess.run([str(PG_BIN/'pg_ctl.exe'),'-D',str(DATA),'-m','fast','-w','stop'],check=True)
        shutil.rmtree(DATA,ignore_errors=True)


if __name__=='__main__':
    raise SystemExit(main())
