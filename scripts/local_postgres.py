"""Manage a persistent, loopback-only PostgreSQL instance for local AgentGuard work."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo


ROOT=Path(__file__).resolve().parents[1]
PG_BIN=ROOT.parent/'.venv/pgminimal/pgsql/bin'
LOCAL=ROOT/'.local'
DATA=LOCAL/'postgres'
LOG=LOCAL/'postgres.log'
ENV_FILE=LOCAL/'postgres.env'
PORT=55432


def run(*args,check=True):
    return subprocess.run([str(PG_BIN/args[0]),*args[1:]],check=check,
                          stdout=subprocess.DEVNULL if args[0]=='pg_ctl.exe' else None)


def values():
    result={}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding='utf-8').splitlines():
            if '=' in line:
                key,value=line.split('=',1);result[key]=value
    return result


def status():
    return run('pg_ctl.exe','-D',str(DATA),'status',check=False).returncode==0 if DATA.exists() else False


def start():
    if not (PG_BIN/'initdb.exe').exists():raise RuntimeError(f'portable PostgreSQL missing: {PG_BIN}')
    LOCAL.mkdir(exist_ok=True)
    config=values()
    if not (DATA/'PG_VERSION').exists():
        postgres_password,secrets_app=secrets.token_urlsafe(48),secrets.token_urlsafe(48)
        password_file=LOCAL/'postgres-password.tmp';password_file.write_text(postgres_password,encoding='utf-8')
        try:
            run('initdb.exe','-D',str(DATA),'-U','postgres','--auth=scram-sha-256',
                '--pwfile='+str(password_file),'--encoding=UTF8','--locale=C')
        finally:password_file.unlink(missing_ok=True)
        owner=make_conninfo(host='127.0.0.1',port=PORT,dbname='agentguard',user='postgres',password=postgres_password)
        app=make_conninfo(host='127.0.0.1',port=PORT,dbname='agentguard',user='ag_control',password=secrets_app)
        config={'CONTROL_DATABASE_URL':app,'MIGRATION_DATABASE_URL':owner,
                'POSTGRES_ADMIN_DSN':owner.replace('dbname=agentguard','dbname=postgres')}
        ENV_FILE.write_text('\n'.join(f'{k}={v}' for k,v in config.items())+'\n',encoding='utf-8')
        os.chmod(ENV_FILE,0o600)
    if not status():run('pg_ctl.exe','-D',str(DATA),'-l',str(LOG),'-o',f'-h 127.0.0.1 -p {PORT}','-w','start')
    if 'POSTGRES_ADMIN_DSN' in config:
        try:
            with psycopg.connect(config['POSTGRES_ADMIN_DSN'],autocommit=True) as conn:
                exists=conn.execute("SELECT 1 FROM pg_roles WHERE rolname='ag_control'").fetchone()
                if not exists:
                    app_password=dict(item.split('=',1) for item in config['CONTROL_DATABASE_URL'].split()).get('password')
                    conn.execute(sql.SQL('CREATE ROLE ag_control LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD {}').format(sql.Literal(app_password)))
                if not conn.execute("SELECT 1 FROM pg_database WHERE datname='agentguard'").fetchone():
                    conn.execute('CREATE DATABASE agentguard')
        except Exception:
            stop();raise
    from importlib.util import module_from_spec,spec_from_file_location
    spec=spec_from_file_location('agentguard_migrate',ROOT/'migrations/postgresql/migrate.py')
    migration=module_from_spec(spec);spec.loader.exec_module(migration)
    migration.migrate(config['MIGRATION_DATABASE_URL'],'up')
    print(f'PostgreSQL ready on 127.0.0.1:{PORT}; connection settings: {ENV_FILE}')


def stop():
    if status():run('pg_ctl.exe','-D',str(DATA),'-m','fast','-w','stop')
    print('PostgreSQL stopped')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=('start','stop','status'))
    command=parser.parse_args().command
    if command=='start':start()
    elif command=='stop':stop()
    else:
        print('running' if status() else 'stopped');raise SystemExit(0 if status() else 1)
