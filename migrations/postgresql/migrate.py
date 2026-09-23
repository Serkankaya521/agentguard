"""Transactional, checksum-checked foundation migrations."""
import argparse
import hashlib
import os
from pathlib import Path
import psycopg

ROOT = Path(__file__).parent

def _migrations():
    return [(int(path.name.split('_', 1)[0]), path)
            for path in sorted(ROOT.glob('[0-9][0-9][0-9]_*.up.sql'))]


def migrate(dsn, direction, target=None):
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        if direction == 'down':
            role=conn.execute('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
            if not role or not (role[0] or role[1]):
                raise RuntimeError('down migrations require a superuser or BYPASSRLS role')
        conn.execute('SELECT pg_advisory_xact_lock(71319001)')
        conn.execute('CREATE TABLE IF NOT EXISTS public.platform_migrations (version integer PRIMARY KEY, checksum text NOT NULL)')
        migrations = _migrations()
        if direction == 'down':
            migrations.reverse()
        for version, path in migrations:
            if target is not None and ((direction == 'up' and version > target) or
                                       (direction == 'down' and version <= target)):
                continue
            up = path.read_text(encoding='utf-8')
            digest = hashlib.sha256(up.encode()).hexdigest()
            row = conn.execute('SELECT checksum FROM public.platform_migrations WHERE version=%s',(version,)).fetchone()
            if row and row[0] != digest:
                raise RuntimeError(f'Migration {version} checksum mismatch')
            if direction == 'up' and not row:
                conn.execute(up)
                conn.execute('INSERT INTO public.platform_migrations VALUES (%s,%s)',(version,digest))
            elif direction == 'down' and row:
                down = path.with_name(path.name.replace('.up.sql','.down.sql'))
                conn.execute(down.read_text(encoding='utf-8'))
                conn.execute('DELETE FROM public.platform_migrations WHERE version=%s',(version,))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('direction', choices=['up','down'])
    parser.add_argument('--target', type=int)
    args = parser.parse_args()
    migrate(os.environ['MIGRATION_DATABASE_URL'], args.direction, args.target)
