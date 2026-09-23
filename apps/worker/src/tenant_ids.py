"""Dynamic fair-scheduling tenant discovery."""
import psycopg


def active_tenant_ids(dsn):
    with psycopg.connect(dsn) as conn:
        return tuple(str(row[0]) for row in conn.execute('SELECT * FROM platform.active_tenant_ids()'))
