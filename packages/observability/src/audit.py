"""Audit chain verifier; mutation prevention is enforced in PostgreSQL."""


def verify_links(records):
    previous = None
    for record in records:
        if record.get("prev_hash") != previous:
            return False, f"broken link at {record.get('id')}"
        current = record.get("record_hash", "")
        if not current.startswith("sha256:") or len(current) != 71:
            return False, f"invalid hash at {record.get('id')}"
        previous = current
    return True, "ok"
