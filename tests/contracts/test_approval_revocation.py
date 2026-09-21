"""Approval-revoke processor: nonce revocation, TTL bounds, fail-safe redelivery."""
import unittest

from approval_revocation import (ApprovalRevocationProcessor, RevocationBackendError,
                                 _MAX_TTL_S)


class FakeGuard:
    def __init__(self, *, error=None):
        self.revoked = []      # (tenant_id, nonce, ttl_s)
        self.error = error

    def revoke(self, tenant_id, nonce, *, ttl_s):
        if self.error is not None:
            raise self.error
        self.revoked.append((tenant_id, nonce, ttl_s))


def event(**kw):
    e = {"event_type": "approval.revoked", "tenant_id": "A", "request_id": "r1",
         "nonces": ["nonce-1", "nonce-2"]}
    e.update(kw)
    return e


class TestApprovalRevocationProcessor(unittest.TestCase):
    def test_revokes_every_nonce_with_max_ttl_by_default(self):
        guard = FakeGuard()
        result = ApprovalRevocationProcessor(guard, clock=lambda: 1000.0).process_event(event())
        self.assertEqual(result.revoked, 2)
        self.assertEqual(result.skipped, 0)
        self.assertEqual([n for _, n, _ in guard.revoked], ["nonce-1", "nonce-2"])
        self.assertTrue(all(ttl == _MAX_TTL_S for _, _, ttl in guard.revoked))

    def test_honours_bounded_expires_at_when_present(self):
        guard = FakeGuard()
        proc = ApprovalRevocationProcessor(guard, clock=lambda: 1000.0)
        proc.process_event(event(nonces=["n"], expires_at=1000.0 + 600))
        self.assertEqual(guard.revoked[0][2], 600)
        guard.revoked.clear()
        # a far-future expiry is clamped to the guard maximum, a past one to 1s
        proc.process_event(event(nonces=["n"], expires_at=1000.0 + 10 * _MAX_TTL_S))
        self.assertEqual(guard.revoked[0][2], _MAX_TTL_S)
        guard.revoked.clear()
        proc.process_event(event(nonces=["n"], expires_at=500.0))
        self.assertEqual(guard.revoked[0][2], 1)

    def test_ignores_unrelated_event_types(self):
        guard = FakeGuard()
        self.assertIsNone(ApprovalRevocationProcessor(guard).process_event(
            {"event_type": "approval.decided", "tenant_id": "A", "nonces": ["x"]}))
        self.assertEqual(guard.revoked, [])

    def test_malformed_event_raises_value_error(self):
        proc = ApprovalRevocationProcessor(FakeGuard())
        for bad in ({"event_type": "approval.revoked", "nonces": ["x"]},
                    {"event_type": "approval.revoked", "tenant_id": "A", "nonces": "x"},
                    {"event_type": "approval.revoked", "tenant_id": "A"}):
            with self.assertRaises(ValueError):
                proc.process_event(bad)

    def test_malformed_nonces_are_skipped_not_fatal(self):
        guard = FakeGuard()
        result = ApprovalRevocationProcessor(guard).process_event(
            event(nonces=["good-1", "bad nonce!", 123, "good-2"]))
        self.assertEqual((result.revoked, result.skipped), (2, 2))
        self.assertEqual([n for _, n, _ in guard.revoked], ["good-1", "good-2"])

    def test_backend_failure_raises_for_redelivery(self):
        proc = ApprovalRevocationProcessor(FakeGuard(error=ConnectionError("redis down")))
        with self.assertRaises(RevocationBackendError):
            proc.process_event(event())

    def test_guard_value_error_is_skipped_not_backend_failure(self):
        proc = ApprovalRevocationProcessor(FakeGuard(error=ValueError("invalid approval nonce")))
        result = proc.process_event(event(nonces=["n"]))
        self.assertEqual((result.revoked, result.skipped), (0, 1))


if __name__ == "__main__":
    unittest.main()
