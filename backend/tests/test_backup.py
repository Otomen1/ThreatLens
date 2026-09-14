from datetime import UTC, datetime

from threatlens.api.routes.backup import BackupBundle, _digest, _errors
from threatlens.api.routes.backup import test_backup as verify_backup


def test_backup_digest_is_stable_and_valid() -> None:
    bundle = BackupBundle(exported_at=datetime(2026, 1, 1, tzinfo=UTC))
    signed = bundle.model_copy(update={"digest": _digest(bundle)})
    assert _errors(signed) == []
    assert _digest(signed) == signed.digest


def test_backup_integrity_detects_tampering() -> None:
    bundle = BackupBundle(exported_at=datetime(2026, 1, 1, tzinfo=UTC), digest="bad")
    assert _errors(bundle) == ["Backup integrity check failed."]


def test_backup_test_performs_isolated_round_trip() -> None:
    bundle = BackupBundle(exported_at=datetime(2026, 1, 1, tzinfo=UTC))
    signed = bundle.model_copy(update={"digest": _digest(bundle)})
    result = verify_backup(signed)
    assert result.valid
    assert result.digest_verified
    assert result.round_trip_verified
