from datetime import UTC, datetime

from threatlens.api.routes.backup import BackupBundle, _digest, _errors


def test_backup_digest_is_stable_and_valid() -> None:
    bundle = BackupBundle(exported_at=datetime(2026, 1, 1, tzinfo=UTC))
    signed = bundle.model_copy(update={"digest": _digest(bundle)})
    assert _errors(signed) == []
    assert _digest(signed) == signed.digest


def test_backup_integrity_detects_tampering() -> None:
    bundle = BackupBundle(exported_at=datetime(2026, 1, 1, tzinfo=UTC), digest="bad")
    assert _errors(bundle) == ["Backup integrity check failed."]
