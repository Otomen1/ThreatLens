"""Stored-source attachment contracts: no provider calls, safe personal persistence."""

import hashlib
import importlib
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from threatlens.api.app import app
from threatlens.api.auth import VerifiedIdentity
from threatlens.api.routes.backup import BackupBundle, _digest, _errors, restore_backup
from threatlens.api.routes.cases import get_case_service
from threatlens.api.routes.poc import require_signed_in
from threatlens.api.routes.threat_feed import get_threat_feed_service
from threatlens.cases import CaseService, CreateCaseRequest, LocalFileStorage, SQLiteCaseStorage
from threatlens.cases.exceptions import CaseFeedLimitError
from threatlens.cases.feed import resolve_reference
from threatlens.cases.models import Case, CaseFeedReference, FeedReferenceKey
from threatlens.cases.postgres_storage import PostgresCaseStorage
from threatlens.ioc_feed.models import IocReport
from threatlens.ioc_feed.storage import get_storage
from threatlens.threat_feed.models import FeedVulnerability, ThreatFeedItem
from threatlens.threat_feed.service import ThreatFeedService
from threatlens.threat_feed.storage import FeedStorage
from threatlens.workspace import LocalFileStorage as WorkspaceStorage
from threatlens.workspace import WorkspaceService

NOW = datetime.now(UTC)
OWNER = "00000000-0000-4000-8000-000000000001"


@pytest.fixture(params=["memory", "sqlite"])
def feed(request, monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", request.param)
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "feed.db"))
    storage = FeedStorage()
    storage.save_items(
        [
            ThreatFeedItem.model_validate(
                {
                    "id": "news",
                    "source_id": "talos",
                    "source_name": "Cisco Talos",
                    "source_kind": "rss",
                    "title": "<b>Campaign report</b>",
                    "summary": "Report",
                    "url": "https://example.test/report",
                    "published_at": NOW,
                    "collected_at": NOW,
                    "region": "global",
                    "relevance": "general",
                    "topic": "research",
                }
            )
        ]
    )
    storage.save_vulnerabilities(
        [
            FeedVulnerability(
                id="CVE-2026-1234",
                cve_id="CVE-2026-1234",
                title="Example vulnerability",
                activity_at=NOW,
                updated_at=NOW,
                sources=("NVD",),
                references=("https://nvd.nist.gov/vuln/detail/CVE-2026-1234",),
            )
        ]
    )
    get_storage(storage).save(
        IocReport(
            id="ioc",
            vendor="talos",
            title="IOC report",
            path="iocs.txt",
            source_url="https://example.test/iocs",
            article_url="https://example.test/report",
            activity_at=NOW,
            collected_at=NOW,
            commit="a" * 40,
            blob="b" * 40,
            license="CC0-1.0",
            license_url="https://example.test/license",
            attribution="Cisco Talos",
        ),
        (),
        {},
    )
    return storage


@pytest.fixture(params=["file", "sqlite"])
def service(request, tmp_path):
    storage = (
        LocalFileStorage(tmp_path / "cases")
        if request.param == "file"
        else SQLiteCaseStorage(tmp_path / "cases.db")
    )
    return CaseService(storage, WorkspaceService(WorkspaceStorage(tmp_path / "workspace")))


@pytest.fixture
def client(service, feed):
    app.dependency_overrides[get_case_service] = lambda: service
    app.dependency_overrides[get_threat_feed_service] = lambda: ThreatFeedService(feed)
    app.dependency_overrides[require_signed_in] = lambda: None
    with TestClient(app) as client:
        yield client
    for dependency in (get_case_service, get_threat_feed_service, require_signed_in):
        app.dependency_overrides.pop(dependency, None)


@pytest.mark.parametrize(
    "kind,record_id", [("news", "news"), ("vulnerability", "cve-2026-1234"), ("ioc", "ioc")]
)
def test_resolve_metadata_only(feed, kind, record_id, monkeypatch):
    monkeypatch.setattr(get_storage(feed), "detail", lambda _: pytest.fail("Loaded indicators"))
    ref = resolve_reference(feed, FeedReferenceKey(kind=kind, id=record_id))
    assert ref and ref.sources and not ref.verified and ref.disposition == "source-reported"
    assert "<b>" not in ref.title
    assert "indicators" not in ref.model_dump()
    if kind == "ioc":
        assert ref.attribution == "Cisco Talos" and ref.license == "CC0-1.0"
        assert any(source.name == "License" for source in ref.sources)
    if kind == "vulnerability":
        assert ref.id == "CVE-2026-1234"


def test_attach_duplicate_remove_and_retained_snapshot(client, service, feed):
    case = service.create(CreateCaseRequest(title="Personal Case", metadata={"keep": True}))
    path = f"/api/v1/cases/{case.id}/feed"
    response = client.post(path, json={"kind": "news", "id": "news"})
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "private, no-store"
    first = response.json()
    assert first["metadata"] == {"keep": True} and first["linked_workspace_ids"] == []
    assert first["feed_references"][0]["title"] == "Campaign report"
    # Expiry of the public source must not invalidate an idempotent save or erase attribution.
    feed.delete_before(NOW.replace(year=NOW.year + 1))
    assert client.post(path, json={"kind": "news", "id": "news"}).json() == first
    assert len(service.get(case.id).feed_references) == 1
    removed = client.delete(path + "/news/news")
    assert removed.status_code == 200 and removed.json()["feed_references"] == []
    assert client.delete(path + "/news/news").json() == removed.json()


def test_invalid_missing_and_forged_inputs(client, service):
    case = service.create(CreateCaseRequest(title="Test"))
    path = f"/api/v1/cases/{case.id}/feed"
    assert client.post(path, json={"kind": "poc", "id": "news"}).status_code == 422
    assert client.post(path, json={"kind": "news", "id": "../news"}).status_code == 422
    assert (
        client.post(path, json={"kind": "news", "id": "news", "title": "Forged"}).status_code == 422
    )
    assert client.post(path, json={"kind": "news", "id": "missing"}).status_code == 404
    assert (
        client.post(
            f"/api/v1/cases/{uuid4()}/feed", json={"kind": "news", "id": "news"}
        ).status_code
        == 404
    )
    assert service.get(case.id).feed_references == []


def reference(record_id="news"):
    return CaseFeedReference(kind="news", id=record_id, title="Report", attached_at=NOW)


def test_concurrent_attachment_preserves_changes(service):
    case = service.create(CreateCaseRequest(title="Concurrent"))
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda n: service.attach_feed(case.id, reference(str(n % 5))), range(20)))
    assert len(service.get(case.id).feed_references) == 5


def test_capacity_and_old_records(service):
    case = service.create(CreateCaseRequest(title="Bounded"))
    old = case.model_dump()
    old.pop("feed_references")
    assert Case.model_validate(old).feed_references == []
    full = case.model_copy(update={"feed_references": [reference(str(n)) for n in range(100)]})
    service._storage.save(full)
    assert service.attach_feed(case.id, reference("0")) == full
    with pytest.raises(CaseFeedLimitError):
        service.attach_feed(case.id, reference("extra"))
    assert service.get(case.id) == full


@pytest.mark.parametrize("version", [1, 2])
def test_backup_digest_and_round_trip_compatibility(service, version):
    case = service.create(CreateCaseRequest(title="Backup"))
    old = BackupBundle(exported_at=NOW, schema_version=version, owner_user_id=OWNER, cases=[case])
    payload = old.model_dump(mode="json", exclude={"digest"})
    payload["cases"][0].pop("feed_references")
    if version == 1:
        payload.pop("owner_user_id")
    original_digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert _digest(old) == original_digest
    service.attach_feed(case.id, reference())
    bundle = old.model_copy(update={"cases": service.snapshot()})
    bundle = bundle.model_copy(update={"digest": _digest(bundle)})
    parsed = BackupBundle.model_validate_json(bundle.model_dump_json())
    assert not _errors(parsed)
    assert parsed.cases[0].feed_references == [reference()]
    assert _digest(bundle) != original_digest


def test_reject_unsafe_restored_reference_links():
    for url in ("javascript:alert(1)", "https://user:password@example.test/"):
        with pytest.raises(ValidationError):
            CaseFeedReference.model_validate(
                {**reference().model_dump(), "sources": [{"name": "Source", "url": url}]}
            )


def test_restore_retains_reference_and_detects_tampering(service, monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "file")
    case = service.create(CreateCaseRequest(title="Restore source"))
    case = service.attach_feed(case.id, reference())
    bundle = BackupBundle(exported_at=NOW, owner_user_id=OWNER, cases=[case])
    bundle = bundle.model_copy(update={"digest": _digest(bundle)})
    tampered = bundle.model_copy(
        update={"cases": [case.model_copy(update={"feed_references": []})]}
    )
    assert "Backup integrity check failed." in _errors(tampered)
    service.delete(case.id)
    result = restore_backup(bundle, service._workspace, service)
    assert result.cases_added == 1
    assert service.get(case.id).feed_references == [reference()]


def test_postgres_json_round_trip_reuses_attachment_transaction(tmp_path, monkeypatch):
    """Exercise the actual adapter against a small protocol fixture, not a live DB."""
    rows, connections, statements = {}, [], []

    class Connection:
        def execute(self, sql, args=()):
            statements.append(sql)
            result = []
            if sql.startswith("INSERT INTO threatlens_case_records"):
                rows[args[0]] = json.loads(args[2])
            elif sql.startswith("SELECT payload") and args[0] in rows:
                result = [(rows[args[0]],)]
            return SimpleNamespace(fetchone=lambda: result[0] if result else None)

    @contextmanager
    def connect(url):
        connection = Connection()
        connections.append(connection)
        yield connection

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))
    storage = PostgresCaseStorage("mock-personal-db")
    service = CaseService(storage, WorkspaceService(WorkspaceStorage(tmp_path / "workspace")))
    case = service.create(CreateCaseRequest(title="Postgres fixture"))
    before = len(connections)
    service.attach_feed(case.id, reference())
    assert len(connections) == before + 1
    assert service.get(case.id).feed_references == [reference()]
    assert any("pg_advisory_xact_lock" in sql for sql in statements)


def test_private_routes_fail_closed_and_reject_other_user(monkeypatch):
    monkeypatch.setenv("THREATLENS_ALLOW_UNAUTHENTICATED_LOCAL", "false")
    monkeypatch.setenv("SUPABASE_URL", "https://auth.test")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "public-test-key")

    async def other(*args):
        return VerifiedIdentity("00000000-0000-4000-8000-000000000002", time.time() + 60)

    module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(module, "supabase_auth_config", lambda: ("https://auth.test", "key"))
    monkeypatch.setattr(module, "verify_supabase_token", other)
    path = f"/api/v1/cases/{uuid4()}/feed"
    with TestClient(app) as client:
        assert client.post(path, json={"kind": "news", "id": "news"}).status_code == 401
        assert (
            client.post(
                path, json={"kind": "news", "id": "news"}, headers={"Authorization": "Bearer other"}
            ).status_code
            == 403
        )
