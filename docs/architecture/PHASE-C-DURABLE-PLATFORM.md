# Phase C — Durable Platform Foundation

Phase C adds an optional SQLite persistence backend behind the existing
WorkspaceStorage and CaseStorage interfaces.

Set:

```text
THREATLENS_STORAGE_BACKEND=sqlite
THREATLENS_DATABASE_PATH=data/threatlens.db
```

When enabled, Workspace and Case records share one SQLite database while
remaining separate tables. The database initializes itself on first use,
enables WAL mode, applies a schema version, and creates indexes for updated
records. The existing local JSON-file backend remains the default and remains
useful for simple single-user development.

SQLite mutations append durable audit events containing the resource type,
resource id, action, and timestamp. Domain records remain JSON payloads inside
the database so the Pydantic models continue to be the canonical contracts.

Authentication and role-based access control remain separate from storage and
are still represented by the existing optional API-key protection. They should
be added after the durable storage path is deployed and validated.
