"""Local SQLite baseline / fingerprint store for drift detection.

Each scan can persist a per-artifact fingerprint that the next scan
compares against. The fingerprint deliberately mixes:

  - identity        : (host, kind, name)
  - declared scope  : SHA-256 of (description + sorted allowed-tools)
  - bundle scope    : SHA-256 of sorted bundled-file SHA-256s

A change to "declared scope" while the file bundle stays put hints at a
metadata-only edit (rebrand, deprecation). A change to the bundle scope
while declared scope is unchanged is the classic skill rug-pull pattern
(Snyk ToxicSkills).

Schema is tiny on purpose; the store is a baseline, not an ASPM database.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillscan.models import Artifact


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_root     TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    artifact_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS artifact_fingerprints (
    scan_id           INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host              TEXT NOT NULL,
    kind              TEXT NOT NULL,
    name              TEXT NOT NULL,
    path              TEXT NOT NULL,
    declared_sha      TEXT NOT NULL,
    bundle_sha        TEXT NOT NULL,
    metadata_json     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifact_lookup
  ON artifact_fingerprints(host, kind, name);
"""


@dataclass
class Fingerprint:
    host: str
    kind: str
    name: str
    path: str
    declared_sha: str
    bundle_sha: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DriftSignal:
    artifact: Artifact
    kind: str           # rug-pull | scope-change | new-artifact | removed
    summary: str
    previous: dict[str, Any]
    current: dict[str, Any]


def default_db_path() -> Path:
    return Path.home() / ".skillscan" / "baseline.db"


def open_db(path: Path | None = None) -> sqlite3.Connection:
    db_path = path or default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def fingerprint(artifact: Artifact) -> Fingerprint:
    declared = json.dumps(
        {
            "description": (artifact.metadata.get("description") or "") if isinstance(artifact.metadata, dict) else "",
            "allowed_tools": sorted(_normalize_tools(artifact.metadata.get("allowed_tools"))) if isinstance(artifact.metadata, dict) else [],
            "raw_keys": sorted(list(artifact.raw.keys())) if isinstance(artifact.raw, dict) else [],
        },
        sort_keys=True,
    )
    declared_sha = hashlib.sha256(declared.encode("utf-8")).hexdigest()
    bundle_hashes = sorted(_safe_sha256(p) for p in artifact.bundled_files)
    bundle_sha = hashlib.sha256(",".join(bundle_hashes).encode("utf-8")).hexdigest()
    return Fingerprint(
        host=artifact.host.value,
        kind=artifact.kind.value,
        name=artifact.name,
        path=str(artifact.path),
        declared_sha=declared_sha,
        bundle_sha=bundle_sha,
        metadata=dict(artifact.metadata) if isinstance(artifact.metadata, dict) else {},
    )


def save_baseline(conn: sqlite3.Connection, scan_root: str, artifacts: list[Artifact]) -> int:
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (scan_root, created_at, artifact_count) VALUES (?, ?, ?)",
        (scan_root, int(time.time()), len(artifacts)),
    )
    scan_id = cursor.lastrowid
    rows = []
    for artifact in artifacts:
        fp = fingerprint(artifact)
        rows.append((
            scan_id, fp.host, fp.kind, fp.name, fp.path,
            fp.declared_sha, fp.bundle_sha,
            json.dumps(fp.metadata, sort_keys=True),
        ))
    cursor.executemany(
        """INSERT INTO artifact_fingerprints
           (scan_id, host, kind, name, path, declared_sha, bundle_sha, metadata_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    conn.commit()
    return int(scan_id)


def latest_baseline(conn: sqlite3.Connection, scan_root: str) -> dict[tuple[str, str, str], Fingerprint]:
    """Return the most recent fingerprint per (host, kind, name) for a given scan root."""
    cursor = conn.cursor()
    cursor.execute(
        """SELECT a.host, a.kind, a.name, a.path, a.declared_sha, a.bundle_sha, a.metadata_json
           FROM artifact_fingerprints a
           JOIN scans s ON s.id = a.scan_id
           WHERE s.scan_root = ?
           ORDER BY s.created_at ASC""",
        (scan_root,),
    )
    out: dict[tuple[str, str, str], Fingerprint] = {}
    for host, kind, name, path, declared, bundle, meta_json in cursor.fetchall():
        out[(host, kind, name)] = Fingerprint(
            host=host, kind=kind, name=name, path=path,
            declared_sha=declared, bundle_sha=bundle,
            metadata=json.loads(meta_json),
        )
    return out


def diff_against_baseline(
    artifacts: list[Artifact],
    baseline: dict[tuple[str, str, str], Fingerprint],
) -> list[DriftSignal]:
    """Compute drift signals for the current artifact set vs a baseline."""
    signals: list[DriftSignal] = []
    seen: set[tuple[str, str, str]] = set()

    for artifact in artifacts:
        current = fingerprint(artifact)
        key = (current.host, current.kind, current.name)
        seen.add(key)
        prev = baseline.get(key)
        if prev is None:
            signals.append(
                DriftSignal(
                    artifact=artifact,
                    kind="new-artifact",
                    summary=f"New artifact `{current.name}` ({current.kind}) appeared since last baseline",
                    previous={},
                    current={"declared_sha": current.declared_sha, "bundle_sha": current.bundle_sha},
                )
            )
            continue
        bundle_changed = prev.bundle_sha != current.bundle_sha
        declared_changed = prev.declared_sha != current.declared_sha
        if bundle_changed and not declared_changed:
            signals.append(
                DriftSignal(
                    artifact=artifact,
                    kind="rug-pull",
                    summary=(
                        f"Bundle of `{current.name}` changed but description / allowed-tools "
                        "did not — classic rug-pull pattern."
                    ),
                    previous={"bundle_sha": prev.bundle_sha},
                    current={"bundle_sha": current.bundle_sha},
                )
            )
        elif declared_changed and not bundle_changed:
            signals.append(
                DriftSignal(
                    artifact=artifact,
                    kind="scope-change",
                    summary=f"Declared scope (description / allowed-tools) of `{current.name}` changed",
                    previous={"declared_sha": prev.declared_sha},
                    current={"declared_sha": current.declared_sha},
                )
            )
        elif bundle_changed and declared_changed:
            signals.append(
                DriftSignal(
                    artifact=artifact,
                    kind="scope-change",
                    summary=f"Both declared scope and bundle of `{current.name}` changed",
                    previous={"declared_sha": prev.declared_sha, "bundle_sha": prev.bundle_sha},
                    current={"declared_sha": current.declared_sha, "bundle_sha": current.bundle_sha},
                )
            )

    # Removed artifacts (in baseline but not current)
    for key, prev in baseline.items():
        if key in seen:
            continue
        from skillscan.models import Artifact as _A, ArtifactKind as _K, Host as _H
        host_value = prev.host if isinstance(prev.host, str) else "unknown"
        kind_value = prev.kind if isinstance(prev.kind, str) else "skill"
        try:
            host_enum = _H(host_value)
        except ValueError:
            host_enum = _H.UNKNOWN
        try:
            kind_enum = _K(kind_value)
        except ValueError:
            kind_enum = _K.SKILL
        synthetic = _A(kind=kind_enum, host=host_enum, name=prev.name, path=Path(prev.path))
        signals.append(
            DriftSignal(
                artifact=synthetic,
                kind="removed",
                summary=f"Artifact `{prev.name}` was present in baseline but not in current scan",
                previous={"declared_sha": prev.declared_sha, "bundle_sha": prev.bundle_sha},
                current={},
            )
        )
    return signals


# --------------------------------------------------------------------------- #

def _normalize_tools(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def _safe_sha256(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return f"missing:{path.name}"
