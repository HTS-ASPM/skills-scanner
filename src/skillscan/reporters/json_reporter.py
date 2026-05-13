from __future__ import annotations

import json

from skillscan.models import ScanResult


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, sort_keys=False)
