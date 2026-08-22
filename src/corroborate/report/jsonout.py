"""JSON output, for maintainers wiring their own triage automation.

Stable shape: adding fields is fine, renaming or removing them is a breaking
change. Anything built on this needs to survive a `corroborate` upgrade.
"""

from __future__ import annotations

import json

from ..verdict import Result
from . import DISCLAIMER


def render(result: Result) -> str:
    return json.dumps(
        {
            "tool": "corroborate",
            "version": 1,
            "ref": result.ref,
            "repo": result.repo_path,
            "counts": result.counts,
            "disclaimer": DISCLAIMER,
            "claims": [
                {
                    "kind": v.claim.kind.value,
                    "tier": v.claim.tier,
                    "raw": v.claim.raw,
                    "span": list(v.claim.span),
                    "in_code": v.claim.in_code,
                    "data": v.claim.data,
                    "status": v.status.value,
                    "detail": v.detail,
                    "query": v.query,
                    "hint": v.hint,
                }
                for v in result.verdicts
            ],
        },
        indent=2,
    )
