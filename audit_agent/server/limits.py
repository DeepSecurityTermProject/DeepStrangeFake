from __future__ import annotations

from typing import Any


CONSOLE_LIMITS_SCHEMA_VERSION = "project-console-limits.v1"

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200
MAX_PAGE_OFFSET = 100_000

EVENT_REPLAY_LIMIT = 500
EVENT_MAX_SUBSCRIBERS_PER_RUN = 8
EVENT_MAX_SUBSCRIBERS_TOTAL = 32
EVENT_DIAGNOSTIC_LIMIT = 100

DASHBOARD_RECENT_RUN_LIMIT = 12
DASHBOARD_HIGH_RISK_LIMIT = 20


def public_console_limits() -> dict[str, Any]:
    """Return non-secret operational bounds and first-release retention semantics."""

    return {
        "schema_version": CONSOLE_LIMITS_SCHEMA_VERSION,
        "pagination": {
            "default_limit": DEFAULT_PAGE_LIMIT,
            "max_limit": MAX_PAGE_LIMIT,
            "max_offset": MAX_PAGE_OFFSET,
        },
        "events": {
            "replay_limit": EVENT_REPLAY_LIMIT,
            "max_subscribers_per_run": EVENT_MAX_SUBSCRIBERS_PER_RUN,
            "max_subscribers_total": EVENT_MAX_SUBSCRIBERS_TOTAL,
            "diagnostic_retention": EVENT_DIAGNOSTIC_LIMIT,
        },
        "dashboard": {
            "recent_run_limit": DASHBOARD_RECENT_RUN_LIMIT,
            "high_risk_finding_limit": DASHBOARD_HIGH_RISK_LIMIT,
        },
        "retention": {
            "projects_and_runs": "retained-until-manual-storage-removal",
            "run_artifacts": "retained-in-authoritative-run-directory",
            "event_journals": "retained-for-run-lifetime",
            "posture_snapshots": "rebuildable-and-retained-for-run-lifetime",
            "automatic_deletion": False,
        },
    }
