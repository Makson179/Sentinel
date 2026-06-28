"""Build-time Sentinel source metadata fallback.

Packagers may replace these constants during release builds. Runtime update
checks prefer PEP 610 direct_url.json metadata when it is available.
"""

SOURCE_URL: str | None = None
REQUESTED_REVISION: str | None = None
COMMIT_SHA: str | None = None
