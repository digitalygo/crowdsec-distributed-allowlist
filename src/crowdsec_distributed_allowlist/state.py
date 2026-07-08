"""JSON state file persistence with atomic writes.

Design
------
State is a simple JSON dictionary (see contract for schema). Every write
goes through a temporary file in the same directory, followed by
``flush()`` + ``os.fsync()`` and ``os.replace()`` to guarantee atomic
replacement on POSIX.

Load errors (missing file, corrupt JSON) never crash the server; they
emit a WARNING and return an empty state dict.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any, Dict

logger = logging.getLogger(__name__)

StateDict = Dict[str, Any]


def load_state(path: str) -> StateDict:
    """Return parsed state dict, or an empty dict on any load failure."""
    if not os.path.exists(path):
        logger.debug("state file not found at %s, starting empty", path)
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("failed to load state from %s: %s, starting empty", path, exc)
        return {}
    if not isinstance(data, dict):
        logger.warning("state file %s is not a JSON object, starting empty", path)
        return {}
    return data


def save_state(path: str, state: StateDict) -> None:
    """Atomically write *state* to *path*.

    Writes to a temporary file in the same directory, then atomically
    replaces the target file with ``os.replace()``.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(
        suffix=".json",
        prefix=".crowdsec-allowlist-state-",
        dir=directory,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except Exception:
        # Clean up the temp file on failure so we don't leak files.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
