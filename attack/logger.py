#!/usr/bin/env python3
"""JSON-lines event logger, ported unchanged from
terrapin-harness-submission:terrapin-harness/relay/logger.py so trial logs
written here follow the same convention described in the project write-up,
Section 4: logs/<target>_<cipher>_<patched|vulnerable>_<manual|auto>_trialNN.jsonl
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional


class JsonlLogger:
    def __init__(self, path: str | Path, echo: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.echo = echo
        self._lock = threading.Lock()
        self._fh = open(self.path, "a", buffering=1)

    def log(
        self,
        event: str,
        direction: Optional[str] = None,
        msg_type: Optional[int] = None,
        msg_name: Optional[str] = None,
        length: Optional[int] = None,
        note: Optional[str] = None,
        **extra: Any,
    ) -> None:
        record = {
            "ts": time.time(),
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "event": event,
            "direction": direction,
            "msg_type": msg_type,
            "msg_name": msg_name,
            "length": length,
            "note": note,
        }
        record.update(extra)
        line = json.dumps(record, sort_keys=True)
        with self._lock:
            self._fh.write(line + "\n")
            if self.echo:
                short = f"[{record['event']}]"
                if direction:
                    short += f" {direction}"
                if msg_name:
                    short += f" {msg_name}"
                if note:
                    short += f" -- {note}"
                print(short, file=sys.stderr, flush=True)

    def close(self) -> None:
        self._fh.close()
