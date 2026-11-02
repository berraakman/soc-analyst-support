"""Ham log satırlarını ortak bir olay (Event) yapısına çevirir."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote

WEB_RE = re.compile(r'^(?P<ip>\S+) - (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
                    r'(?P<status>\d{3}) (?P<size>\d+) "[^"]*" "(?P<ua>[^"]*)" rt=(?P<rt>[\d.]+)$')
SYSLOG_RE = re.compile(r"^(?P<ts>\S+) (?P<host>\S+) (?P<prog>[\w-]+)(?:\[\d+\])?: (?P<msg>.*)$")
PROC_RE = re.compile(r'^(?P<ts>\S+) host=(?P<host>\S+) user=(?P<user>\S+) pid=(?P<pid>\d+) ppid=(?P<ppid>\d+) '
                     r'parent=(?P<parent>\S+) exe=(?P<exe>\S+) cmd="(?P<cmd>.*)"$')
SSH_FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
SSH_OK_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")


@dataclass
class Event:
    id: str            # "web:123" -> kaynak:satır numarası, LLM kanıt gösterirken bunu kullanır
    ts: datetime
    source: str
    raw: str
    f: dict = field(default_factory=dict)


def parse(source: str, lineno: int, line: str) -> Event | None:
    line = line.rstrip("\n")
    eid = f"{source}:{lineno}"
    try:
        if source == "web":
            m = WEB_RE.match(line)
            if not m:
                return None
            d = m.groupdict()
            d.update(status=int(d["status"]), size=int(d["size"]), rt=float(d["rt"]), path_decoded=unquote(d["path"]))
            return Event(eid, datetime.strptime(d.pop("ts"), "%d/%b/%Y:%H:%M:%S %z"), source, line, d)
        if source == "auth":
            m = SYSLOG_RE.match(line)
            if not m:
                return None
            d = m.groupdict()
            msg = d["msg"]
            if fm := SSH_FAIL_RE.search(msg):
                d.update(kind="ssh_fail", **fm.groupdict())
            elif om := SSH_OK_RE.search(msg):
                d.update(kind="ssh_ok", **om.groupdict())
            elif d["prog"] == "sudo":
                d["kind"] = "sudo"
            elif "useradd" in msg or d["prog"] == "useradd":
                d["kind"] = "useradd"
            else:
                d["kind"] = "other"
            return Event(eid, datetime.fromisoformat(d.pop("ts")), source, line, d)
        if source == "app":
            d = json.loads(line)
            return Event(eid, datetime.fromisoformat(d.pop("ts")), source, line, d)
        if source == "proc":
            m = PROC_RE.match(line)
            if not m:
                return None
            d = m.groupdict()
            return Event(eid, datetime.fromisoformat(d.pop("ts")), source, line, d)
    except (ValueError, KeyError):
        return None
    return None
