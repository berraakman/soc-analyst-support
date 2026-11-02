"""Motor: log dosyalarını takip eder, zaman pencerelerine böler, dedektörden geçirir, gerekirse LLM'e sorar."""
from __future__ import annotations

import json
import random
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

from .detector import Baseline, analyze, compute, select_evidence
from .generator import SOURCES
from .parsers import Event, parse

LABELS = {"normal": "NORMAL", "dinamik_hata": "DİNAMİK HATA", "imzasiz_saldiri": "İMZASIZ SALDIRI",
          "bilinen_saldiri": "BİLİNEN SALDIRI", "belirsiz": "BELİRSİZ"}


class Tailer:
    """Dosyaları `tail -f` gibi okur; yarım satırları bir sonraki okumaya bırakır."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.handles: dict[str, object] = {}
        self.lineno = defaultdict(int)
        self.partial = defaultdict(str)

    def poll(self) -> list[Event]:
        out = []
        for s in SOURCES:
            if s not in self.handles:
                p = self.log_dir / f"{s}.log"
                if not p.exists():
                    continue
                self.handles[s] = open(p, encoding="utf-8")
            chunk = self.handles[s].read()
            if not chunk:
                continue
            data = self.partial[s] + chunk
            lines = data.split("\n")
            self.partial[s] = lines.pop()  # son eleman boş ya da yarım satır
            for line in lines:
                self.lineno[s] += 1
                if ev := parse(s, self.lineno[s], line):
                    out.append(ev)
        return out


class Engine:
    def __init__(self, log_dir: str | Path, out_path: str | Path, judge, window_s: int = 60,
                 warmup_windows: int = 10, llm_all: bool = False, lateness_s: int = 5, quiet: bool = False):
        self.log_dir = Path(log_dir)
        self.out_path = Path(out_path)
        self.judge = judge
        self.window = timedelta(seconds=window_s)
        self.warmup = warmup_windows
        self.llm_all = llm_all
        self.lateness = timedelta(seconds=lateness_s)
        self.quiet = quiet
        ctx = self.log_dir / "context.json"
        self.context = json.loads(ctx.read_text(encoding="utf-8")) if ctx.exists() else {}
        self.tailer = Tailer(self.log_dir)
        self.baseline = Baseline()
        self.buffers: dict[int, list[Event]] = defaultdict(list)
        self.t0: datetime | None = None
        self.watermark: datetime | None = None
        self.recent: deque = deque(maxlen=3)
        self.rng = random.Random(0)

    # ------------------------------------------------------------ akış
    def ingest(self, events: list[Event]):
        for e in events:
            if self.t0 is None:
                self.t0 = e.ts.replace(second=0, microsecond=0)
            idx = int((e.ts - self.t0) / self.window)
            if idx < 0:
                continue
            self.buffers[idx].append(e)
            self.watermark = e.ts if self.watermark is None else max(self.watermark, e.ts)

    def close_ready(self, out, final: bool = False):
        for idx in sorted(self.buffers):
            end = self.t0 + (idx + 1) * self.window
            if final or self.watermark >= end + self.lateness:
                out.write(json.dumps(self.process(idx, self.buffers.pop(idx)), ensure_ascii=False) + "\n")
                out.flush()

    def run(self, follow: bool = False, poll_s: float = 1.0):
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.out_path, "w", encoding="utf-8") as out:
            try:
                while True:
                    events = self.tailer.poll()
                    self.ingest(events)
                    if self.t0 is not None:
                        self.close_ready(out)
                    if not events:
                        if not follow:
                            break
                        time.sleep(poll_s)
            except KeyboardInterrupt:
                pass
            if self.t0 is not None:
                self.close_ready(out, final=True)

    # ------------------------------------------------------------ pencere işleme
    def process(self, idx: int, events: list[Event]) -> dict:
        events.sort(key=lambda e: e.ts)
        start = self.t0 + idx * self.window
        rec = {
            "window": idx, "start": start.isoformat(), "end": (start + self.window).isoformat(),
            "counts": {s: sum(e.source == s for e in events) for s in SOURCES},
        }
        if idx < self.warmup:
            feats, sets, _ = compute(events)
            self.baseline.update(feats, sets)
            rec.update(decided_by="warmup", verdict="normal", triggered=False, trigger_reasons=[], decision=None, error=None)
            self._print(rec)
            return rec

        analysis = analyze(events, self.baseline)
        evidence = select_evidence(events, analysis["novel"], rng=self.rng)
        window = {**rec, "analysis": analysis, "evidence": [{"id": e.id, "raw": e.raw} for e in evidence]}
        rec.update(triggered=analysis["triggered"], trigger_reasons=analysis["trigger_reasons"],
                   deviations=analysis["deviations"], signature_hits=analysis["signature_hits"],
                   evidence_shown=[e.id for e in evidence])

        if analysis["triggered"] or self.llm_all:
            t = time.monotonic()
            decision, error = self.judge.decide(window, self.context, list(self.recent))
            rec["latency_s"] = round(time.monotonic() - t, 1)
            if decision:
                shown = set(rec["evidence_shown"])
                # Uydurma kanıt kontrolü: LLM'e gösterilmeyen satır kimlikleri
                rec["invalid_evidence"] = [ev["line_id"] for ev in decision["evidence"] if ev["line_id"] not in shown]
                rec.update(decided_by="llm", verdict=decision["verdict"], decision=decision, error=None, model=self.judge.model)
            else:
                rec.update(decided_by="llm_error", verdict="belirsiz", decision=None, error=error)
        else:
            rec.update(decided_by="detector", verdict="normal", decision=None, error=None)

        if not analysis["triggered"]:
            # Baseline yalnızca temiz pencerelerden öğrenir; saldırıyı "normal" diye öğrenmesin.
            self.baseline.update(analysis["features"], analysis["sets"])
        elif rec["verdict"] == "normal":
            # LLM sapmayı meşru buldu: yeni varlıkları tanı, ama uç sayısal değerleri baseline'a katma.
            self.baseline.learn_entities(analysis["sets"])
        title = (rec.get("decision") or {}).get("title", "")
        self.recent.append({"window_start": rec["start"], "verdict": rec["verdict"], "title": title})
        self._print(rec)
        return rec

    def _print(self, rec: dict):
        if self.quiet:
            return
        hhmm = rec["start"][11:16]
        if rec["decided_by"] in ("warmup", "detector"):
            print(f"{hhmm}  {'·':<16} {rec['decided_by']}", flush=True)
            return
        d = rec.get("decision")
        label = LABELS.get(rec["verdict"], rec["verdict"])
        if d:
            flag = "  [İNSAN İNCELEMESİ]" if d["needs_human_review"] else ""
            print(f"{hhmm}  {label:<16} {d['title']}  (önem {d['severity']}, güven {d['confidence']}, {rec['latency_s']}s){flag}", flush=True)
        else:
            print(f"{hhmm}  {label:<16} LLM hatası: {rec['error']}", flush=True)
