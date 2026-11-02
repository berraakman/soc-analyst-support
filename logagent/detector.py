"""İmzasız tespit katmanı: pencere istatistikleri, öğrenilen davranış tabanı (baseline) ve sapma.

Bu katman ucuzdur ve her pencerede çalışır. Ne olduğunu söylemez, yalnızca "burada olağandışı bir şey var"
der ve LLM'e gidecek kanıtı hazırlar. Bilinen saldırılar için küçük bir imza kümesi de vardır; böylece
LLM imzalı ve imzasız durumları ayırt edebilir.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .parsers import Event

WEB_PARENTS = {"php-fpm", "nginx", "apache2", "httpd"}
Z_TRIGGER = 4.0
# z-skorunda paydanın alt sınırı: sayımlar için 1, saniye/MB cinsinden öznitelikler için kendi ölçeğinde
STD_FLOOR = {"web_p95_latency_s": 0.05, "web_max_mb_per_actor": 0.5}

SIGNATURES = [
    ("SQL injection kalıbı", re.compile(r"(?i)(union\s+select|'\s*or\s*1\s*=\s*1|sleep\(\d+\)|drop\s+table)")),
    ("Path traversal kalıbı", re.compile(r"\.\./\.\./")),
    ("Bilinen saldırı aracı user-agent", re.compile(r"(?i)(sqlmap|nikto|masscan|acunetix|nmap scripting)")),
]
SSH_BRUTE_THRESHOLD = 20  # tek IP'den pencere başına başarısız SSH: klasik eşik kuralı


def path_template(path: str) -> str:
    base = path.split("?", 1)[0]
    return re.sub(r"\d+", "{n}", base)


def p95(values: list[float]) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return v[min(len(v) - 1, int(math.ceil(0.95 * len(v))) - 1)]


def compute(events: list[Event]) -> tuple[dict[str, float], dict[str, set], dict]:
    """Bir penceredeki olaylardan sayısal öznitelikler, yenilik kümeleri ve 'en çok konuşanlar' çıkarır."""
    web = [e for e in events if e.source == "web"]
    auth = [e for e in events if e.source == "auth"]
    app = [e for e in events if e.source == "app"]
    proc = [e for e in events if e.source == "proc"]

    actor = lambda e: e.f["user"] if e.f["user"] != "-" else e.f["ip"]
    bytes_by_actor, ids_by_actor, req_by_ip = Counter(), defaultdict(set), Counter()
    for e in web:
        bytes_by_actor[actor(e)] += e.f["size"]
        req_by_ip[e.f["ip"]] += 1
        base = e.f["path"].split("?", 1)[0]
        nums = re.findall(r"\d+", base)
        if nums and not base.startswith("/static"):
            ids_by_actor[(actor(e), path_template(base))].update(nums)
    login401 = [e for e in web if e.f["path"] == "/login" and e.f["status"] == 401]
    fails_by_ip = Counter(e.f["ip"] for e in auth if e.f.get("kind") == "ssh_fail")

    feats = {
        "web_requests": len(web),
        "web_5xx": sum(e.f["status"] >= 500 for e in web),
        "web_4xx": sum(400 <= e.f["status"] < 500 for e in web),
        "web_login_401": len(login401),
        "web_login_401_distinct_ips": len({e.f["ip"] for e in login401}),
        "web_p95_latency_s": round(p95([e.f["rt"] for e in web]), 3),
        "web_max_mb_per_actor": round(max(bytes_by_actor.values(), default=0) / 1e6, 2),
        "web_max_distinct_ids_per_actor": max((len(v) for v in ids_by_actor.values()), default=0),
        "auth_ssh_fail": sum(fails_by_ip.values()),
        "auth_ssh_fail_max_per_ip": max(fails_by_ip.values(), default=0),
        "auth_sudo": sum(e.f.get("kind") == "sudo" for e in auth),
        "app_error": sum(e.f.get("level") == "ERROR" for e in app),
        "app_fatal": sum(e.f.get("level") == "FATAL" for e in app),
        "app_warn": sum(e.f.get("level") == "WARN" for e in app),
        "proc_events": len(proc),
        "proc_from_web_server": sum(e.f["parent"] in WEB_PARENTS or e.f["user"] == "www-data" for e in proc),
    }
    sets = {
        "web_ip": {e.f["ip"] for e in web},
        "web_user_agent": {e.f["ua"] for e in web},
        "web_user_ip": {f"{e.f['user']}@{e.f['ip']}" for e in web if e.f["user"] != "-"},
        "web_path_template": {path_template(e.f["path"]) for e in web},
        "auth_login_ip": {f"{e.f['user']}@{e.f['ip']}" for e in auth if e.f.get("kind") == "ssh_ok"},
        "proc_exe": {f"{e.f['user']}:{e.f['exe']}" for e in proc},
        "app_alert_msg": {e.f.get("msg", "") for e in app if e.f.get("level") in ("WARN", "ERROR", "FATAL")},
    }
    top = {
        "web_top_ips": dict(req_by_ip.most_common(5)),
        "web_top_bytes_mb": {k: round(v / 1e6, 2) for k, v in bytes_by_actor.most_common(3)},
        "ssh_fail_top_ips": dict(fails_by_ip.most_common(3)),
    }
    return feats, sets, top


# Hangi yeniliklerin tek başına tetikleyici olduğu ve kaç tane gerektiği
NOVELTY_TRIGGERS = {"web_user_ip": 1, "web_path_template": 1, "auth_login_ip": 1, "proc_exe": 1, "app_alert_msg": 1, "web_ip": 5}


@dataclass
class Baseline:
    """Welford ile çevrimiçi ortalama/varyans + görülmüş varlık kümeleri. Yalnızca temiz pencerelerden öğrenir."""
    n: int = 0
    mean: dict = field(default_factory=dict)
    m2: dict = field(default_factory=dict)
    seen: dict = field(default_factory=lambda: defaultdict(set))

    def update(self, feats: dict, sets: dict):
        self.n += 1
        for k, v in feats.items():
            mu = self.mean.get(k, 0.0)
            d = v - mu
            mu += d / self.n
            self.mean[k] = mu
            self.m2[k] = self.m2.get(k, 0.0) + d * (v - mu)
        for k, s in sets.items():
            self.seen[k] |= s

    def learn_entities(self, sets: dict):
        """Sayısal istatistiklere dokunmadan yalnızca görülmüş varlıkları öğrenir (LLM 'normal' dediğinde)."""
        for k, s in sets.items():
            self.seen[k] |= s

    def z(self, k: str, v: float) -> float:
        mu = self.mean.get(k, 0.0)
        std = math.sqrt(self.m2.get(k, 0.0) / max(self.n - 1, 1))
        return (v - mu) / max(std, STD_FLOOR.get(k, 1.0), 0.1 * abs(mu))

    def stats(self, k: str) -> tuple[float, float]:
        return round(self.mean.get(k, 0.0), 2), round(math.sqrt(self.m2.get(k, 0.0) / max(self.n - 1, 1)), 2)


def signature_hits(events: list[Event], feats: dict, top: dict) -> list[dict]:
    hits = []
    for name, rx in SIGNATURES:
        ids = [e.id for e in events if e.source == "web" and (rx.search(e.f["path_decoded"]) or rx.search(e.f["ua"]))]
        if ids:
            hits.append({"rule": name, "count": len(ids), "sample_ids": ids[:5]})
    if feats["auth_ssh_fail_max_per_ip"] >= SSH_BRUTE_THRESHOLD:
        hits.append({"rule": f"SSH brute force eşiği (tek IP >= {SSH_BRUTE_THRESHOLD} başarısız)",
                     "count": feats["auth_ssh_fail_max_per_ip"], "sample_ids": [], "ips": top["ssh_fail_top_ips"]})
    return hits


def interesting(e: Event, novel: dict[str, set]) -> str | None:
    """Olay LLM'e kanıt olarak gösterilmeye değerse bir gruplama anahtarı döner."""
    f = e.f
    if e.source == "web":
        tpl = path_template(f["path"])
        if (f["status"] >= 500 or f["status"] in (401, 403) or f["size"] > 500_000 or tpl in novel["web_path_template"]
                or f"{f['user']}@{f['ip']}" in novel["web_user_ip"] or f["ip"] in novel["web_ip"]):
            return f"web|{f['status']}|{tpl}"
    elif e.source == "auth":
        if f.get("kind") in ("ssh_fail", "sudo", "useradd") or f"{f.get('user')}@{f.get('ip')}" in novel["auth_login_ip"]:
            return f"auth|{f.get('kind')}|{f.get('ip')}"
    elif e.source == "app":
        if f.get("level") in ("ERROR", "FATAL") or (f.get("level") == "WARN" and f.get("msg") != "slow query") \
                or f.get("msg") == "order-api starting":
            return f"app|{f.get('level')}|{f.get('msg')}"
    elif e.source == "proc":
        if f["parent"] in WEB_PARENTS or f["user"] == "www-data" or f"{f['user']}:{f['exe']}" in novel["proc_exe"]:
            return f"proc|{f['user']}|{f['exe']}"
    return None


def select_evidence(events: list[Event], novel: dict[str, set], cap: int = 40, per_group: int = 4,
                    normal_samples: int = 4, rng=None) -> list[Event]:
    """İlginç olayları gruplayıp gruplar arasında dönüşümlü seçer; karşılaştırma için birkaç normal satır ekler."""
    groups: dict[str, list[Event]] = defaultdict(list)
    normal = []
    for e in events:
        key = interesting(e, novel)
        (groups[key] if key else normal).append(e)
    picked, round_ = [], 0
    while len(picked) < cap and round_ < per_group:
        for evs in groups.values():
            if round_ < len(evs) and len(picked) < cap:
                # grubun başından, ortasından, sonundan örnekle
                idx = [0, len(evs) - 1, len(evs) // 2, len(evs) // 4][round_]
                if evs[idx] not in picked:
                    picked.append(evs[idx])
        round_ += 1
    if rng and normal:
        picked += rng.sample(normal, min(normal_samples, len(normal)))
    return sorted(picked, key=lambda e: e.ts)


def analyze(events: list[Event], baseline: Baseline) -> dict:
    """Bir pencereyi baseline'a göre değerlendirir. LLM'e gidecek raporu döner (karar içermez)."""
    feats, sets, top = compute(events)
    deviations = {}
    for k, v in feats.items():
        z = baseline.z(k, v)
        if abs(z) >= Z_TRIGGER:
            mu, sd = baseline.stats(k)
            deviations[k] = {"value": v, "baseline_mean": mu, "baseline_std": sd, "z": round(z, 1)}
    novel = {k: s - baseline.seen.get(k, set()) for k, s in sets.items()}
    hits = signature_hits(events, feats, top)

    reasons = [f"{k} z={d['z']}" for k, d in deviations.items() if d["z"] > 0]
    reasons += [f"yeni {k} x{len(novel[k])}" for k, need in NOVELTY_TRIGGERS.items() if len(novel[k]) >= need]
    reasons += [f"imza: {h['rule']}" for h in hits]
    return {
        "features": feats, "sets": sets, "novel": novel, "top": top,
        "deviations": deviations, "signature_hits": hits,
        "triggered": bool(reasons), "trigger_reasons": reasons,
    }
