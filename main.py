"""Log analiz ajanı - komut satırı.

  python main.py generate                      # 56 dakikalık sahte log üret (anında)
  python main.py generate --live --speed 20    # gerçek zamanlı akış (20x hızlı)
  python main.py run                           # logları analiz et
  python main.py run --follow                  # akan logları canlı izle
  python main.py evaluate                      # kararları ground truth ile karşılaştır
"""
from __future__ import annotations

import argparse
import json
import sys

sys.stdout.reconfigure(encoding="utf-8")


def cmd_generate(a):
    from logagent.generator import write
    if a.live:
        print(f"Canlı akış başladı ({a.speed}x). Durdurmak için Ctrl+C.", flush=True)
    n, t0, t1 = write(a.logs, seed=a.seed, live=a.live, speed=a.speed)
    print(f"{n} satır yazıldı -> {a.logs}  ({t0:%H:%M} - {t1:%H:%M})")


def cmd_run(a):
    from logagent.engine import Engine
    from logagent.judge import MockJudge, OllamaJudge
    judge = MockJudge() if a.mock else OllamaJudge(model=a.model) if a.model else OllamaJudge()
    print(f"Yargıç: {judge.model}  pencere: {a.window}s  ısınma: {a.warmup} pencere", flush=True)
    Engine(a.logs, a.out, judge, window_s=a.window, warmup_windows=a.warmup, llm_all=a.llm_all).run(follow=a.follow)
    print(f"Kararlar -> {a.out}")


def cmd_evaluate(a):
    from logagent.evaluate import evaluate, print_report
    rep = evaluate(a.logs, a.decisions)
    if a.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print_report(rep)


def main():
    p = argparse.ArgumentParser(description="Yerel LLM ile log analiz ajanı")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Senaryolu sahte log üret")
    g.add_argument("--logs", default="logs")
    g.add_argument("--seed", type=int, default=7)
    g.add_argument("--live", action="store_true", help="Satırları zaman damgalarına göre gerçek zamanlı yaz")
    g.add_argument("--speed", type=float, default=10.0, help="Canlı modda hız çarpanı")
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("run", help="Logları analiz et")
    r.add_argument("--logs", default="logs")
    r.add_argument("--out", default="results/decisions.jsonl")
    r.add_argument("--window", type=int, default=60, help="Pencere uzunluğu (saniye)")
    r.add_argument("--warmup", type=int, default=10, help="Baseline öğrenme penceresi sayısı")
    r.add_argument("--follow", action="store_true", help="Dosyalar büyüdükçe izlemeye devam et (Ctrl+C ile çık)")
    r.add_argument("--llm-all", action="store_true", help="Dedektör tetiklemese de her pencereyi LLM'e sor")
    r.add_argument("--model", default=None, help="Ollama modeli (varsayılan LOGAGENT_MODEL ya da qwen2.5vl:7b)")
    r.add_argument("--mock", action="store_true", help="LLM yerine kural tabanlı sahte yargıç")
    r.set_defaults(func=cmd_run)

    e = sub.add_parser("evaluate", help="Kararları ground truth ile karşılaştır")
    e.add_argument("--logs", default="logs")
    e.add_argument("--decisions", default="results/decisions.jsonl")
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=cmd_evaluate)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
