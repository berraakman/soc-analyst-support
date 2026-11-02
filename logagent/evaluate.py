"""Motor kararlarını ground_truth.json ile karşılaştırır."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

CLASSES = ["normal", "dinamik_hata", "imzasiz_saldiri", "bilinen_saldiri"]
PRED = CLASSES + ["belirsiz"]
MIN_OVERLAP_S = 20


def _overlap(a0, a1, b0, b1) -> float:
    return max(0.0, (min(a1, b1) - max(a0, b0)).total_seconds())


def truth_for(rec: dict, truth: list[dict]) -> dict | None:
    w0, w1 = datetime.fromisoformat(rec["start"]), datetime.fromisoformat(rec["end"])
    best, best_ov = None, 0.0
    for s in truth:
        ov = _overlap(w0, w1, datetime.fromisoformat(s["start"]), datetime.fromisoformat(s["end"]))
        if ov > best_ov:
            best, best_ov = s, ov
    return best if best_ov >= MIN_OVERLAP_S else None


def evaluate(log_dir: str | Path, decisions_path: str | Path) -> dict:
    truth = json.loads((Path(log_dir) / "ground_truth.json").read_text(encoding="utf-8"))
    recs = [json.loads(l) for l in open(decisions_path, encoding="utf-8") if l.strip()]
    recs = [r for r in recs if r["decided_by"] != "warmup"]

    confusion = defaultdict(Counter)
    by_scenario = defaultdict(list)
    det = Counter()
    for r in recs:
        sc = truth_for(r, truth)
        label = sc["label"] if sc else "normal"
        r["_truth"], r["_scenario"] = label, sc
        confusion[label][r["verdict"]] += 1
        if sc:
            by_scenario[sc["id"]].append(r)
        kind = "anomali" if label != "normal" else ("decoy" if sc and sc["decoy"] else "temiz")
        det[(kind, r["triggered"])] += 1

    per_class = {}
    for c in CLASSES:
        tp = confusion[c][c]
        fp = sum(confusion[t][c] for t in CLASSES if t != c)
        fn = sum(confusion[c].values()) - tp
        p = tp / (tp + fp) if tp + fp else 0.0
        rc = tp / (tp + fn) if tp + fn else 0.0
        per_class[c] = {"precision": round(p, 2), "recall": round(rc, 2),
                        "f1": round(2 * p * rc / (p + rc), 2) if p + rc else 0.0, "pencere": tp + fn}

    scenarios = []
    for s in truth:
        rs = by_scenario.get(s["id"], [])
        correct = [r for r in rs if r["verdict"] == s["label"]]
        delay = None
        if correct:
            delay = (datetime.fromisoformat(correct[0]["start"]) - datetime.fromisoformat(s["start"])).total_seconds() / 60
        scenarios.append({"id": s["id"], "gerçek": s["label"] + (" (decoy)" if s["decoy"] else ""),
                          "kararlar": [r["verdict"] for r in rs], "doğru_tespit": bool(correct),
                          "gecikme_dk": round(max(delay, 0), 1) if delay is not None else None})

    llm = [r for r in recs if r["decided_by"] == "llm"]
    refs = sum(len(r["decision"]["evidence"]) for r in llm)
    bad = sum(len(r.get("invalid_evidence", [])) for r in llm)
    return {
        "pencere_sayısı": len(recs),
        "llm_çağrısı": len(llm),
        "llm_hatası": sum(r["decided_by"] == "llm_error" for r in recs),
        "ortalama_llm_süresi_s": round(sum(r["latency_s"] for r in llm) / len(llm), 1) if llm else None,
        "insan_incelemesi_oranı": round(sum(r["decision"]["needs_human_review"] for r in llm) / len(llm), 2) if llm else None,
        "uydurma_kanıt_oranı": round(bad / refs, 3) if refs else None,
        "dedektör": {
            "anomali_yakalama": f"{det[('anomali', True)]}/{det[('anomali', True)] + det[('anomali', False)]}",
            "temiz_pencerede_tetikleme": f"{det[('temiz', True)]}/{det[('temiz', True)] + det[('temiz', False)]}",
            "decoy_tetikleme": f"{det[('decoy', True)]}/{det[('decoy', True)] + det[('decoy', False)]}",
        },
        "sınıf_bazında": per_class,
        "karışıklık_matrisi": {t: {p: confusion[t][p] for p in PRED} for t in CLASSES},
        "senaryolar": scenarios,
    }


def print_report(rep: dict):
    print(f"Pencere: {rep['pencere_sayısı']}  LLM çağrısı: {rep['llm_çağrısı']}  LLM hatası: {rep['llm_hatası']}  "
          f"Ort. LLM süresi: {rep['ortalama_llm_süresi_s']}s")
    print(f"İnsan incelemesi oranı: {rep['insan_incelemesi_oranı']}  Uydurma kanıt oranı: {rep['uydurma_kanıt_oranı']}")
    print("\nDedektör (LLM öncesi katman):")
    for k, v in rep["dedektör"].items():
        print(f"  {k:<28} {v}")
    print("\nSenaryolar:")
    print(f"  {'id':<14} {'gerçek':<26} {'tespit':<7} {'gecikme':<8} kararlar")
    for s in rep["senaryolar"]:
        print(f"  {s['id']:<14} {s['gerçek']:<26} {'evet' if s['doğru_tespit'] else 'HAYIR':<7} "
              f"{str(s['gecikme_dk']) + ' dk' if s['gecikme_dk'] is not None else '-':<8} {', '.join(s['kararlar'])}")
    print("\nSınıf bazında:")
    for c, m in rep["sınıf_bazında"].items():
        print(f"  {c:<16} P={m['precision']:<5} R={m['recall']:<5} F1={m['f1']:<5} (n={m['pencere']})")
    print("\nKarışıklık matrisi (satır=gerçek, sütun=tahmin):")
    print(f"  {'':<16}" + "".join(f"{p[:10]:>11}" for p in PRED))
    for t, row in rep["karışıklık_matrisi"].items():
        print(f"  {t:<16}" + "".join(f"{row[p]:>11}" for p in PRED))
