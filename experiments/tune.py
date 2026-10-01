"""[0단계] 임계값 후보 조합별 TP/FP/FN/TN, Precision/Recall/F1 비교 -> 최종 기준 선정.

    python experiments/tune.py data/features.csv --split 0.7 --seed 42
--split R : 데이터의 R 비율(기본 0.7)만 튜닝에 사용. 나머지는 evaluate.py 가 검증에 사용 (같은 seed 필수).
A) 등록기간 x 다운로드 규칙 조합  (예: age<=7d & dl<=100)
B) 종합 점수 Threshold 스윕 (현재 점수표 기준, 이름 유사도 포함)
"""
import argparse
import csv

from veripi.config import Config
from veripi.scoring import total_from_features

from common import confusion, fmt, fpr, load_features, prf, stratified_split

AGES = [1, 3, 7, 14, 30, 90]
DLS = [100, 500, 1000, 5000, 10000]


def rule_sweep(rows):
    usable = [r for r in rows if r["exists"] and r["age_days"] is not None and r["weekly_downloads"] is not None]
    res = []
    for a in AGES:
        for d in DLS:
            y = [r["label"] for r in usable]
            p = [int(r["age_days"] <= a and r["weekly_downloads"] <= d) for r in usable]
            m = confusion(y, p)
            res.append(dict(rule=f"age<={a}d & dl<={d}", tp=m[0], fp=m[1], fn=m[2], tn=m[3],
                            **dict(zip(("precision", "recall", "f1"), prf(*m))), fpr=fpr(*m)))
    return sorted(res, key=lambda x: (-x["f1"], -x["precision"])), len(rows) - len(usable)


def threshold_sweep(rows, cfg, policy="positive"):
    """policy: positive=미존재/MAL 패키지를 항상 위험 판정, exclude=미존재 패키지를 평가에서 제외."""
    if policy == "exclude":
        rows = [r for r in rows if r["exists"]]
    y = [r["label"] for r in rows]
    totals = [None if (not r["exists"] or r["malware"]) else
              total_from_features(r["age_days"], r["weekly_downloads"], cfg,
                                  r["sim_distance"], r["sim_min_len"])
              for r in rows]
    res = []
    for t in range(1, 14):   # v0.7: 슬롭스쿼팅 총점 최대 13 (OSV 분리)
        p = [1 if s is None or s >= t else 0 for s in totals]
        m = confusion(y, p)
        res.append(dict(threshold=t, tp=m[0], fp=m[1], fn=m[2], tn=m[3],
                        **dict(zip(("precision", "recall", "f1"), prf(*m))), fpr=fpr(*m)))
    return res


def suggest(res, min_precision=0.95):
    """warn = F1 최대 지점(F1 미정의인 지점은 후보에서 제외), fail = warn 보다 엄격하면서
    Precision >= min_precision 인 최소 지점. 조건을 만족하는 fail이 없으면 (warn, None)을
    반환하고, 호출부가 '목표를 만족하는 FAIL 기준 없음'을 명시하도록 한다(§7.3 (5))."""
    scored = [x for x in res if x["f1"] is not None]
    if not scored:
        return None, None
    warn = max(scored, key=lambda x: (x["f1"], -x["threshold"]))["threshold"]
    strict = [x["threshold"] for x in res
             if x["threshold"] > warn and x["precision"] is not None
             and x["precision"] >= min_precision and x["tp"] > 0]
    fail = min(strict) if strict else None
    return warn, fail


def show(res, cols):
    print("  ".join(f"{c:>14}" for c in cols))
    for r in res:
        row = []
        for c in cols:
            v = r[c]
            row.append(f"{v:>14.3f}" if isinstance(v, float) else (f"{'미정의':>14}" if v is None else f"{v:>14}"))
        print("  ".join(row))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("features")
    ap.add_argument("--out")
    ap.add_argument("--min-precision", type=float, default=0.95)
    ap.add_argument("--split", type=float, default=None, help="튜닝에 쓸 비율 (예: 0.7). 미지정 시 전체 사용")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--exists-policy", choices=["positive", "exclude"], default="positive")
    a = ap.parse_args()
    rows = load_features(a.features)
    if a.split:
        rows, _ = stratified_split(rows, a.split, a.seed)
        print(f"[튜닝 세트] 전체의 {a.split:.0%} 사용 (seed={a.seed}) — 나머지는 evaluate.py 검증용\n")
    else:
        print("[주의] 전체 데이터로 튜닝합니다. 같은 데이터로 검증하면 성능이 과대평가됩니다 (--split 권장)\n")
    print(f"데이터 {len(rows)}건 (악성 {sum(r['label'] for r in rows)}, 정상 {sum(1 - r['label'] for r in rows)})\n")

    rules, skipped = rule_sweep(rows)
    print(f"[A] 등록기간 x 다운로드 조합 상위 10 (결측/미존재 {skipped}건 제외)")
    show(rules[:10], ["rule", "tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr"])

    ts = threshold_sweep(rows, Config(), a.exists_policy)
    print(f"\n[B] 종합 점수 Threshold 스윕 (미존재 처리={a.exists_policy})")
    show(ts, ["threshold", "tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr"])

    w, f = suggest(ts, a.min_precision)
    if w is None:
        print("\n[추천 불가] 모든 Threshold에서 F1이 미정의(분모 0)입니다. 라벨 데이터가 더 필요합니다.")
    elif f is None:
        print(f"\n[추천] warn_threshold={w} (F1 최대)")
        print(f"[미달성] Precision>={a.min_precision} 를 만족하는 WARN보다 높은 Threshold가 없습니다.")
        print("  → 운영상 fail_threshold를 임시로 둘 수는 있으나, 이를 '검증된 95% Precision 기준'이라고")
        print("    표현하지 마십시오(§7.3 (5)). WARN이 이미 최대 Threshold라면 더 높일 여지 자체가 없습니다.")
    else:
        print(f"\n[추천] warn_threshold={w} (F1 최대), fail_threshold={f} (warn 초과 & Precision>={a.min_precision} 최소 지점)")
    print("→ src/veripi/config.py 에 반영 후 evaluate.py (같은 --split/--seed) 로 검증")

    if a.out:
        with open(a.out, "w", newline="", encoding="utf-8") as fh:
            wr = csv.DictWriter(fh, fieldnames=list(ts[0].keys()))
            wr.writeheader()
            wr.writerows(ts)
        print(f"저장: {a.out}")


if __name__ == "__main__":
    main()
