"""[2단계] 완성된 알고리즘(현재 Config) 성능 검증: 통과/경고/부적합 vs 실제 정답.

    python experiments/evaluate.py data/features.csv --split 0.7 --seed 42
--split R          : tune.py 와 같은 값/seed 를 주면 '검증 세트(1-R)'로만 평가 (튜닝 데이터와 분리)
--positive warn|fail : 경고+부적합(+미존재+MAL) / 부적합(+미존재+MAL)만 을 '위험 판정'으로 볼지.
                     MAL은 이미 FAIL 판정에 포함되므로 별도로 중복 집계하지 않는다(§7.1).
--exists-policy    : both(기본)=두 관점 모두 출력
                     positive = 미존재 패키지를 위험(환각)으로 판정하는 전체 성능
                     exclude  = 미존재(삭제된 악성 포함) 제외, '존재하는 패키지'에서 지표 기반 성능만
--prevalence P1,P2,...: 실제 환경의 악성 비율 가정들(쉼표 구분). 기본 0.0001,0.001,0.01 로
                     민감도 분석을 함께 보여준다(§7.4). 단일 실측값이 아님에 유의.
--exclude-unknown-category : label=1 중 category='unknown'(출처 불명)인 항목을 평가에서 제외.
"""
import argparse
from collections import Counter

from veripi.config import Config
from veripi.scoring import total_from_features, verdict

from common import (confusion, excluding_unknown_category, fmt, fpr, load_features, prf,
                    precision_at_prevalence, stratified_split)


def predict(r, cfg):
    if not r["exists"]:
        return "NOT_FOUND"
    if r["malware"]:
        return "FAIL"           # OSV MAL 리포트는 점수 무관 즉시 부적합
    t = total_from_features(r["age_days"], r["weekly_downloads"], cfg,
                            r["sim_distance"], r["sim_min_len"])
    return verdict(t, cfg)


def block(title, rows, cfg, positive_kind, prevalences):
    if not rows:
        print(f"── {title}  (평가 대상 0건, 건너뜀)\n")
        return
    labels = [r["label"] for r in rows]
    preds = [predict(r, cfg) for r in rows]
    # MAL은 FAIL 판정 안에 이미 포함되어 있으므로 집합에 별도로 추가하지 않는다(중복 집계 방지, §7.1)
    pos = {"FAIL", "NOT_FOUND"} | ({"WARN"} if positive_kind == "warn" else set())
    # UNKNOWN/INVALID는 정상/위험 어느 쪽으로도 집계하지 않는다(§7.1) — 주 혼동행렬에서 제외
    idx_decidable = [i for i, p in enumerate(preds) if p not in ("UNKNOWN", "INVALID")]
    excluded = len(rows) - len(idx_decidable)
    y = [labels[i] for i in idx_decidable]
    yp = [int(preds[i] in pos) for i in idx_decidable]
    m = confusion(y, yp)
    p, rc, f1 = prf(*m)
    f = fpr(*m)
    print(f"── {title}  (n={len(rows)}, 악성 {sum(labels)} / 정상 {len(labels) - sum(labels)}, "
          f"판정불가 제외 {excluded}건, 판정가능비율 {1 - excluded / len(rows):.1%})")
    print("   판정 분포:", dict(Counter(preds)))
    print(f"   TP={m[0]} FP={m[1]} FN={m[2]} TN={m[3]}")
    print(f"   Precision={fmt(p)}  Recall={fmt(rc)}  F1={fmt(f1)}  FPR(오탐률)={fmt(f)}")
    if f is not None:
        print(f"   → 정상 패키지 10,000개당 오탐 약 {f * 10000:.0f}개")
    for prev in prevalences:
        ep = precision_at_prevalence(rc, f, prev)
        print(f"   → 악성 비율 {prev:.4%} 가정 시 기대 Precision ≈ {fmt(ep)}"
              f"  (표본 Precision {fmt(p)}은 표본의 악성 비율이 실제보다 높아 낙관적일 수 있음)")
    miss = [rows[i]["name"] for i in idx_decidable if labels[i] and preds[i] not in pos]
    fa = [rows[i]["name"] for i in idx_decidable if not labels[i] and preds[i] in pos]
    if miss:
        print("   놓친 위험(FN):", ", ".join(miss[:15]))
    if fa:
        print("   오탐 정상(FP):", ", ".join(fa[:15]))
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("features")
    ap.add_argument("--positive", choices=["warn", "fail"], default="warn")
    ap.add_argument("--split", type=float, default=None)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--exists-policy", choices=["both", "positive", "exclude"], default="both")
    ap.add_argument("--prevalence", default="0.0001,0.001,0.01",
                    help="쉼표로 구분한 민감도 분석용 악성 비율 가정들 (기본: 0.01%%,0.1%%,1%%)")
    ap.add_argument("--exclude-unknown-category", action="store_true",
                    help="category='unknown'(출처 불명) 라벨 행을 평가에서 제외")
    a = ap.parse_args()
    prevalences = [float(x) for x in a.prevalence.split(",")]
    cfg = Config()
    rows = load_features(a.features)
    if a.split:
        _, rows = stratified_split(rows, a.split, a.seed)
        print(f"[검증 세트] 튜닝에 쓰지 않은 {1 - a.split:.0%} (seed={a.seed})")
    else:
        print("[주의] 분할 없이 전체 데이터로 평가합니다. 튜닝에 쓴 데이터면 성능이 과대평가됩니다 (--split 권장)")
    if a.exclude_unknown_category:
        rows, n_excl = excluding_unknown_category(rows)
        print(f"[제외] 출처 불명(category=unknown) {n_excl}건을 평가에서 제외")
    print(f"설정: warn>={cfg.warn_threshold}, fail>={cfg.fail_threshold}, 위험판정={a.positive}+\n")

    if a.exists_policy in ("both", "positive"):
        block("① 전체 (PyPI 미존재 = 환각/삭제 → 위험 판정)", rows, cfg, a.positive, prevalences)
    if a.exists_policy in ("both", "exclude"):
        block("② 존재하는 패키지만 (지표 기반 성능, 삭제된 악성 패키지의 '손쉬운 탐지' 효과 배제)",
              [r for r in rows if r["exists"]], cfg, a.positive, prevalences)


if __name__ == "__main__":
    main()
