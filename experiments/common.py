import csv
import random
from typing import Dict, List, Optional

FIELDS = ["name", "label", "category", "exists", "age_days", "weekly_downloads", "pkg_vulns", "vuln_deps",
          "malware", "sim_distance", "sim_min_len", "group"]

# label=1 의 세부 유형. "MAL/미존재만으로 슬롭스쿼팅 공격 경로를 정답 라벨로 부여하지 않는다"는
# 원칙에 따라, 평가 시 출처가 불명확한 항목은 이 값으로 걸러낼 수 있다.
CATEGORIES = ["hallucinated_nonexistent", "typosquatting", "confirmed_malicious", "benign", "unknown"]


def _num(s, cast=float) -> Optional[float]:
    return None if s in ("", None) else cast(s)


def load_features(path: str) -> List[Dict]:
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append({
                "name": r["name"],
                "label": int(r["label"]),                  # 1=악성/위험, 0=정상
                "exists": int(r["exists"]),
                "age_days": _num(r["age_days"]),
                "weekly_downloads": _num(r["weekly_downloads"], int),
                "pkg_vulns": _num(r["pkg_vulns"], int) or 0,
                "vuln_deps": _num(r["vuln_deps"], int) or 0,
                "malware": _num(r.get("malware", ""), int) or 0,
                "sim_distance": _num(r.get("sim_distance", ""), int),   # None=근접한 인기 패키지 없음
                "sim_min_len": _num(r.get("sim_min_len", ""), int) or 0,
                "category": r.get("category") or "unknown",
                "group": r.get("group") or r["name"],   # 그룹 미지정 시 패키지명 자체를 그룹으로 사용
            })
    return rows


def excluding_unknown_category(rows):
    """category='unknown'(출처 불명)인 항목을 주 평가에서 제외. (제외된 행, 제외 개수)를 반환."""
    kept = [r for r in rows if r["category"] != "unknown"]
    return kept, len(rows) - len(kept)


def stratified_split(rows, train_ratio=0.7, seed=42):
    """라벨 비율을 유지하며 (튜닝용 train, 검증용 val) 로 분할."""
    rnd = random.Random(seed)
    train, val = [], []
    for lab in (0, 1):
        grp = [r for r in rows if r["label"] == lab]
        rnd.shuffle(grp)
        k = int(round(len(grp) * train_ratio))
        train += grp[:k]
        val += grp[k:]
    return train, val


def confusion(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    return tp, fp, fn, tn


def fmt(x, nd=3):
    """None(미정의)을 보고서에 표시할 때 쓰는 포맷터."""
    return "미정의" if x is None else f"{x:.{nd}f}"


def prf(tp, fp, fn, tn):
    """분모가 0이면 0으로 임의 처리하지 않고 None(미정의)을 반환한다(§7.2)."""
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if (p is not None and r is not None and p + r) else None
    return p, r, f1


def fpr(tp, fp, fn, tn):
    """오탐률: 정상 패키지 중 위험으로 잘못 판정된 비율. 분모 0이면 None(미정의)."""
    return fp / (fp + tn) if fp + tn else None


def precision_at_prevalence(recall, false_positive_rate, prevalence):
    """실제 환경(악성 비율=prevalence)에서 기대되는 Precision (베이즈 보정).
    Recall/FPR이 None(미정의)이면 계산할 수 없으므로 None을 반환한다."""
    if recall is None or false_positive_rate is None:
        return None
    tp = recall * prevalence
    fp = false_positive_rate * (1 - prevalence)
    return tp / (tp + fp) if tp + fp else None
