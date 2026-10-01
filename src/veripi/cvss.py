"""CVSS v3.1 기본(Base) 점수 계산 — FIRST.org 공식 명세를 직접 구현.
출처: https://www.first.org/cvss/v3-1/specification-document (Section 7.4 Base scoring)
CVSS v3.0 벡터도 동일 공식으로 근사 계산한다(3.1과 기본식이 사실상 동일. 큰 차이는
Scope 변경 시 PR 가중치뿐이며, 이는 해당 경우에만 근소한 오차를 만들 수 있음).
CVSS v2, v4는 미지원(값이 다르거나 매크로벡터 방식이라 별도 구현 필요) — 이 경우
severity_label()은 None을 반환하고 호출부가 "심각도 미확인"으로 처리한다.
"""
import re
from math import ceil
from typing import Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope: Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope: Changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

# 공식 등급 경계 (FIRST.org CVSS v3.1 Qualitative Severity Rating Scale)
RATING_BOUNDS = [(0.0, "NONE"), (3.9, "LOW"), (6.9, "MEDIUM"), (8.9, "HIGH"), (10.0, "CRITICAL")]


def _roundup(value: float) -> float:
    """CVSS 공식 반올림(소수 첫째자리 올림) — 부동소수 오차 방지용 정수 연산."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10.0


def base_score(vector: str) -> Optional[float]:
    """CVSS:3.0/3.1 벡터 문자열 -> Base Score(0.0~10.0). 파싱 실패/미지원 버전이면 None."""
    if not vector or not re.match(r"^CVSS:3\.[01]/", vector):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        metrics[k] = v
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope_changed = metrics.get("S") == "C"
        pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if scope_changed else (impact + exploitability)
    return _roundup(min(total, 10.0))


def rating(score: Optional[float]) -> Optional[str]:
    """CVSS 점수 -> 공식 등급 문자열(NONE/LOW/MEDIUM/HIGH/CRITICAL). score가 None이면 None."""
    if score is None:
        return None
    for upper, label in RATING_BOUNDS:
        if score <= upper:
            return label
    return "CRITICAL"


def severity_label(vuln: dict) -> Optional[str]:
    """OSV API의 취약점(vuln) 객체 하나에서 심각도 등급을 뽑는다.
    우선순위: 1) top-level severity 배열의 CVSS_V3 벡터를 직접 계산
             2) database_specific.severity 문자열(GHSA 관례: LOW/MODERATE/HIGH/CRITICAL)
    둘 다 없으면 None (호출부가 '심각도 미확인'으로 처리).
    """
    for sev in vuln.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            s = base_score(sev.get("score", ""))
            r = rating(s)
            if r:
                return r
    ds = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ds, str):
        u = ds.upper()
        return "MEDIUM" if u == "MODERATE" else u if u in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"} else None
    return None


# 공식 등급 순위 — worst_of()에서 사용. UNKNOWN_SEVERITY/QUERY_FAILED는 등급이 아니라
# 별도의 정보-상태(osv.unknown_severity_present, checker.py의 query_status)로 다루므로
# 이 순위에는 포함하지 않는다(docs/detection_criteria.md §3.5 (c)).
_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def worst_of(labels) -> Optional[str]:
    """등급 목록(NONE/LOW/MEDIUM/HIGH/CRITICAL) 중 가장 심각한 것. 빈 목록이면 None."""
    labels = [l for l in labels if l in _ORDER]
    if not labels:
        return None
    return max(labels, key=_ORDER.index)
