"""[5] OSV 취약점 조회 — 심각도(CVSS 기반)와 조회 상태(페이지네이션 포함)를 함께 반환."""
from typing import List, Optional, TypedDict

from . import cvss
from .http import get_json, post_json
from .pypi import normalize

URL = "https://api.osv.dev/v1/query"


class OsvResult(TypedDict):
    vulns: List[dict]      # 각 {id, malware(bool), severity(str|None)}
    truncated: bool        # True면 OSV 응답에 next_page_token이 있었는데 다음 페이지를 조회하지 않았음


def query_vulns(name: str, version: str, timeout: float = 10.0) -> Optional[OsvResult]:
    """조회 실패 시 None. 성공 시 OsvResult."""
    try:
        data = post_json(
            URL,
            {"package": {"name": normalize(name), "ecosystem": "PyPI"}, "version": version},
            timeout,
        )
        vulns = []
        for v in data.get("vulns", []):
            vid = v["id"]
            vulns.append({
                "id": vid,
                "malware": vid.startswith("MAL-"),
                "severity": None if vid.startswith("MAL-") else cvss.severity_label(v),
            })
        # OSV API는 결과가 많으면 next_page_token을 반환한다(OSV API 문서, §11 [21]).
        # 이 구현은 페이지네이션을 따라가지 않으므로, 토큰이 있으면 "일부만 조회함"을
        # 명시적으로 알린다 (query_status=PARTIAL 로 이어짐, checker.py 참고).
        return {"vulns": vulns, "truncated": bool(data.get("next_page_token"))}
    except Exception:
        return None


def split_ids(vulns: List[dict]):
    """(악성 리포트 id 목록, 일반 취약점 id 목록) — 기존 호출부·테스트 호환용."""
    mal = [v["id"] for v in vulns if v["malware"]]
    vul = [v["id"] for v in vulns if not v["malware"]]
    return mal, vul


def worst_severity(vulns: List[dict]) -> Optional[str]:
    """일반 취약점(악성 리포트 제외) 중 확인된 등급의 최대값. 등급이 전혀 없으면(취약점이
    없거나, 있어도 전부 미확인이면) None. '미확인 취약점 존재 여부'는 호출부가
    unknown_severity_present() 로 별도 확인한다(등급 순위에는 섞지 않음, §3.5 (c))."""
    labels = [v["severity"] for v in vulns if not v["malware"] and v["severity"]]
    return cvss.worst_of(labels)


def unknown_severity_present(vulns: List[dict]) -> bool:
    """일반 취약점 중 심각도를 확인하지 못한 항목이 하나라도 있으면 True."""
    return any(not v["malware"] and v["severity"] is None for v in vulns)
