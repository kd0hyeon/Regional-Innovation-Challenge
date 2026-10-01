from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from . import cvss
from . import deps as deps_mod
from . import osv, pypi, pypistats
from .config import Config
from .pypistats import StatsNotFound
from .scoring import age_days, score_age, score_downloads, score_similarity, verdict

LABELS = {
    "PASS": "통과",
    "WARN": "경고",
    "FAIL": "부적합",
    "NOT_FOUND": "존재하지 않음(환각 패키지 의심)",
    "UNKNOWN": "판정 불가(일부 조회 실패)",
    "INVALID": "잘못된 입력",
}


@dataclass
class Report:
    name: str
    version: Optional[str]
    verdict: str
    total_score: int = 0                       # 슬롭스쿼팅 신호만 합산 (등록기간+다운로드+이름유사, 최대 13)
    scores: Dict[str, int] = field(default_factory=dict)
    # security: max_known_severity(str|None) / unknown_severity_present(bool) /
    #           query_status("COMPLETE"|"PARTIAL"|"FAILED") / vulnerability_count(int|None)
    #           + 디버그용 부가 필드(package_vulns, vulnerable_dependencies, malicious_dependencies, package_malware)
    security: Dict[str, object] = field(default_factory=dict)
    signals: List[str] = field(default_factory=list)
    incomplete: List[str] = field(default_factory=list)   # 조회에 실패/누락된 항목
    details: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return LABELS[self.verdict]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["label"] = self.label
        return d


def parse_spec(spec: str):
    """'name' 또는 'name==version'. 형식이 잘못되면 ValueError."""
    if "==" in spec:
        n, v = spec.split("==", 1)
        return pypi.validate_name(n.strip()), pypi.validate_version(v.strip())
    return pypi.validate_name(spec.strip()), None


def check_package(spec: str, cfg: Optional[Config] = None, use_installed: bool = False,
                  check_deps: bool = True) -> Report:
    cfg = cfg or Config()
    try:
        name, req_version = parse_spec(spec)
    except ValueError as e:
        return Report(name=str(spec)[:60], version=None, verdict="INVALID", signals=[str(e)])
    try:
        return _check(name, req_version, cfg, use_installed, check_deps)
    except Exception as e:  # 검사 대상 PyPI 조회 자체가 실패 -> 점수 계산 중단, 즉시 UNKNOWN (§3.7)
        return Report(name=name, version=req_version, verdict="UNKNOWN",
                      signals=[f"PyPI 조회 실패: {type(e).__name__}"], incomplete=["PyPI"])


def _check(name, req_version, cfg, use_installed, check_deps) -> Report:
    # [1] 존재 여부 — 없으면 검사 중단
    info = pypi.fetch_package(name, req_version, cfg.timeout)
    if info is None:
        return Report(name=name, version=req_version, verdict="NOT_FOUND",
                      signals=["PyPI에 존재하지 않는 패키지/버전 (AI 환각 슬롭스쿼팅 가능성 — 단, 오타나 "
                              "삭제된 패키지일 수도 있어 환각 여부를 확정하지는 않음)"])

    rep = Report(name=info.name, version=info.version, verdict="PASS")
    incomplete: List[str] = []

    # [2] 최초 등록일 (슬롭스쿼팅 축)
    days = age_days(info.first_release)
    s_age = score_age(days, cfg)
    rep.scores["age"] = s_age
    rep.details["first_release"] = info.first_release.isoformat() if info.first_release else None
    rep.details["age_days"] = round(days, 2) if days is not None else None
    if days is None:
        incomplete.append("등록일 이력 없음")
        rep.signals.append(f"릴리즈 이력을 확인할 수 없음 (보수적 대체값 {cfg.age_unknown}점 적용)")
    elif s_age >= 4:
        rep.signals.append(f"최근 등록된 패키지 (등록 후 {days:.1f}일)")

    # [3] 주간 다운로드 (슬롭스쿼팅 축) — 통계 없음(404)과 조회 오류를 구분
    try:
        weekly = pypistats.weekly_downloads(info.name, cfg.timeout)
    except StatsNotFound:
        weekly = 0
        incomplete.append("다운로드 통계 없음(404)")
        rep.signals.append("pypistats에 다운로드 통계 없음(404) — 계산용 0회로 대체(실제 0회와는 다를 수 있음)")
    s_dl = score_downloads(weekly, cfg)
    rep.scores["downloads"] = s_dl
    rep.details["weekly_downloads"] = weekly
    if weekly is None:
        incomplete.append("다운로드 조회 오류")
        rep.signals.append(f"다운로드 수 조회 실패 (임시 대체점수 {cfg.download_unknown}점 적용)")
    elif s_dl >= 5 and weekly > 0:
        rep.signals.append(f"주간 다운로드 매우 낮음 ({weekly}회)")

    # [4] 인기 패키지와 이름 유사도 (슬롭스쿼팅 축)
    from . import similarity
    near = similarity.nearest_popular(info.name, cfg.popular)
    s_sim = score_similarity(near.distance if near else None, near.min_len if near else 0, cfg)
    rep.scores["similarity"] = s_sim
    rep.details["nearest_popular"] = (
        {"name": near.name, "distance": near.distance, "ratio": near.ratio} if near else None)
    if s_sim:
        rep.signals.append(f"인기 패키지 '{near.name}'와 이름이 유사 (편집거리 {near.distance}) — 타이포스쿼팅 의심")

    # 슬롭스쿼팅 총점 = 등록기간 + 다운로드 + 이름유사 (OSV/CVSS는 별도 축, 아래에서 처리)
    rep.total_score = s_age + s_dl + s_sim
    v = verdict(rep.total_score, cfg)

    # [5] OSV: 패키지 자체 + 직접 의존성 — "알려진 보안 취약점" 축 (총점에 합산하지 않음)
    pkg_result = osv.query_vulns(info.name, info.version, cfg.timeout)
    package_query_ok = pkg_result is not None
    pkg_truncated = bool(pkg_result and pkg_result["truncated"])
    pkg_vulns = pkg_result["vulns"] if pkg_result else []
    if not package_query_ok:
        incomplete.append("패키지 OSV 조회 실패")
        rep.signals.append("OSV 조회 실패 (패키지) — 알려진 악성(MAL) 리포트 여부를 확인하지 못함")
    if pkg_truncated:
        incomplete.append("OSV 결과의 다음 페이지 미조회(패키지)")
        rep.signals.append("OSV 응답에 다음 페이지가 더 있으나 조회하지 않음(패키지) — 일부 취약점이 누락됐을 수 있음")
    pkg_mal, pkg_vul_ids = osv.split_ids(pkg_vulns)
    pkg_severity = osv.worst_severity(pkg_vulns)
    pkg_unknown_sev = osv.unknown_severity_present(pkg_vulns)
    if pkg_vul_ids:
        sev_txt = pkg_severity or ("심각도 미확인" if pkg_unknown_sev else "알 수 없음")
        rep.signals.append(f"알려진 취약점 {len(pkg_vul_ids)}건 (OSV, 최고 확인 등급: {sev_txt})")

    # [5-2] OSV: 직접 의존성
    vuln_deps: List[str] = []
    mal_deps: List[str] = []
    dep_list: List = []
    dep_severities: List[str] = []
    dep_unknown_sev = False
    deps_any_failed = False
    deps_any_truncated = False
    dep_vuln_count = 0
    if check_deps:
        if use_installed:
            dep_list = deps_mod.from_pipdeptree(info.name)
            if dep_list is None:
                rep.signals.append("pipdeptree 사용 불가 -> PyPI 메타데이터로 대체")
        if not use_installed or dep_list is None:
            dep_list = deps_mod.from_pypi(info.requires, cfg.max_deps, cfg.timeout)
            if len(dep_list) >= cfg.max_deps:
                # 파싱된 의존성 수가 상한에 닿은 경우, 더 있었을 가능성을 배제할 수 없음
                incomplete.append(f"직접 의존성 {cfg.max_deps}개 제한 도달")
                deps_any_truncated = True

        def _q(item):
            n, v = item
            if v is None:
                return n, None            # 버전 해석 실패
            if v == "":
                return n, {"vulns": [], "truncated": False, "_unresolved": True}
            return n, osv.query_vulns(n, v, cfg.timeout)

        with ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(_q, dep_list))
        failed = [n for n, r in results if r is None]
        unresolved = [n for n, v in dep_list if v is None]
        missing = [n for n, v in dep_list if v == ""]
        if failed:
            deps_any_failed = True
            incomplete.append(f"의존성 OSV 조회 실패({len(failed)}개)")
            rep.signals.append(f"의존성 OSV 조회 실패: {', '.join(failed)}")
        if unresolved:
            deps_any_failed = True
            incomplete.append(f"의존성 버전 해석 실패({len(unresolved)}개)")
        if missing:
            deps_any_failed = True
            incomplete.append(f"PyPI에 없는 의존성({len(missing)}개)")
            rep.signals.append(f"PyPI에 없는 의존성(버전 해석 불가): {', '.join(missing)}")
        for n, r in results:
            if r is None:
                continue
            vulns = r["vulns"]
            if r.get("truncated"):
                deps_any_truncated = True
            m, vul_ids = osv.split_ids(vulns)
            if m:
                mal_deps.append(n)
            if vul_ids:
                vuln_deps.append(n)
                dep_vuln_count += len(vul_ids)
                sev = osv.worst_severity(vulns)
                if sev:
                    dep_severities.append(sev)
            if osv.unknown_severity_present(vulns):
                dep_unknown_sev = True
        if vuln_deps:
            rep.signals.append(f"취약점이 있는 직접 의존성: {', '.join(vuln_deps)}")
    rep.details["dependencies"] = [f"{n}=={v}" if v else n for n, v in dep_list]

    if deps_any_truncated or pkg_truncated:
        rep.signals.append("안내: 이 구현은 OSV 응답의 다음 페이지나 30개 초과 의존성을 따라가지 않습니다.")

    # --- security 축 종합 ---
    any_failure = (not package_query_ok) or deps_any_failed
    any_partial_info = any_failure or deps_any_truncated or pkg_truncated
    if not package_query_ok:
        # 패키지 자체의 OSV 조회가 실패하면 보안 결론 전체를 신뢰할 수 없음(§3.5 (c))
        query_status = "FAILED"
        max_known_severity = None
        unknown_severity_present = False
        vulnerability_count = None
    else:
        query_status = "PARTIAL" if any_partial_info else "COMPLETE"
        max_known_severity = cvss.worst_of([pkg_severity] + dep_severities) if (pkg_severity or dep_severities) else None
        unknown_severity_present = pkg_unknown_sev or dep_unknown_sev
        vulnerability_count = len(pkg_vul_ids) + dep_vuln_count

    rep.security = {
        "max_known_severity": max_known_severity,
        "unknown_severity_present": unknown_severity_present,
        "query_status": query_status,
        "vulnerability_count": vulnerability_count,
        # 디버그/상세 정보 (명세 필수 4개 필드 외 부가 제공)
        "package_vulns": pkg_vul_ids,
        "vulnerable_dependencies": vuln_deps,
        "malicious_dependencies": mal_deps,
        "package_malware": pkg_mal,
    }

    # 적용되는 MAL 리포트는 슬롭스쿼팅 총점·다른 조회의 성공 여부와 무관하게 즉시 부적합
    if pkg_mal or mal_deps:
        v = "FAIL"
        if mal_deps:
            rep.signals.insert(0, f"⛔ 악성 패키지로 보고된 의존성 (OSV MAL): {', '.join(mal_deps)}")
        if pkg_mal:
            rep.signals.insert(0, f"⛔ OSV에 악성 패키지로 등록됨: {', '.join(pkg_mal[:3])}")
    elif incomplete and v == "PASS":
        # 슬롭스쿼팅 신호가 통과 수준이어도, 필수 조회가 불완전하면(등록일/다운로드/
        # PyPI/OSV/의존성 중 하나라도) 통과 대신 판정 불가로 처리한다(fail-closed, §3.7).
        v = "UNKNOWN"
    rep.verdict = v
    rep.incomplete = incomplete
    return rep
