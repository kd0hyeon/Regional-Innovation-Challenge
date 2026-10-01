import argparse
import json
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from .checker import LABELS, check_package
from .config import Config
from .similarity import load_popular
from .extract import extract_packages

EXIT = {"PASS": 0, "WARN": 1, "FAIL": 2, "NOT_FOUND": 3, "UNKNOWN": 4, "INVALID": 5}
ICON = {"PASS": "✅", "WARN": "⚠️ ", "FAIL": "⛔", "NOT_FOUND": "❓", "UNKNOWN": "❔", "INVALID": "🚫"}


def _print(rep):
    print(f"{ICON[rep.verdict]} {rep.name}{'==' + rep.version if rep.version else ''} -> {rep.label}")
    if rep.scores:
        s = rep.scores
        print(f"   슬롭스쿼팅 위험점수 {rep.total_score}  (등록기간 {s['age']} / 다운로드 {s['downloads']} / 이름유사 {s.get('similarity', 0)})")
    if rep.security:
        sec = rep.security
        sev = sec.get("max_known_severity") or ("미확인" if sec.get("unknown_severity_present") else "없음")
        print(f"   알려진 취약점(별도 축): 최고 등급 {sev} / 조회상태 {sec.get('query_status')} / 건수 {sec.get('vulnerability_count')}")
    for sig in rep.signals:
        print(f"   - {sig}")


def _summary(reps):
    c = Counter(r.verdict for r in reps)
    return {k: c.get(k, 0) for k in LABELS}


def _print_summary(reps):
    c = _summary(reps)
    print(f"\n총 {len(reps)}개: 통과 {c['PASS']} / 경고 {c['WARN']} / 부적합 {c['FAIL']} / "
          f"미존재 {c['NOT_FOUND']} / 판정불가 {c['UNKNOWN']} / 잘못된입력 {c['INVALID']}")


def _run(specs, use_installed, check_deps, cfg=None, workers=4):
    def one(s):
        return check_package(s, cfg=cfg, use_installed=use_installed, check_deps=check_deps)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(one, specs))


def _read(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _is_requirements(path):
    b = os.path.basename(path).lower()
    return bool(re.search(r"(requirements|constraints).*\.(txt|in)$", b))


def main(argv=None):
    p = argparse.ArgumentParser(prog="veripi", description="설치 전 패키지 위험도 검사 (슬롭스쿼팅 탐지)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--json", action="store_true", help="JSON 출력")
        sp.add_argument("--installed", action="store_true", help="pipdeptree로 설치된 환경의 의존성 사용")
        sp.add_argument("--no-deps", action="store_true", help="의존성 검사 생략")
        sp.add_argument("--popular-file", help="이름 유사도 비교용 인기 패키지 목록 파일 (공백/줄바꿈 구분, # 주석)")

    c = sub.add_parser("check", help="패키지 검사 (예: requests, flask==3.0.0)")
    c.add_argument("packages", nargs="+")
    common(c)

    s = sub.add_parser("scan", help="파일/텍스트에서 패키지를 추출해 일괄 검사 (requirements.txt, AI 답변, Dockerfile, '-'=stdin)")
    s.add_argument("file")
    s.add_argument("--format", choices=["auto", "requirements", "text"], default="auto")
    s.add_argument("--max", type=int, default=50, help="최대 검사 개수 (기본 50)")
    common(s)

    a = p.parse_args(argv)
    skipped = []
    if a.cmd == "check":
        specs = a.packages
    else:
        text = _read(a.file)
        as_req = a.format == "requirements" or (a.format == "auto" and a.file != "-" and _is_requirements(a.file))
        specs, skipped = extract_packages(text, as_requirements=as_req)
        if len(specs) > a.max:
            skipped += [{"token": x, "reason": f"--max {a.max} 초과"} for x in specs[a.max:]]
            specs = specs[:a.max]
        if not specs:
            print("검사할 패키지를 찾지 못했습니다. (텍스트 모드는 'pip install ...' 명령만 인식합니다)", file=sys.stderr)

    cfg = Config(popular=tuple(load_popular(a.popular_file))) if a.popular_file else None
    reps = _run(specs, a.installed, not a.no_deps, cfg)
    if a.json:
        print(json.dumps({"summary": _summary(reps), "results": [r.to_dict() for r in reps],
                          "skipped": skipped}, ensure_ascii=False, indent=2))
    else:
        for r in reps:
            _print(r)
        if a.cmd == "scan":
            _print_summary(reps)
            for sk in skipped:
                print(f"   (건너뜀) {sk['token']} — {sk['reason']}")
    return max((EXIT[r.verdict] for r in reps), default=0)


if __name__ == "__main__":
    sys.exit(main())
