"""직접 의존성 수집.

- 기본(설치 전): PyPI requires_dist -> 각 의존성의 (조건을 만족하는 최신) 버전 해석
- --installed: pipdeptree 로 설치된 환경의 정확한 버전 사용
"""
import json
import subprocess
import sys
from typing import List, Optional, Tuple

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from . import pypi


def _pick_version(versions: List[str], spec, fallback: str) -> str:
    best = None
    for v in versions:
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if pv.is_prerelease or pv.is_devrelease:
            continue
        if spec.contains(pv, prereleases=False) and (best is None or pv > best):
            best = pv
    return str(best) if best else fallback


def from_pypi(requires: List[str], max_deps: int, timeout: float) -> List[Tuple[str, Optional[str]]]:
    out, seen = [], set()
    for line in requires:
        try:
            req = Requirement(line)
            if req.marker is not None and not req.marker.evaluate({"extra": ""}):
                continue
        except (InvalidRequirement, Exception):
            continue
        n = pypi.normalize(req.name)
        if n in seen:
            continue
        seen.add(n)
        try:
            info = pypi.fetch_package(n, timeout=timeout)
        except Exception:
            out.append((n, None))  # 조회 실패 -> None
            continue
        if info is None:
            out.append((n, ""))  # PyPI에 없는 의존성 -> 빈 문자열
        else:
            out.append((n, _pick_version(info.versions, req.specifier, info.version)))
        if len(out) >= max_deps:
            break
    return out


def from_pipdeptree(name: str) -> Optional[List[Tuple[str, str]]]:
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pipdeptree", "-p", name, "--json"],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return None
        target = pypi.normalize(name)
        for entry in json.loads(r.stdout):
            if pypi.normalize(entry["package"]["key"]) == target:
                return [
                    (pypi.normalize(d["package_name"]), d["installed_version"])
                    for d in entry.get("dependencies", [])
                ]
    except Exception:
        return None
    return None
