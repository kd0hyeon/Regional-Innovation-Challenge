"""[1] 존재 여부 + [2] 최초 등록일 + 의존성 메타데이터."""
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from packaging.version import InvalidVersion, Version

from .http import NotFound, get_json

BASE = "https://pypi.org/pypi"


NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]*$")


def validate_name(name: str) -> str:
    """PEP 508 패키지명 형식만 허용 (URL/명령어 삽입 방지)."""
    if not isinstance(name, str) or len(name) > 100 or not NAME_RE.match(name):
        raise ValueError(f"올바르지 않은 패키지명: {str(name)[:40]!r}")
    return name


def validate_version(version: str) -> str:
    """허용 문자 검사(정규식) + PEP 440 유효성 검사. 정규식만으로는 유효한 버전인지
    완전히 판별할 수 없으므로(예: 'a..b'는 정규식은 통과하지만 PEP 440상 무효),
    packaging.version.Version 으로 추가 검증한다. 전체 PEP 508 문법을 지원한다는
    뜻은 아니며, '이름==버전' 형태의 단순 지정만 다룬다."""
    if len(version) > 64 or not VERSION_RE.match(version):
        raise ValueError(f"올바르지 않은 버전: {version[:40]!r}")
    try:
        Version(version)
    except InvalidVersion:
        raise ValueError(f"PEP 440 형식이 아닌 버전: {version[:40]!r}")
    return version


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class PackageInfo:
    name: str
    version: str
    first_release: Optional[datetime]
    requires: List[str] = field(default_factory=list)
    versions: List[str] = field(default_factory=list)


def _parse_time(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def first_release_time(releases: dict) -> Optional[datetime]:
    times = []
    for files in (releases or {}).values():
        for f in files:
            t = f.get("upload_time_iso_8601") or f.get("upload_time")
            if t:
                times.append(_parse_time(t))
    return min(times) if times else None


def fetch_package(name: str, version: Optional[str] = None, timeout: float = 10.0) -> Optional[PackageInfo]:
    """존재하지 않으면 None (환각 패키지 의심)."""
    n = normalize(validate_name(name))
    if version:
        validate_version(version)
    try:
        base = get_json(f"{BASE}/{n}/json", timeout)
    except NotFound:
        return None
    releases = base.get("releases", {})
    ver = version or base["info"]["version"]
    info = base["info"]
    if version:
        if version not in releases:
            return None
        try:
            info = get_json(f"{BASE}/{n}/{version}/json", timeout)["info"]
        except NotFound:
            return None
    return PackageInfo(
        name=base["info"].get("name", n),
        version=ver,
        first_release=first_release_time(releases),
        requires=info.get("requires_dist") or [],
        versions=list(releases.keys()),
    )
