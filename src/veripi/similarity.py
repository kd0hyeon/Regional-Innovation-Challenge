"""인기 패키지와의 이름 유사도 (typosquatting 후보 탐지).

편집거리: Damerau-Levenshtein(삽입/삭제/치환/인접 전치) — 'reqeusts' -> 'requests' = 1.
구분자(-, _, .) 는 제거하고 비교하므로 'req-uests' 같은 변형도 거리 0 으로 잡힌다.
(인기 패키지와 정규화 이름이 완전히 같으면 그 패키지 자신이므로 대상에서 제외)
"""
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Iterable, Optional

from .pypi import normalize
from .popular import POPULAR


def _strip(n: str) -> str:
    return re.sub(r"[-_.]", "", n)


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment)."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


@dataclass
class Nearest:
    name: str        # 가장 가까운 인기 패키지
    distance: int
    min_len: int     # 비교한 두 이름 중 짧은 쪽 길이 (짧은 이름은 오탐이 많아 점수화에서 제외)
    ratio: float     # difflib 유사도(참고용)


def load_popular(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        return sorted({normalize(t) for line in f for t in line.split("#")[0].split()})


def nearest_popular(name: str, popular: Optional[Iterable[str]] = None, max_distance: int = 2) -> Optional[Nearest]:
    pop = [normalize(p) for p in (popular if popular is not None else POPULAR)]
    n = normalize(name)
    if n in set(pop):
        return None                       # 인기 패키지 자신
    s = _strip(n)
    best = None
    for p in pop:
        ps = _strip(p)
        if abs(len(ps) - len(s)) > max_distance:
            continue
        d = edit_distance(s, ps)
        if d > max_distance:
            continue
        ratio = SequenceMatcher(None, n, p).ratio()
        key = (d, -ratio)
        if best is None or key < best[0]:
            best = (key, p, d, len(ps), ratio)
    if best is None:
        return None
    _, p, d, plen, ratio = best
    return Nearest(name=p, distance=d, min_len=min(len(s), plen), ratio=round(ratio, 3))
