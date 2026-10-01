from datetime import datetime, timezone
from typing import Optional

from .config import Config


def age_days(first_release: Optional[datetime], now: Optional[datetime] = None) -> Optional[float]:
    if first_release is None:
        return None
    now = now or datetime.now(timezone.utc)
    return (now - first_release).total_seconds() / 86400


def score_age(days: Optional[float], cfg: Config) -> int:
    if days is None:
        return cfg.age_unknown
    for limit, pts in cfg.age_bands:
        if days <= limit:
            return pts
    return cfg.age_default


def score_downloads(weekly: Optional[int], cfg: Config) -> int:
    if weekly is None:
        return cfg.download_unknown
    for limit, pts in cfg.download_bands:
        if weekly <= limit:
            return pts
    return cfg.download_default


def score_similarity(distance: Optional[int], min_len: int, cfg: Config) -> int:
    """인기 패키지와의 편집거리 기반 점수. distance=None 이면 근접한 인기 패키지 없음.
    v0.7 수정본: 다운로드 수에 따른 면제 규칙은 점수표와 충돌하여 적용하지 않는다
    (docs/detection_criteria.md §3.4)."""
    if distance is None or min_len < cfg.sim_min_len:
        return 0
    if distance <= 1:
        return cfg.sim_dist1_pts
    if distance == 2 and min_len >= cfg.sim_dist2_min_len:
        return cfg.sim_dist2_pts
    return 0


def verdict(total: int, cfg: Config) -> str:
    if total >= cfg.fail_threshold:
        return "FAIL"
    if total >= cfg.warn_threshold:
        return "WARN"
    return "PASS"


def total_from_features(age_d, weekly, cfg: Config, sim_distance=None, sim_min_len=0) -> int:
    """수집된 지표(features)만으로 슬롭스쿼팅 총점을 재계산 (네트워크 불필요).
    v0.7부터 OSV/CVSS 취약점은 이 총점에 포함되지 않는다(별도 보안 축으로 분리,
    docs/detection_criteria.md §3.5·§3.6 참고). MAL-* 는 이 함수 밖(checker.py)에서
    총점과 무관하게 FAIL로 즉시 override된다."""
    return (score_age(age_d, cfg) + score_downloads(weekly, cfg)
            + score_similarity(sim_distance, sim_min_len or 0, cfg))
