"""[3] 주간 다운로드 수 (pypistats.org).

404(통계 없음)와 그 외 조회 실패(네트워크/서버 오류)를 구분한다. pypistats는 알려진
PyPI 미러를 집계에서 기본 제외한다(https://pypistats.org/about).
"""
from .http import NotFound, get_json
from .pypi import normalize


class StatsNotFound(Exception):
    """pypistats에 해당 패키지 통계 자체가 없음(404). 실제 다운로드 0회와는 다른 상태."""


def weekly_downloads(name: str, timeout: float = 10.0):
    """성공 시 int. 통계 없음(404)이면 StatsNotFound 예외. 그 외 실패 시 None."""
    try:
        data = get_json(f"https://pypistats.org/api/packages/{normalize(name)}/recent", timeout)
        return int(data["data"]["last_week"])
    except NotFound:
        raise StatsNotFound(name)
    except Exception:
        return None
