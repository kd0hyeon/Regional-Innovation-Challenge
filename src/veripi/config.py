"""임시 고정 기준값. 0단계 실험(experiments/)으로 검증 후 수정할 것."""
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class Config:
    # (일 이하 상한, 점수) — 등록 후 경과 기간
    # 근거: pnpm 11 기본 최소 릴리즈 나이 24시간, npm min-release-age 통상 1~7일,
    # OpenSSF(2026) "대부분의 악성 패키지는 OSV에 3일 내 분류됨" + 7일 쿨다운 권장,
    # Harness Dependency Firewall 공식 정책 템플릿(3일 감사/7일 보통/30일 고보안),
    # safeinstall·VibeScan(둘 다 공개 소스인 패키지 위험도 채점 도구)이 7/30/90일 구간 사용.
    # (출처는 docs/detection_criteria.md §3.2 참고)
    age_bands: tuple = ((7, 5), (30, 4), (90, 2))
    age_default: int = 0          # 91일 이상
    age_unknown: int = 5          # 릴리즈 이력 없음 -> 의심

    # (주간 다운로드 상한, 점수) — PyPI 실측 분포 + 실제 악성 패키지 적발 사례 기반
    # 근거: Taylor et al. "SpellBound" (arXiv:2003.03471) — npm 자체 추정상 봇/미러가
    #   패키지당 하루 최대 50회(주 350회)까지 다운로드를 발생시킬 수 있어 그 미만은
    #   실사용자 채택의 증거가 사실상 없음(노이즈 하한). PyPI 패키지의 93.3%가 주 350회
    #   미만이며, 같은 논문이 npm·PyPI 전체 분포를 분석해 "확실히 인기 있음" 기준으로
    #   주 15,000회를 채택(해당 구간 도달 패키지는 전체의 약 3%).
    # 실제 적발 사례(참고, docs 참조): pymafka 325회, aws-login0tool 3,042회,
    #   dpp-client 10,000회+, acloud-client 5,496회 등 — 다수가 350~15,000 구간에서
    #   적발되었고 일부는 그 이상에서도 발견되어, 다운로드 수 단독은 판별력이
    #   제한적임을 시사(그래서 OSV MAL 즉시 차단 규칙으로 보완).
    download_bands: tuple = ((349, 5), (14_999, 3))
    download_default: int = 1     # 15,000회 이상
    download_unknown: int = 3     # 조회 실패 시 중립값

    # 이름 유사도 (typosquatting) — 인기 패키지와의 편집거리
    sim_dist1_pts: int = 3        # 편집거리 0~1 (구분자 변형/오탈자/전치)
    sim_dist2_pts: int = 2        # 편집거리 2 (긴 이름에만 적용)
    sim_min_len: int = 5          # 이 길이 미만의 짧은 이름은 오탐이 많아 제외
    sim_dist2_min_len: int = 8
    popular: Optional[Tuple[str, ...]] = None   # None=내장 목록, 지정 시 사용자 목록 사용
    # v0.7 수정본: 다운로드 수에 따라 이름 유사도를 면제하는 규칙은 점수표와 충돌하여
    # 삭제했습니다(docs/detection_criteria.md §3.4). sim_skip_downloads 필드도 제거.

    # v0.7: OSV/CVSS는 "알려진 보안 취약점" 축으로 완전히 분리되어 아래 총점에 더 이상
    # 합산되지 않는다(대신 Report.security 필드로 별도 제공). MAL-* 악성 리포트는
    # 여전히 총점과 무관하게 즉시 FAIL(이건 취약점 심각도가 아니라 "이미 악성으로
    # 확인됨"이라는 별개의 확정적 증거이기 때문).
    #
    # 최종 판정 (총점 = 등록기간 0~5 + 다운로드 1~5 + 이름유사 0~3, 최대 13)
    # v0.6까지의 6/10(당시 최대 18점 기준, OSV 포함)을 새 최대치(13)에 비례 환산한
    # 임시값이며, 여전히 실제 라벨 데이터셋 기반 검증(experiments/tune.py)이 필요한
    # 플레이스홀더다.
    warn_threshold: int = 4       # >= 경고  (6 * 13/18 ≈ 4.3 -> 4)
    fail_threshold: int = 7       # >= 부적합 (10 * 13/18 ≈ 7.2 -> 7)

    max_deps: int = 30
    timeout: float = 10.0
