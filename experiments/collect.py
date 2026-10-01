"""데이터셋(name,label[,version,category,group,reported_at]) -> 지표 수집 -> features CSV
(1회 수집 후 오프라인 실험).

    python experiments/collect.py data/dataset.csv data/features.csv

label: 1=악성/위험, 0=정상.
category(선택): hallucinated_nonexistent / typosquatting / confirmed_malicious / benign.
  지정하지 않으면 "unknown"(출처 불명)으로 저장되며, evaluate.py --exclude-unknown-category로
  주 평가에서 뺄 수 있다(§7.1 — MAL/미존재만으로 슬롭스쿼팅 경로를 라벨링하지 않는다는 원칙).
group(선택): 같은 캠페인/같은 패키지의 여러 버전을 묶는 키. 지정하지 않으면 패키지명을 그룹으로 쓴다
  (tune.py/evaluate.py의 stratified_split이 그룹 단위로 분할해 데이터 누수를 막는다, §7.3 (2)).
reported_at(선택, YYYY-MM-DD): 악성 패키지가 적발/신고된 시점. 있으면 '현재'가 아니라 그 시점
  기준으로 등록 후 경과 기간을 계산한다. 다만 다운로드·OSV는 여전히 수집 시점(현재) 값이라
  완전한 과거 스냅샷 재현은 아님에 유의(§7.4).
존재하지 않는 패키지(환각)는 label=1, exists는 자동으로 0이 된다.
"""
import csv
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from veripi import deps as deps_mod
from veripi import osv, pypi, pypistats, similarity
from veripi.config import Config
from veripi.pypistats import StatsNotFound
from veripi.scoring import age_days

from common import FIELDS

CFG = Config()


def _weekly(name):
    """StatsNotFound(404)는 0회로, 그 외 실패는 None으로 (checker.py와 동일한 구분)."""
    try:
        return pypistats.weekly_downloads(name, CFG.timeout)
    except StatsNotFound:
        return 0


def collect(row):
    name, label, ver = row["name"], row["label"], (row.get("version") or None)
    category = row.get("category") or "unknown"
    group = row.get("group") or name
    info = pypi.fetch_package(name, ver, CFG.timeout)
    if info is None:
        return dict(name=name, label=label, category=category, group=group, exists=0,
                    age_days="", weekly_downloads="", pkg_vulns="", vuln_deps="",
                    malware=0, sim_distance="", sim_min_len="")
    now = None
    if row.get("reported_at"):
        now = datetime.fromisoformat(row["reported_at"]).replace(tzinfo=timezone.utc)
    ad = age_days(info.first_release, now)
    near = similarity.nearest_popular(info.name)
    dl = _weekly(info.name)

    pkg_result = osv.query_vulns(info.name, info.version, CFG.timeout)
    pkg_vulns = pkg_result["vulns"] if pkg_result else []
    mal, vul = osv.split_ids(pkg_vulns)

    dep_list = deps_mod.from_pypi(info.requires, CFG.max_deps, CFG.timeout)
    vd, dep_mal = 0, 0
    for n, v in dep_list:
        if v:
            r = osv.query_vulns(n, v, CFG.timeout)
            if r:
                m, x = osv.split_ids(r["vulns"])
                dep_mal += bool(m)
                vd += bool(x) and not m

    return dict(name=name, label=label, category=category, group=group, exists=1,
                age_days="" if ad is None else round(ad, 3),
                weekly_downloads="" if dl is None else dl,
                pkg_vulns="" if pkg_result is None else len(vul), vuln_deps=vd,
                malware=int(bool(mal) or dep_mal > 0),
                sim_distance="" if near is None else near.distance,
                sim_min_len="" if near is None else near.min_len)


def main(src, dst):
    with open(src, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    with ThreadPoolExecutor(max_workers=4) as ex:
        out = list(ex.map(collect, rows))
    with open(dst, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(out)
    unknown = sum(1 for o in out if o["category"] == "unknown")
    print(f"{len(out)}개 수집 완료 -> {dst} (category 미지정 {unknown}건은 'unknown'으로 저장됨)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
