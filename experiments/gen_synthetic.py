"""스크립트 동작 확인용 '합성' 데이터 생성 (실제 데이터 아님 — 성능 수치를 논문/발표에 쓰지 말 것)."""
import csv
import random
import sys

from common import FIELDS

random.seed(7)


def row(**kw):
    base = dict(name="", label=0, category="unknown", exists=1, age_days="", weekly_downloads="",
                pkg_vulns=0, vuln_deps=0, malware=0, sim_distance="", sim_min_len="", group="")
    base.update(kw)
    if not base["group"]:
        base["group"] = base["name"]
    return base


rows = []
for i in range(120):   # 정상: 오래되고 다운로드 많음 (SpellBound 기준 15,000/주 이상이 "확실히 인기")
    rows.append(row(name=f"normal-{i}", label=0, category="benign", age_days=round(random.uniform(90, 3000), 2),
                    weekly_downloads=int(10 ** random.uniform(4.3, 7)),
                    pkg_vulns=random.choice([0, 0, 0, 1]), vuln_deps=random.choice([0, 0, 1]),
                    sim_distance=random.choice(["", "", "", "", 1]) , sim_min_len=6))
for i in range(50):   # 악성: 신규 + 저다운로드(<350/주, SpellBound 노이즈 하한) (일부는 노이즈)
    noisy = random.random() < 0.2
    rows.append(row(name=f"mal-{i}", label=1, category="confirmed_malicious",
                    age_days=round(random.uniform(0.1, 400 if noisy else 20), 2),
                    weekly_downloads=int(10 ** random.uniform(0, 4.5 if noisy else 2.5)),
                    malware=1 if random.random() < 0.1 else 0))
for i in range(30):   # 타이포스쿼팅: 인기 패키지 이름을 모방
    rows.append(row(name=f"typosquat-{i}", label=1, category="typosquatting",
                    age_days=round(random.uniform(0.1, 60), 2),
                    weekly_downloads=int(10 ** random.uniform(0, 2.7)),
                    sim_distance=1, sim_min_len=7))
for i in range(20):   # 환각: PyPI에 없음 (출처가 확인된 환각 사례라고 가정)
    rows.append(row(name=f"hallu-{i}", label=1, category="hallucinated_nonexistent", exists=0))
random.shuffle(rows)
with open(sys.argv[1] if len(sys.argv) > 1 else "data/sample_features.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=FIELDS)
    w.writeheader()
    w.writerows(rows)
