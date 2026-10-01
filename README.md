# veriPI

AI 환각으로 추천된 존재하지 않는/악성 패키지(슬롭스쿼팅)를 **설치 전에** 위험도로 판정하는 라이브러리 + CLI.

## 설치 / 사용

```bash
pip install -e .            # 의존성: packaging
pip install -e ".[installed]"   # (선택) pipdeptree 모드

veripi check requests flask==3.0.0
veripi check some-pkg --json
veripi check some-pkg --installed     # 설치된 환경의 의존성(pipdeptree) 사용
veripi check some-pkg --no-deps

# AI 답변/README/Dockerfile/requirements.txt 에서 패키지를 추출해 일괄 검사
veripi scan requirements.txt
veripi scan ai_answer.md
pbpaste | veripi scan -               # stdin (AI 답변을 그대로 파이프)
```

`scan` 은 파일을 **파싱만** 하며 패키지를 설치/실행/import 하지 않습니다.
텍스트 모드는 `pip install ...`(코드블록/인라인 코드/줄 시작/Dockerfile `RUN`) 명령만 인식하고,
`requirements*.txt` 는 줄 단위로 파싱합니다. URL·경로·`-r`/`-e` 같은 옵션은 건너뜁니다.

`--popular-file my_popular.txt` 로 이름 유사도 비교용 인기 패키지 목록을 교체할 수 있습니다(공백/줄바꿈 구분, `#` 주석).
시연용 예시: `veripi scan examples/ai_answer_sample.md` (AI 답변 형태의 텍스트에서 설치 명령 추출 → 일괄 검사)

종료 코드(여러 패키지면 최댓값): 통과 0 / 경고 1 / 부적합 2 / 존재하지 않음 3 / 판정 불가 4 / 잘못된 입력 5

```python
from veripi import check_package
r = check_package("requests")
print(r.verdict, r.total_score, r.scores, r.signals)
```

> 판정 기준 전체 설명(점수표, 근거, 한계, 평가 방법)은 **[docs/detection_criteria.md](docs/detection_criteria.md)** 참고.

## 판정 로직

> v0.7: "슬롭스쿼팅 위험도"(통과/경고/부적합)와 "알려진 보안 취약점"(CVSS 등급)을 **완전히 분리**했습니다.
> 성숙하고 인기 많은 정상 패키지도 CVE가 있을 수 있는데, 이를 하나의 점수에 합치면 원인이 섞이기 때문입니다.

**① 슬롭스쿼팅 판정 (총점 최대 13)**
0. 입력 검증 — PEP 508 패키지명 형식 + **PEP 440 버전 파서**로 추가 검증, 형식이 아니면 `INVALID` (URL·명령어 삽입 방지)
1. PyPI 존재 여부 — 없으면 검사 중단 (`NOT_FOUND`, 환각 의심. 단, 오타·삭제된 패키지일 수도 있어 환각 여부를 확정하지는 않음)
2. 최초 등록일 → 점수: ≤7일 5 / ≤30일 4 / ≤90일 2 / 그 이상 0 (릴리즈 이력 없음도 5점, `incomplete` 기록)
3. 주간 다운로드(pypistats) → 점수: 0~349 5 / 350~14,999 3 / 15,000+ 1
   (통계 없음·404는 0회로 간주해 5점 + `incomplete` 기록, 조회 오류는 임시 3점 + `incomplete` 기록 — 둘을 구분)
4. 이름 유사도(인기 패키지와 Damerau-Levenshtein 편집거리) → 점수: 거리 0~1(5자 이상) 3 / 거리 2(8자 이상) 2.
   "동일 패키지" 판정은 PEP 503 정규화 기준(`Requests`=`requests`)만 쓰고, 구분자를 완전히 제거한 비교용 이름은 쓰지 않음
   (`req-uests`는 `requests`와 별개 패키지로 취급되어 거리 0으로 점수를 받음). **다운로드 수에 따른 유사도 면제 규칙은 없음.**
5. 총점(최대 13, 실제로는 다운로드 최소점이 1이라 1~13) → `warn_threshold`(4) 이상 경고, `fail_threshold`(7) 이상 부적합

**② 알려진 보안 취약점 (`security` 필드, 총점과 완전히 무관)**
- OSV API에서 패키지+직접 의존성의 취약점을 조회하고 **CVSS v3.0/3.1 공식 Base Score 수식**(FIRST 명세)으로 심각도를 계산
- `security.max_known_severity`: 확인된 등급 중 최고값(NONE/LOW/MEDIUM/HIGH/CRITICAL), 확인 가능한 등급이 없으면 `null`
- `security.unknown_severity_present`: 취약점은 있는데 등급을 확인 못한 것이 하나라도 있으면 `true`
- `security.query_status`: `COMPLETE`/`PARTIAL`(일부 누락·실패·OSV 다음 페이지 미조회)/`FAILED`(패키지 자체 OSV 조회 실패)
- `security.vulnerability_count`: 확인된 일반 취약점 수, 전부 실패하면 `null`
- `MAL-*`(OSV 공식 악성 패키지 리포트)는 패키지 자신이나 직접 의존성에 하나라도 있으면 **①의 총점과 무관하게 즉시 부적합**

모든 기준값은 `src/veripi/config.py` 에 있으며, 상당수가 **임시값이거나 실무 자료 기반**입니다. 근거 수준(논문 1순위 / 공식표준·실무도구 2순위 / 자체설정 3순위)은 `docs/detection_criteria.md` §6에 항목별로 정리되어 있습니다.

## 실험 워크플로 (0단계 → 2단계)

```bash
# 1) 라벨 데이터셋(name,label[,version,category,group,reported_at]) -> 지표 수집 (네트워크 필요, 1회)
python experiments/collect.py data/dataset.csv data/features.csv

# 2) [0단계] 튜닝 세트(70%)에서 임계값 조합별 Precision/Recall/F1/FPR 비교 + 추천 Threshold
python experiments/tune.py data/features.csv --split 0.7 --seed 42 --out data/tune_result.csv

# 3) config.py 수정 후 [2단계] 튜닝에 쓰지 않은 검증 세트(30%)로 최종 성능 검증
python experiments/evaluate.py data/features.csv --split 0.7 --seed 42
```

평가 설계상 주의할 점 (스크립트가 자동으로 반영/출력)
- **학습/검증 분리(그룹 단위)**: `--split`/`--seed` 를 tune 과 evaluate 에 똑같이 주면 라벨 비율을 유지한 채 분리된다.
  같은 `group`(기본값=패키지명)을 가진 행은 항상 같은 쪽에만 배치되어, 같은 캠페인/패키지의 여러 변형이
  튜닝·검증 양쪽에 걸쳐 데이터가 새는 것을 막는다.
- **분모 0인 지표는 0이 아니라 "미정의"**: Precision/Recall/F1/FPR는 분모가 0이면 `None`으로 표시되고
  "미정의"로 출력된다(임의로 0.0 처리하지 않음).
- **판정 불가(UNKNOWN)/잘못된 입력(INVALID)은 정상/위험 어느 쪽으로도 집계하지 않음**: 주 혼동행렬에서 제외하고,
  판정 가능 비율을 함께 보고한다.
- **악성 비율 민감도 분석**: 표본은 악성 비율이 높아 Precision 이 낙관적이다. `--prevalence 0.0001,0.001,0.01`
  (기본값)로 여러 실제 악성 비율 가정에서 기대 Precision 을 함께 보여준다. 단일 실측값이 아님에 유의.
- **삭제된 악성 패키지**: 적발된 악성 패키지는 PyPI 에서 삭제되어 `exists=0` 이 된다. 이를 "환각 탐지 성공"으로 세면
  Recall 이 부풀려지므로, `--exists-policy both`(기본)가 ① 전체 ② 존재하는 패키지만 두 관점을 나눠 출력한다.
- **출처 불명 라벨 제외**: `category`(hallucinated_nonexistent/typosquatting/confirmed_malicious/benign)를
  지정하지 않으면 `unknown`으로 저장되며, `--exclude-unknown-category`로 주 평가에서 뺄 수 있다
  (MAL/미존재만으로 슬롭스쿼팅 공격 경로를 단정하지 않는다는 원칙, §7.1).
- **기준 시점**: dataset 에 `reported_at`(YYYY-MM-DD)을 주면 '현재'가 아닌 신고 시점 기준으로 등록 후 경과 기간을 계산한다.
  (다운로드 수는 pypistats 가 최근 1주만 제공해 시점 불일치가 남는다)
- **WARN은 찾았지만 FAIL 기준을 못 찾을 수 있음**: `tune.py`가 목표 Precision을 만족하는 WARN보다 엄격한
  지점을 찾지 못하면 "미달성"이라고 명시하고, 검증되지 않은 숫자를 임의로 내놓지 않는다.

> `data/sample_features.csv` 는 스크립트 동작 확인용 **합성 데이터**입니다. 성능 수치로 인용하지 마세요.

## 테스트

```bash
python -m unittest discover -s tests -v
```

## 알려진 한계

- 이름 유사도: 정적 인기 목록(약 200개 요약본)이라 범위가 좁고, 정상 패키지가 인기 패키지와 우연히 가까운 경우
  (예: `willow`↔`pillow`)는 오탐 가능. 동형문자(`0`/`o`, `rn`/`m`)·콤보스쿼팅(`requests-security` 류)은 미지원
- 직접 의존성만 검사 (전이 의존성 제외, 최대 30개), 의존성 버전은 조건을 만족하는 최신 안정 버전으로 해석(실제 설치
  해결 결과와 다를 수 있음)
- pypistats 는 "최근 1주" 값만 제공 — 시점이 다른 데이터를 섞으면 편향 가능
- CVSS 벡터는 v3.0/3.1만 지원 (v2·v4는 `database_specific.severity`로 대체되거나 "심각도 미확인"으로 처리)
- OSV 응답에 다음 페이지가 더 있으면 감지는 하지만 따라가지는 않음(`query_status=PARTIAL`로 표시)
- 조회 실패·누락 시 `security`는 `QUERY_FAILED` 같은 가짜 등급이 아니라 `query_status`/`unknown_severity_present`
  같은 별도 상태 필드로 정직하게 표시
