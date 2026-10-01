import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from veripi import Config, check_package
from veripi.pypi import PackageInfo, first_release_time, normalize
from veripi.scoring import score_age, score_downloads, verdict

CFG = Config()
NOW = datetime.now(timezone.utc)


def osv_result(vulns=(), truncated=False):
    """osv.query_vulns()가 반환하는 OsvResult 목업 헬퍼."""
    return {"vulns": list(vulns), "truncated": truncated}


def v(id_, severity=None):
    """취약점 dict 목업 헬퍼."""
    return {"id": id_, "malware": id_.startswith("MAL-"), "severity": None if id_.startswith("MAL-") else severity}


class Scoring(unittest.TestCase):
    def test_age_boundaries(self):
        for d, s in [(0.5, 5), (7, 5), (7.01, 4), (30, 4), (31, 2), (90, 2), (90.01, 0), (91, 0), (400, 0)]:
            self.assertEqual(score_age(d, CFG), s, d)
        self.assertEqual(score_age(None, CFG), 5)

    def test_downloads_boundaries(self):
        for w, s in [(0, 5), (349, 5), (350, 3), (14_999, 3), (15_000, 1), (10**7, 1)]:
            self.assertEqual(score_downloads(w, CFG), s, w)
        self.assertEqual(score_downloads(None, CFG), 3)

    def test_verdict(self):
        self.assertEqual(verdict(3, CFG), "PASS")
        self.assertEqual(verdict(4, CFG), "WARN")
        self.assertEqual(verdict(7, CFG), "FAIL")


class CVSS(unittest.TestCase):
    def test_base_score_known_vectors(self):
        from veripi.cvss import base_score, rating
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(rating(9.8), "CRITICAL")
        self.assertEqual(rating(0.0), "NONE")
        self.assertEqual(rating(3.9), "LOW")
        self.assertEqual(rating(4.0), "MEDIUM")
        self.assertEqual(rating(7.0), "HIGH")
        self.assertIsNone(base_score("not-a-vector"))
        self.assertIsNone(base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"))  # v2 미지원

    def test_severity_label_prefers_cvss_then_database_specific(self):
        from veripi.cvss import severity_label
        v_cvss = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(severity_label(v_cvss), "CRITICAL")
        v_ghsa = {"database_specific": {"severity": "MODERATE"}}
        self.assertEqual(severity_label(v_ghsa), "MEDIUM")   # GHSA MODERATE -> 공식 명칭 MEDIUM
        self.assertIsNone(severity_label({}))

    def test_worst_of_only_ranks_real_severities(self):
        from veripi.cvss import worst_of
        self.assertEqual(worst_of(["LOW", "HIGH", "MEDIUM"]), "HIGH")
        self.assertIsNone(worst_of([]))
        self.assertIsNone(worst_of([None, None]))
        self.assertIsNone(worst_of(["UNKNOWN_SEVERITY"]))   # 더 이상 등급으로 취급하지 않음


class OsvHelpers(unittest.TestCase):
    def test_unknown_severity_present(self):
        from veripi.osv import unknown_severity_present
        self.assertTrue(unknown_severity_present([v("GHSA-1", None)]))
        self.assertFalse(unknown_severity_present([v("GHSA-1", "LOW")]))
        self.assertFalse(unknown_severity_present([v("MAL-1", None)]))  # MAL은 집계 제외


class Util(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize("Foo_Bar.baz"), "foo-bar-baz")

    def test_first_release(self):
        rel = {"1.0": [{"upload_time_iso_8601": "2024-01-02T00:00:00Z"}],
               "0.1": [{"upload_time_iso_8601": "2023-05-01T10:00:00.123456Z"}]}
        self.assertEqual(first_release_time(rel).year, 2023)
        self.assertIsNone(first_release_time({}))


def info(days, requires=()):
    if days is None:
        return PackageInfo("pkg", "1.0", None, list(requires), ["1.0"])
    return PackageInfo("pkg", "1.0", NOW - timedelta(days=days), list(requires), ["1.0"])


class Checker(unittest.TestCase):
    @patch("veripi.checker.pypi.fetch_package", return_value=None)
    def test_not_found(self, _):
        r = check_package("ghost-pkg")
        self.assertEqual(r.verdict, "NOT_FOUND")

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=5_000_000)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_safe(self, *_):
        r = check_package("requests", check_deps=False)
        self.assertEqual(r.verdict, "PASS")
        self.assertEqual(r.total_score, 1)   # age 0 + downloads 1(>=15,000) + similarity 0
        self.assertIsNone(r.security["max_known_severity"])
        self.assertEqual(r.security["query_status"], "COMPLETE")
        self.assertEqual(r.security["vulnerability_count"], 0)
        self.assertFalse(r.security["unknown_severity_present"])

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=3)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(1))
    def test_new_low_download_fails(self, *_):
        r = check_package("evil-pkg", check_deps=False)
        self.assertEqual(r.verdict, "FAIL")
        self.assertEqual(r.total_score, 10)

    @patch("veripi.checker.osv.query_vulns")
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=500)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(20))
    def test_dependency_vuln_goes_to_security_axis_not_total(self, _f, _d, q):
        q.side_effect = lambda n, v_, t=10: osv_result([v("GHSA-x", "HIGH")]) if n == "baddep" else osv_result()
        with patch("veripi.checker.deps_mod.from_pypi", return_value=[("baddep", "1.0"), ("ok", "2.0")]):
            r = check_package("pkg")
        self.assertEqual(r.security["vulnerable_dependencies"], ["baddep"])
        self.assertEqual(r.security["max_known_severity"], "HIGH")
        self.assertEqual(r.security["query_status"], "COMPLETE")
        self.assertNotIn("osv", r.scores)
        self.assertEqual(r.total_score, 4 + 3 + 0)   # 등록 20일(4) + 다운로드 500(3) + 유사도 0

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result([v("PYSEC-1", "LOW"), v("PYSEC-2", "CRITICAL")]))
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=5_000_000)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_mature_safe_package_with_critical_cve_stays_pass_but_flags_security(self, *_):
        r = check_package("requests", check_deps=False)
        self.assertEqual(r.verdict, "PASS")
        self.assertEqual(r.total_score, 1)
        self.assertEqual(r.security["max_known_severity"], "CRITICAL")
        self.assertEqual(r.security["vulnerability_count"], 2)

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result([v("GHSA-1", None)]))
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=5_000_000)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_unknown_severity_tracked_separately_from_grade(self, *_):
        r = check_package("requests", check_deps=False)
        self.assertIsNone(r.security["max_known_severity"])
        self.assertTrue(r.security["unknown_severity_present"])
        self.assertEqual(r.security["query_status"], "COMPLETE")


class Malware(unittest.TestCase):
    @patch("veripi.checker.osv.query_vulns", return_value=osv_result([v("MAL-2024-1234"), v("GHSA-x", "LOW")]))
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=10_000_000)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_package_mal_is_instant_fail(self, *_):
        r = check_package("popular-but-hijacked", check_deps=False)
        self.assertEqual(r.verdict, "FAIL")
        self.assertIn("MAL-2024-1234", r.signals[0])
        self.assertEqual(r.security["package_vulns"], ["GHSA-x"])

    @patch("veripi.checker.osv.query_vulns")
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=10_000_000)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_dependency_mal_is_fail(self, _f, _d, q):
        q.side_effect = lambda n, v_, t=10: osv_result([v("MAL-1")]) if n == "evildep" else osv_result()
        with patch("veripi.checker.deps_mod.from_pypi", return_value=[("evildep", "1.0")]):
            r = check_package("innocent")
        self.assertEqual(r.verdict, "FAIL")
        self.assertEqual(r.security["malicious_dependencies"], ["evildep"])


class FailClosed(unittest.TestCase):
    @patch("veripi.checker.osv.query_vulns", return_value=None)
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=10_000_000)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_osv_failure_is_unknown_not_pass(self, *_):
        r = check_package("requests", check_deps=False)
        self.assertEqual(r.verdict, "UNKNOWN")
        self.assertIn("패키지 OSV 조회 실패", r.incomplete)
        self.assertEqual(r.security["query_status"], "FAILED")
        self.assertIsNone(r.security["max_known_severity"])
        self.assertIsNone(r.security["vulnerability_count"])
        self.assertFalse(r.security["unknown_severity_present"])

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=None)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_downloads_generic_failure_is_unknown(self, *_):
        r = check_package("requests", check_deps=False)
        self.assertEqual(r.verdict, "UNKNOWN")
        self.assertIn("다운로드 조회 오류", r.incomplete)

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", side_effect=__import__("veripi.pypistats", fromlist=["StatsNotFound"]).StatsNotFound("x"))
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_downloads_404_uses_zero_but_flags_incomplete(self, *_):
        r = check_package("requests", check_deps=False)
        self.assertEqual(r.details["weekly_downloads"], 0)
        self.assertEqual(r.scores["downloads"], 5)          # 0회 구간 점수
        self.assertIn("다운로드 통계 없음(404)", r.incomplete)
        self.assertEqual(r.verdict, "WARN")                 # 총점 5(age0+dl5+sim0) -> WARN, PASS가 아니므로 UNKNOWN 전환 없음

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=1)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(1))
    def test_risky_stays_fail_even_if_incomplete(self, *_):
        self.assertEqual(check_package("evil", check_deps=False).verdict, "FAIL")

    @patch("veripi.checker.pypi.fetch_package", side_effect=OSError("network down"))
    def test_pypi_outage_is_unknown(self, _):
        self.assertEqual(check_package("requests").verdict, "UNKNOWN")

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=10_000_000)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_dependency_lookup_failure_is_unknown(self, *_):
        with patch("veripi.checker.deps_mod.from_pypi", return_value=[("dep", None)]):
            r = check_package("pkg")
        self.assertEqual(r.verdict, "UNKNOWN")
        self.assertEqual(r.security["query_status"], "PARTIAL")

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result(truncated=True))
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=10_000_000)
    @patch("veripi.checker.pypi.fetch_package", return_value=info(3000))
    def test_osv_pagination_truncation_marks_partial(self, *_):
        r = check_package("requests", check_deps=False)
        self.assertEqual(r.security["query_status"], "PARTIAL")
        self.assertEqual(r.verdict, "UNKNOWN")

    @patch("veripi.checker.pypi.fetch_package", return_value=info(None))
    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=10_000_000)
    def test_missing_release_history_is_incomplete(self, *_):
        r = check_package("pkg", check_deps=False)
        self.assertIn("등록일 이력 없음", r.incomplete)
        self.assertEqual(r.scores["age"], 5)


class Validation(unittest.TestCase):
    def test_invalid_names(self):
        for bad in ["../etc/passwd", "a b", "req; rm -rf /", "x" * 200, "", "-e", "http://evil", "pkg==1.0;ls"]:
            self.assertEqual(check_package(bad).verdict, "INVALID", bad)

    def test_invalid_pep440_version(self):
        self.assertEqual(check_package("pkg==a..b").verdict, "INVALID")

    def test_valid_names_pass_validation(self):
        from veripi.checker import parse_spec
        self.assertEqual(parse_spec("Flask==3.0.0"), ("Flask", "3.0.0"))
        self.assertEqual(parse_spec("zope.interface"), ("zope.interface", None))


class Extract(unittest.TestCase):
    TEXT = """다음처럼 설치하세요:
```
$ pip install requests flask==3.0.0 "numpy>=1.20" -r other.txt --upgrade
python -m pip install --index-url https://x.y/simple fooo
```
또는 `pip install evil-lib[extra]` 를 실행하세요. Run pip install is nice 같은 문장은 무시.
RUN pip3 install pandas && echo done
- pip install torch==2.1.*
pip install git+https://github.com/a/b.git ./local ../x.whl
"""

    def test_text_mode(self):
        from veripi.extract import extract_packages
        specs, skipped = extract_packages(self.TEXT)
        self.assertEqual(specs, ["requests", "flask==3.0.0", "numpy", "fooo", "evil-lib", "pandas", "torch"])
        self.assertEqual(len(skipped), 3)

    def test_requirements_mode(self):
        from veripi.extract import extract_packages
        txt = ("requests==2.31.0  # http\n-r base.txt\n\n# comment\nflask>=2; python_version>'3'\n"
               "git+https://github.com/x/y.git\npkg @ https://a/b.whl\nDjango==4.2 --hash=sha256:abc\n")
        specs, skipped = extract_packages(txt, as_requirements=True)
        self.assertEqual(specs, ["requests==2.31.0", "flask", "Django==4.2"])
        self.assertEqual(len(skipped), 2)

    def test_dedup(self):
        from veripi.extract import extract_packages
        specs, _ = extract_packages("pip install Foo_Bar foo-bar")
        self.assertEqual(specs, ["Foo_Bar"])

    def test_no_install_command(self):
        from veripi.extract import extract_packages
        self.assertEqual(extract_packages("그냥 requests 라이브러리를 씁니다")[0], [])


class CLI(unittest.TestCase):
    def test_scan_stdin_exit_code_and_json(self):
        import io, json, sys
        from veripi import cli
        Report = check_package.__globals__["Report"]
        rep_pass = Report(name="requests", version="1.0", verdict="PASS", total_score=1,
                          scores={"age": 0, "downloads": 1, "similarity": 0},
                          security={"max_known_severity": None, "unknown_severity_present": False,
                                    "query_status": "COMPLETE", "vulnerability_count": 0})
        rep_nf = Report(name="ghost", version=None, verdict="NOT_FOUND")
        outs = {"requests": rep_pass, "ghost": rep_nf}
        with patch("veripi.cli.check_package", side_effect=lambda s, **k: outs[s]), \
             patch("sys.stdin", io.StringIO("pip install requests ghost")), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            code = cli.main(["scan", "-", "--json"])
        data = json.loads(out.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(data["summary"]["NOT_FOUND"], 1)
        self.assertEqual(len(data["results"]), 2)


class Similarity(unittest.TestCase):
    def test_edit_distance(self):
        from veripi.similarity import edit_distance
        self.assertEqual(edit_distance("requests", "reqeusts"), 1)
        self.assertEqual(edit_distance("requests", "requestss"), 1)
        self.assertEqual(edit_distance("requests", "requestz"), 1)
        self.assertEqual(edit_distance("abc", "abc"), 0)
        self.assertEqual(edit_distance("", "abc"), 3)

    def test_same_package_via_pep503_normalization_only(self):
        from veripi.similarity import nearest_popular
        self.assertIsNone(nearest_popular("Requests"))            # 대소문자만 다름 -> 동일 패키지
        self.assertIsNone(nearest_popular("requests"))
        # req-uests 는 PEP503 정규화로도 'requests'와 다른 이름이므로 "동일 패키지" 면제 대상이
        # 아니며, 구분자 제거 후 편집거리 비교에서 거리 0으로 별도 패키지로서 점수를 받는다.
        n = nearest_popular("req-uests")
        self.assertIsNotNone(n)
        self.assertEqual((n.name, n.distance), ("requests", 0))

    def test_nearest_popular(self):
        from veripi.similarity import nearest_popular
        n = nearest_popular("reqeusts")
        self.assertEqual((n.name, n.distance), ("requests", 1))
        self.assertIsNone(nearest_popular("my-cool-lib"))
        self.assertIsNone(nearest_popular("zzzzzzzz"))

    def test_score_similarity_no_download_exemption(self):
        from veripi.scoring import score_similarity
        self.assertEqual(score_similarity(1, 8, CFG), 3)
        self.assertEqual(score_similarity(0, 8, CFG), 3)
        self.assertEqual(score_similarity(2, 8, CFG), 2)
        self.assertEqual(score_similarity(2, 6, CFG), 0)
        self.assertEqual(score_similarity(1, 4, CFG), 0)
        self.assertEqual(score_similarity(None, 0, CFG), 0)
        self.assertFalse(hasattr(CFG, "sim_skip_downloads"))   # v0.7 수정본: 필드 자체 삭제

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=20)
    @patch("veripi.checker.pypi.fetch_package")
    def test_typosquat_in_checker(self, fetch, *_):
        fetch.return_value = PackageInfo("reqeusts", "1.0", NOW - timedelta(days=2), [], ["1.0"])
        r = check_package("reqeusts", check_deps=False)
        self.assertEqual(r.scores["similarity"], 3)
        self.assertEqual(r.total_score, 5 + 5 + 3)
        self.assertEqual(r.verdict, "FAIL")
        self.assertTrue(any("requests" in x for x in r.signals))

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=5)   # 다운로드 적어도 더는 면제되지 않음
    @patch("veripi.checker.pypi.fetch_package")
    def test_real_popular_not_flagged_but_low_download_lookalike_is(self, fetch, *_):
        fetch.return_value = PackageInfo("requests", "1.0", NOW - timedelta(days=4000), [], ["1.0"])
        r = check_package("requests", check_deps=False)
        self.assertEqual(r.scores["similarity"], 0)   # 자기 자신이라 유사도 대상 아님
        # 다운로드가 적으면(주 5회) 유사도와 무관하게 다운로드 점수만으로도 WARN이 될 수 있음
        # (v0.7 수정본: 다운로드 많으면 유사도를 면제하던 규칙은 삭제했지만, 이는 유사도
        # 계산과 무관한 별개 신호이므로 실제 인기 패키지 자신에게도 동일하게 적용됨)
        self.assertEqual(r.verdict, "WARN")
        self.assertEqual(r.scores["downloads"], 5)


class PopularFile(unittest.TestCase):
    def test_load_and_use_custom_popular(self):
        import os, tempfile
        from veripi.similarity import load_popular, nearest_popular
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("# 내 목록\nMy_Lib  other-lib # 주석\n")
            path = f.name
        try:
            pop = load_popular(path)
        finally:
            os.unlink(path)
        self.assertEqual(pop, ["my-lib", "other-lib"])
        self.assertEqual(nearest_popular("my-libb", pop).name, "my-lib")
        self.assertIsNone(nearest_popular("requestss", pop))

    @patch("veripi.checker.osv.query_vulns", return_value=osv_result())
    @patch("veripi.checker.pypistats.weekly_downloads", return_value=5)
    @patch("veripi.checker.pypi.fetch_package")
    def test_cfg_popular_used_by_checker(self, fetch, *_):
        fetch.return_value = PackageInfo("acme-toolz", "1.0", NOW - timedelta(days=400), [], ["1.0"])
        r = check_package("acme-toolz", cfg=Config(popular=("acme-tools",)), check_deps=False)
        self.assertEqual(r.scores["similarity"], 3)


class ExperimentTools(unittest.TestCase):
    def setUp(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))

    def test_split_is_stratified_and_reproducible(self):
        from common import stratified_split
        rows = [{"label": i % 4 == 0, "name": str(i)} for i in range(100)]
        rows = [dict(r, label=int(r["label"])) for r in rows]
        tr, va = stratified_split(rows, 0.7, 1)
        tr2, _ = stratified_split(rows, 0.7, 1)
        self.assertEqual([r["name"] for r in tr], [r["name"] for r in tr2])
        self.assertEqual(len(tr) + len(va), 100)
        self.assertEqual({r["name"] for r in tr} & {r["name"] for r in va}, set())
        self.assertEqual(sum(r["label"] for r in tr), round(25 * 0.7))

    def test_fpr_and_prevalence(self):
        from common import fpr, precision_at_prevalence
        self.assertAlmostEqual(fpr(5, 2, 1, 8), 0.2)
        self.assertIsNone(fpr(0, 0, 0, 0))                 # 분모 0 -> 미정의(None), 0으로 임의 처리하지 않음
        self.assertLess(precision_at_prevalence(0.9, 0.03, 0.001), 0.05)
        self.assertAlmostEqual(precision_at_prevalence(1.0, 0.0, 0.5), 1.0)

    def test_prf_undefined_when_denominator_zero(self):
        from common import prf
        p, r, f1 = prf(0, 0, 0, 0)
        self.assertIsNone(p)
        self.assertIsNone(r)
        self.assertIsNone(f1)

    def test_evaluate_predict_uses_malware_and_similarity(self):
        from evaluate import predict
        base = dict(exists=1, age_days=3000.0, weekly_downloads=10**7,
                    malware=0, sim_distance=None, sim_min_len=0)
        self.assertEqual(predict(base, CFG), "PASS")
        self.assertEqual(predict(dict(base, malware=1), CFG), "FAIL")
        self.assertEqual(predict(dict(base, exists=0), CFG), "NOT_FOUND")


class Metrics(unittest.TestCase):
    def test_prf_normal_case(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))
        from common import confusion, prf
        m = confusion([1, 1, 0, 0, 1], [1, 0, 0, 1, 1])
        self.assertEqual(m, (2, 1, 1, 1))
        p, r, f1 = prf(*m)
        self.assertAlmostEqual(p, 2 / 3)
        self.assertAlmostEqual(r, 2 / 3)
        self.assertAlmostEqual(f1, 2 / 3)


if __name__ == "__main__":
    unittest.main()
