"""텍스트(AI 답변, README, Dockerfile 등)와 requirements 파일에서 패키지 후보 추출.

설치/실행/import 를 하지 않고 문자열만 파싱한다.
"""
import re
import shlex
from typing import Dict, List, Tuple

from packaging.requirements import InvalidRequirement, Requirement

from .pypi import normalize

_PREFIX = (r"(?:^|`|&&|;)[ \t]*(?:[-*][ \t]+)?(?:\d+\.[ \t]+)?(?:RUN[ \t]+)?(?:[$>!%][ \t]*)?"
           r"(?:sudo[ \t]+)?(?:python[0-9.]*[ \t]+-m[ \t]+)?")
_CMD = r"(?:pip3?|pipx|uv[ \t]+pip)[ \t]+install\b([^\n`;&|#]*)"
INSTALL_RE = re.compile(_PREFIX + _CMD, re.M | re.I)

OPTS_WITH_VALUE = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
    "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root",
    "--platform", "--python-version", "--implementation", "--abi", "--only-binary", "--no-binary",
    "--trusted-host", "--proxy", "--cert", "--src", "--upgrade-strategy", "-C", "--config-settings",
    "--report", "--progress-bar", "--python",
}


def _tokens(argstr: str) -> List[str]:
    try:
        toks = shlex.split(argstr)
    except ValueError:
        toks = argstr.split()
    out, skip = [], False
    for t in toks:
        if skip:
            skip = False
        elif t in OPTS_WITH_VALUE:
            skip = True
        elif not t.startswith("-"):
            out.append(t)
    return out


def _to_spec(req: Requirement) -> str:
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version:
        return f"{req.name}=={specs[0].version}"
    return req.name


def extract_packages(text: str, as_requirements: bool = False) -> Tuple[List[str], List[Dict[str, str]]]:
    """(검사할 spec 목록, 건너뛴 항목 [{token, reason}])"""
    found: Dict[str, str] = {}
    skipped: List[Dict[str, str]] = []

    def add(tok: str):
        if ("://" in tok or "$" in tok or tok.startswith((".", "/", "~"))
                or tok.lower().endswith((".whl", ".tar.gz", ".zip"))):
            skipped.append({"token": tok[:80], "reason": "URL/경로/변수 (PyPI 이름 아님)"})
            return
        try:
            req = Requirement(tok)
        except InvalidRequirement:
            skipped.append({"token": tok[:80], "reason": "패키지 요구사항 형식이 아님"})
            return
        if req.url:
            skipped.append({"token": tok[:80], "reason": "URL 기반 의존성"})
            return
        found.setdefault(normalize(req.name), _to_spec(req))

    if as_requirements:
        for line in text.splitlines():
            line = re.split(r"\s#", line)[0].strip()
            if not line or line.startswith(("#", "-")):
                continue
            add(line.split(" --")[0].strip())
    else:
        for m in INSTALL_RE.finditer(text):
            for t in _tokens(m.group(1)):
                add(t)
    return list(found.values()), skipped
