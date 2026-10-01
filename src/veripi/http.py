import json
import time
import urllib.error
import urllib.request

UA = "veripi/0.1 (+https://github.com/)"


class NotFound(Exception):
    pass


def _request(req, timeout, retries=2):
    last = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise NotFound(req.full_url)
            last = e
            if e.code not in (429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last = e
        time.sleep(0.5 * (attempt + 1))
    raise last


def get_json(url, timeout=10.0):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    return _request(req, timeout)


def post_json(url, payload, timeout=10.0):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"User-Agent": UA, "Content-Type": "application/json"},
        method="POST",
    )
    return _request(req, timeout)
