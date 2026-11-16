"""
Live lookups: PyPI JSON API (does the package exist, how old, how many releases),
OSV.dev (has this package name ever been reported as malicious), and the full
PyPI name index (is a hallucinated name one typo away from a real package).

Results are cached in results/cache/. Temporary errors are NEVER cached, so
re-running the analysis retries them.
"""
import json
import random
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
import http.client

from parsing import normalize

UA = "package-hallucination-study/1.0 (undergraduate research; contact via Purdue)"
REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht", "sourceforge.net")
TRANSIENT = (URLError, TimeoutError, ConnectionError, http.client.HTTPException)


def _now():
    return datetime.now(timezone.utc)


def _parse_time(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


class Cache:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.data = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self.data = {}

    def get(self, key):
        with self.lock:
            return self.data.get(key)

    def put(self, key, value):
        with self.lock:
            self.data[key] = value

    def save(self):
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
            tmp.replace(self.path)


def _get_json(url, data=None, headers=None, timeout=20, tries=5):
    """Returns (http_status, parsed_json_or_None). Raises after repeated temporary failures."""
    last = None
    for attempt in range(tries):
        try:
            h = {"User-Agent": UA, "Accept": "application/json"}
            h.update(headers or {})
            req = Request(url, data=data, headers=h, method="POST" if data else "GET")
            with urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except HTTPError as e:
            if e.code == 404:
                return 404, None
            if e.code in (429, 500, 502, 503, 504):
                last = f"HTTP {e.code}"
            else:
                return e.code, None
        except TRANSIENT as e:
            last = f"{type(e).__name__}: {e}"
        except json.JSONDecodeError as e:
            last = f"bad JSON: {e}"
        time.sleep(min(30, 2 ** attempt) + random.uniform(0, 0.5))
    raise RuntimeError(last)


def pypi_lookup(name, cache):
    """Facts about one PyPI project name. status: EXISTS, NOT_FOUND or ERROR."""
    key = normalize(name)
    hit = cache.get(key)
    if hit and hit.get("status") in ("EXISTS", "NOT_FOUND"):
        return hit
    res = {"query": key, "status": "ERROR", "lookup_utc": _now().isoformat()}
    try:
        code, data = _get_json(f"https://pypi.org/pypi/{quote(key)}/json")
    except RuntimeError as e:
        res["error"] = str(e)
        return res                       # not cached -> retried next time
    res["http_status"] = code
    if code == 404:
        res["status"] = "NOT_FOUND"
    elif code == 200 and isinstance(data, dict):
        info = data.get("info") or {}
        releases = data.get("releases") or {}
        uploads = []
        n_with_files = 0
        for files in releases.values():
            times = [_parse_time(f.get("upload_time_iso_8601")) for f in (files or [])]
            times = [t for t in times if t]
            if times:
                n_with_files += 1
                uploads.extend(times)
        if not uploads:   # 'releases' missing: fall back to the files of the latest version
            uploads = [t for t in (_parse_time(f.get("upload_time_iso_8601")) for f in data.get("urls") or []) if t]
        urls = list((info.get("project_urls") or {}).values()) + [info.get("home_page") or ""]
        res.update({
            "status": "EXISTS",
            "canonical_name": info.get("name"),
            "summary": (info.get("summary") or "").strip(),
            "version": info.get("version"),
            "n_releases": n_with_files if releases else None,
            "first_release_utc": min(uploads).isoformat() if uploads else None,
            "latest_release_utc": max(uploads).isoformat() if uploads else None,
            "has_repo_link": any(h in (u or "").lower() for u in urls for h in REPO_HOSTS),
            "yanked": bool(info.get("yanked")),
        })
    else:
        res["error"] = f"HTTP {code}"
        return res
    cache.put(key, res)
    return res


def osv_lookup(name, cache):
    """Has this name ever had OSV advisories? MAL-* ids = reported malicious package
    (OpenSSF malicious-packages data). Works even for packages PyPI already deleted."""
    key = normalize(name)
    hit = cache.get(key)
    if hit and hit.get("status") == "OK":
        return hit
    res = {"query": key, "status": "ERROR", "lookup_utc": _now().isoformat()}
    ids, token = [], None
    try:
        for _ in range(20):
            body = {"package": {"name": key, "ecosystem": "PyPI"}}
            if token:
                body["page_token"] = token
            code, data = _get_json("https://api.osv.dev/v1/query", data=json.dumps(body).encode(),
                                   headers={"Content-Type": "application/json"})
            if code != 200 or not isinstance(data, dict):
                res["error"] = f"HTTP {code}"
                return res
            ids += [v.get("id") for v in data.get("vulns", []) if v.get("id")]
            token = data.get("next_page_token")
            if not token:
                break
    except RuntimeError as e:
        res["error"] = str(e)
        return res
    res.update({"status": "OK", "mal_ids": sorted(i for i in ids if i.startswith("MAL-")),
                "other_vuln_ids": sorted(i for i in ids if not i.startswith("MAL-"))})
    cache.put(key, res)
    return res


def load_pypi_index(path, refresh=False):
    """Set of every normalized project name on PyPI (downloaded once, ~10 MB)."""
    path = Path(path)
    if path.exists() and not refresh:
        return set(path.read_text(encoding="utf-8").split())
    print("Downloading the PyPI name index (one time, may take a minute)...")
    code, data = _get_json("https://pypi.org/simple/", headers={"Accept": "application/vnd.pypi.simple.v1+json"},
                           timeout=180)
    if code != 200:
        raise RuntimeError(f"PyPI index download failed: HTTP {code}")
    names = sorted({normalize(p["name"]) for p in data.get("projects", []) if p.get("name")})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(names), encoding="utf-8")
    return set(names)


ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"


def edit1_neighbors(name, index):
    """Real PyPI names exactly one edit (insert, delete, substitute, swap) away."""
    n = normalize(name)
    splits = [(n[:i], n[i:]) for i in range(len(n) + 1)]
    cands = set()
    for a, b in splits:
        if b:
            cands.add(a + b[1:])
            for c in ALPHABET:
                cands.add(a + c + b[1:])
        if len(b) > 1:
            cands.add(a + b[1] + b[0] + b[2:])
        for c in ALPHABET:
            cands.add(a + c + b)
    cands.discard(n)
    return sorted(c for c in cands if c in index)
