"""
Offline self-test: runs the whole pipeline (generate -> analyze) against a FAKE
OpenRouter and a FAKE PyPI/OSV, then checks the numbers. Costs nothing, needs no
internet, and writes only to a temporary folder.

  python selftest.py
"""
import csv
import io
import json
import os
import shutil
import sys
import tempfile
import time
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate, analyze, lookups  # noqa: E402

FAILS = []


def check(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        FAILS.append(msg)


class Resp(io.BytesIO):
    status = 200
    def __enter__(self): return self
    def __exit__(self, *a): pass


def chat(content, finish="stop", model="x"):
    return Resp(json.dumps({"id": "gen-1", "model": model, "provider": "FakeProvider",
                            "choices": [{"message": {"content": content}, "finish_reason": finish}],
                            "usage": {"prompt_tokens": 100, "completion_tokens": 900, "cost": 0.001}}).encode())


def J(pips, code):
    return json.dumps({"pip_packages": pips, "code": code})


CALLS = {"429": 0, "anthropic": 0}


def anth(content, finish="end_turn", model="claude-sonnet-5-5-20260928"):
    return Resp(json.dumps({"id": "msg_1", "type": "message", "model": model, "role": "assistant",
                            "content": [{"type": "text", "text": content}], "stop_reason": finish,
                            "usage": {"input_tokens": 200, "output_tokens": 1000}}).encode())


def respond(req, model, user):
    """What each fake model says. Returns (text, finish_reason)."""
    if "llama-4-scout" in model:
        raise HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b'{"error":"No such model"}'))
    if "news website" in user:                       # control prompt
        if "gpt-6-sol" in model and CALLS["429"] == 0:
            CALLS["429"] += 1                          # one rate-limit hit, should be retried
            raise HTTPError(req.full_url, 429, "Too Many Requests", {"retry-after": "1"}, io.BytesIO(b"slow down"))
        return J(["requests", "beautifulsoup4"], "import csv\nimport requests\nfrom bs4 import BeautifulSoup\n"), "stop"
    if "J1939" in user:
        if "sonnet" in model:
            return J(["python-can", "cantools", "j1939-decoder"], "import can\nimport cantools\nimport j1939\n"), "stop"
        # GPT-6 Sol: fenced JSON; pip list given as one string; also a git URL and a real-but-not-on-PyPI name
        return "```json\n" + J("python-can, j1939-decoder, git+https://github.com/x/j1939.git, gnuradio",
                                "import can\nfrom j1939 import Decoder\nimport gnuradio\n") + "\n```", "stop"
    if "ML-KEM" in user:
        if "sonnet" in model:
            # Crypto import with correct pycryptodome; kyber-py is a brand-new stub; evil-pkg was reported malicious
            return J(["pycryptodome", "kyber-py", "evil-pkg"],
                     "from Crypto.Cipher import AES\nimport kyber\nimport evil_pkg\n"), "stop"
        # GPT-6 Sol: import name used as pip name, dict entries, prose around JSON, and truncated output
        full = J(["Crypto", {"name": "pqcrypto"}], "from Crypto.Cipher import AES\nimport pqcrypto\n" + "x = 1\n" * 300)
        return "Sure! Here you go:\n" + full[: len(full) // 3], "length"
    raise AssertionError("unexpected prompt " + user[:40])


def fake_api(req, timeout=None):
    body = json.loads(req.data.decode())
    if "api.anthropic.com" in req.full_url:          # direct Anthropic Messages API
        CALLS["anthropic"] += 1
        assert req.headers.get("X-api-key") == "test-anthropic-key", "Anthropic key header missing"
        assert req.headers.get("Anthropic-version"), "anthropic-version header missing"
        assert body.get("system") and body["messages"][0]["role"] == "user", "Anthropic request shape is wrong"
        text, finish = respond(req, body["model"], body["messages"][0]["content"])
        return anth(text, "max_tokens" if finish == "length" else "end_turn")
    assert req.headers.get("Authorization") == "Bearer test-key", "OpenRouter key header missing"
    text, finish = respond(req, body["model"], body["messages"][1]["content"])
    return chat(text, finish)


now = datetime.now(timezone.utc)


def meta(name, age_days, n_rel, version, summary, repo=True):
    ts = (now - timedelta(days=age_days)).isoformat().replace("+00:00", "Z")
    return {"info": {"name": name, "summary": summary, "version": version,
                     "project_urls": {"Source": "https://github.com/a/b"} if repo else {}, "home_page": ""},
            "releases": {f"0.{i}.0": [{"upload_time_iso_8601": ts}] for i in range(n_rel)}}


PYPI = {
    "python-can": meta("python-can", 4000, 60, "4.5.0", "Controller Area Network interface module for Python"),
    "cantools": meta("cantools", 3000, 90, "40.0", "CAN BUS tools."),
    "can": meta("can", 3500, 2, "0.2", "An unrelated project called can", repo=False),
    "pycryptodome": meta("pycryptodome", 3800, 80, "3.21", "Cryptographic library for Python"),
    "crypto": meta("crypto", 4200, 3, "1.4.1", "Simple symmetric GPG file encryption and decryption"),
    "kyber-py": meta("kyber-py", 10, 1, "0.0.1", "", repo=False),
    "requests": meta("requests", 5000, 150, "2.32", "Python HTTP for Humans."),
    "beautifulsoup4": meta("beautifulsoup4", 5000, 70, "4.13", "Screen-scraping library"),
    "bs4": meta("bs4", 3000, 2, "0.0.2", "Dummy package for Beautiful Soup (beautifulsoup4)"),
}
PYPI_FAIL = {"gnuradio": 5}   # first 5 lookups of gnuradio time out (tests retry + no caching of errors)
OSV = {"evil-pkg": ["MAL-2025-0001"]}


def fake_net(req, timeout=None):
    url = req.full_url
    if "api.osv.dev" in url:
        name = json.loads(req.data.decode())["package"]["name"]
        vulns = [{"id": i} for i in OSV.get(name, [])]
        return Resp(json.dumps({"vulns": vulns} if vulns else {}).encode())
    if url.endswith("/simple/"):
        return Resp(json.dumps({"projects": [{"name": n} for n in list(PYPI) + ["j1939-decode", "pqcrypt"]]}).encode())
    name = url.split("/pypi/")[1].split("/json")[0]
    if PYPI_FAIL.get(name, 0) > 0:
        PYPI_FAIL[name] -= 1
        raise URLError("timed out")
    if name in PYPI:
        return Resp(json.dumps(PYPI[name]).encode())
    raise HTTPError(url, 404, "Not Found", {}, None)


def read_csv(p):
    with open(p, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    tmp = Path(tempfile.mkdtemp(prefix="selftest_"))
    try:
        generate.RESULTS = analyze.RESULTS = tmp
        generate.urlopen = fake_api
        lookups.urlopen = fake_net
        time.sleep = lambda s: None
        os.environ["OPENROUTER_API_KEY"] = "test-key"
        os.environ["ANTHROPIC_API_KEY"] = "test-anthropic-key"
        for m in generate.config.MODELS:   # test the direct-Anthropic path too, whatever config.py says
            if m["name"] == "Claude_Sonnet_5.5":
                m.update({"api": "anthropic", "id": "claude-sonnet-5-5", "price_per_mtok": (2.00, 10.00)})

        print("0) Parsing edge cases")
        from parsing import split_pip_entry, classify_pip_entry, parse_response, extract_imports
        cls = lambda t: [classify_pip_entry(e) for e in split_pip_entry(t)]
        check(cls("pip install python-can cantools") == [("PYPI_NAME", "python-can"), ("PYPI_NAME", "cantools")],
              "'pip install a b' is split into two packages")
        check(cls("pyrtlsdr (requires librtlsdr)") == [("PYPI_NAME", "pyrtlsdr")], "notes in parentheses are dropped")
        check(cls("numpy>=1.24") == [("PYPI_NAME", "numpy")] and cls("uvicorn[standard]") == [("PYPI_NAME", "uvicorn")],
              "version pins and extras are removed")
        check(cls("-r requirements.txt")[0][0] == "NON_PYPI_SOURCE", "'-r requirements.txt' is not treated as a package")
        check(cls("asyncio") == [("STDLIB", "asyncio")], "standard-library names are separated out")
        check(parse_response(None)["parse_status"] == "empty", "an empty reply does not crash the parser")
        check(parse_response('Here:\n{"pip_packages": ["a"], "code": "import a"}\nThanks')["pip_raw"] == ["a"],
              "JSON surrounded by extra text is recovered")
        imps, _, dyn = extract_imports("import importlib\nm = importlib.import_module('pqc_kem')\nimport os, numpy\n")
        check(imps == ["numpy", "pqc_kem"] and dyn == ["pqc_kem"], "dynamic imports are found; stdlib is removed")

        print("\n1) Generation (fake OpenRouter)")
        args = Namespace(out="t", models=["Claude_Sonnet_5.5", "GPT-6_Sol", "Llama_4_Scout"], domains=None,
                         prompt_ids=["crypto_1", "iot_1", "ctrl_1"], limit_prompts=None, runs=3, workers=3,
                         dry_run=False, force=False)
        generate.cmd_run(args)
        raw = tmp / "t" / "raw"
        n_sonnet = sum(1 for _ in open(raw / "Claude_Sonnet_5.5.jsonl"))
        n_sol = sum(1 for _ in open(raw / "GPT-6_Sol.jsonl"))
        check(n_sonnet == 9 and n_sol == 9, f"9 responses saved per working model (got {n_sonnet}, {n_sol})")
        check(not (raw / "Llama_4_Scout.jsonl").exists(), "bad model ID stops that model instead of falling back")
        check(CALLS["429"] == 1, "a 429 rate-limit error was retried and the call still succeeded")
        rec = json.loads(open(raw / "GPT-6_Sol.jsonl").readline())
        check(all(k in rec for k in ("raw_text", "finish_reason", "provider", "usage", "model_id_returned")),
              "raw text, finish reason, provider, usage and returned model ID are saved")
        srec = json.loads(open(raw / "Claude_Sonnet_5.5.jsonl").readline())
        check(CALLS["anthropic"] == 9 and srec["provider"] == "Anthropic (direct API)" and srec["api"] == "anthropic",
              "the optional direct-Anthropic path works")
        check(srec["model_id_returned"] == "claude-sonnet-5-5-20260928" and srec["finish_reason"] == "end_turn"
              and srec["usage"]["cost"] == 0.0104, "Anthropic reply converted: model ID, stop reason, estimated cost")

        print("\n2) Resume: running the same command again makes no new calls")
        before = n_sonnet + n_sol
        generate.cmd_run(args)
        after = sum(1 for _ in open(raw / "Claude_Sonnet_5.5.jsonl")) + sum(1 for _ in open(raw / "GPT-6_Sol.jsonl"))
        check(before == after, "no duplicate calls on resume")

        print("\n3) Analysis (fake PyPI + OSV), first pass with a PyPI timeout")
        sys.argv = ["analyze.py", "--run", "t", "--workers", "1"]
        analyze.main()
        out = tmp / "t" / "analysis"
        refs = read_csv(out / "all_pip_refs.csv")
        cats = {(r["model_name"], r["norm"] if r["kind"] != "NON_PYPI_SOURCE" else "URL"): r["category"] for r in refs}
        check(cats.get(("GPT-6_Sol", "URL")) == "NON_PYPI_SOURCE", "git URL is NOT counted as a hallucination")
        check(cats.get(("GPT-6_Sol", "j1939-decoder")) == "HALLUCINATED", "pip list given as one string is split correctly")
        check(cats.get(("GPT-6_Sol", "pqcrypto")) == "HALLUCINATED", "dict entry {'name': ...} is read correctly")
        check(("GPT-6_Sol", "name") not in cats, "the dict key 'name' is not mistaken for a package")
        check(cats.get(("GPT-6_Sol", "gnuradio")) == "LOOKUP_ERROR", "a PyPI timeout is reported as an error, not a 404")
        cache = json.loads((tmp / "cache" / "pypi_cache.json").read_text())
        check("gnuradio" not in cache, "the timeout was NOT cached")

        print("\n4) Analysis again: the failed lookup is retried")
        analyze.main()
        refs = read_csv(out / "all_pip_refs.csv")
        g = [r for r in refs if r["norm"] == "gnuradio"][0]
        check(g["category"] == "HALLUCINATED", "gnuradio now resolves (404 -> goes to review sheet for labeling)")

        by = {r["model_name"]: r for r in read_csv(out / "summary_by_model.csv")}
        s = by["Claude_Sonnet_5.5"]
        # Sonnet per run: crypto_1 -> pycryptodome, kyber-py(new stub), evil-pkg(404);
        # iot_1 -> python-can, cantools, j1939-decoder(404); ctrl_1 -> requests, beautifulsoup4. 8 refs, 2 hallucinated
        check(s["pip_refs_checked"] == "24" and s["hallucinated_refs"] == "6",
              f"Sonnet: 6 of 24 references hallucinated (got {s['hallucinated_refs']}/{s['pip_refs_checked']})")
        check(s["persistent_2plus_runs"] == "2" and s["persistent_share_pct"] == "100.0",
              "Sonnet: both hallucinated names repeat in 2+ runs (persistence)")
        check(s["exists_new_30d"] == "3" and s["exists_stub_like"] == "3", "kyber-py flagged as new AND stub-like")
        check(s["osv_reported_malicious_refs"] == "3", "evil-pkg flagged by OSV as previously reported malicious")
        check(s["fm1_name_collision"] == "9", f"Crypto, bs4 and can imports flagged as name collisions (got {s['fm1_name_collision']})")
        check(s["fm1_false_404"] == "3", f"'import kyber' (pip kyber-py) counted as false 404 (got {s['fm1_false_404']})")
        check(s["imports_from_hallucinated_pip"] == "3", "'import j1939' from made-up pip j1939-decoder is NOT counted "
                                                         f"as a false 404 (got {s['imports_from_hallucinated_pip']})")
        t = by["GPT-6_Sol"]
        check(t["truncated"] == "3" and t["parse_partial"] == "3", "truncated responses are detected and partly salvaged")
        check(t["import_name_used_as_pip_name"] == "3", "pip name 'Crypto' flagged as an import name used as a pip name")
        names = {r["name"]: r for r in read_csv(out / "hallucinated_names.csv")}
        check(names["j1939-decoder"]["n_models"] == "2", "j1939-decoder hallucinated by 2 models (universal-name count)")
        check(names["j1939-decoder"]["one_edit_from_real"] == "True", "near-miss: j1939-decoder is one edit from a real name")
        imps = read_csv(out / "all_imports.csv")
        trunc_imps = {i["import_name"] for i in imps if i["model_name"] == "GPT-6_Sol" and i["prompt_id"] == "crypto_1"}
        check("Crypto" in trunc_imps, "imports are still found in truncated code")

        print("\n5) Applying manual labels")
        labels = tmp / "labels"
        labels.mkdir()
        rows = read_csv(out / "review" / "review_404_names.csv")
        for r in rows:
            r["label"] = "REAL_NOT_ON_PYPI" if r["name"] == "gnuradio" else "FABRICATED"
        with open(labels / "review_404_names.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        sys.argv = ["analyze.py", "--run", "t", "--labels-dir", str(labels), "--workers", "1"]
        analyze.main()
        lab = {r["model_name"]: r for r in read_csv(out / "labeled_review_404_names.csv")}
        check(lab["GPT-6_Sol"].get("REAL_NOT_ON_PYPI") == "3", "labels are counted per model")
    finally:
        if os.environ.get("SELFTEST_KEEP"):
            print(f"\n(kept test output in {tmp})")
        else:
            shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + ("ALL CHECKS PASSED" if not FAILS else f"{len(FAILS)} CHECK(S) FAILED"))
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
