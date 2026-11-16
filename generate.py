"""
Stage 1-2: send every prompt to every model and save the RAW responses.

Nothing is parsed or checked here; that happens in analyze.py, so a parsing
mistake can always be fixed later without paying for the API calls again.

Usage
  python generate.py check                        # 1 tiny call per model: are IDs, key and params OK?
  python generate.py run --out smoke --runs 1 --limit-prompts 2   # smoke test
  python generate.py run --out main               # full run (resumes automatically if stopped)
  python generate.py run --out main --models GPT-6_Sol Llama_4_Scout   # only some models
  python generate.py run --out main --dry-run     # just print how many calls would be made
"""
import argparse
import hashlib
import http.client
import json
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import config

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"


class FatalAPIError(Exception):
    """An error that retrying will not fix (bad key, bad model ID, no credits, bad parameter)."""


KEY_VARS = {"openrouter": "OPENROUTER_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}


def _api_key(api):
    var = KEY_VARS[api]
    key = os.environ.get(var, "").strip()
    if not key:
        raise FatalAPIError(f"{var} is not set (needed for this model). See RUNNING.md step 2.")
    return key


def _build_request(model, system_prompt, user_prompt, max_tokens):
    """Request URL, headers and body for the model's API."""
    api = model.get("api", "openrouter")
    if api == "anthropic":
        payload = {"model": model["id"], "max_tokens": max_tokens, "system": system_prompt,
                   "messages": [{"role": "user", "content": user_prompt}]}
        headers = {"x-api-key": _api_key(api), "anthropic-version": config.ANTHROPIC_VERSION,
                   "content-type": "application/json"}
        url = config.ANTHROPIC_URL
    else:
        payload = {"model": model["id"],
                   "messages": [{"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt}],
                   "max_tokens": max_tokens,
                   "usage": {"include": True}}   # ask OpenRouter to report the cost of each call
        headers = {"Authorization": f"Bearer {_api_key(api)}", "Content-Type": "application/json",
                   "HTTP-Referer": "https://www.purdue.edu", "X-Title": "Package hallucination study"}
        url = config.OPENROUTER_URL
    if model.get("send_temperature", True):
        payload["temperature"] = config.TEMPERATURE
    payload.update(model.get("extra", {}))   # optional per-model request settings from config.py (e.g. reasoning)
    return url, headers, json.dumps(payload).encode("utf-8")


def _from_anthropic(data, model):
    """Convert an Anthropic Messages API reply to the same shape OpenRouter uses."""
    blocks = data.get("content") or []
    text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
    thinking = "".join(b.get("thinking", "") for b in blocks if isinstance(b, dict) and b.get("type") == "thinking")
    u = data.get("usage") or {}
    cost = None
    if model.get("price_per_mtok"):
        p_in, p_out = model["price_per_mtok"]
        cost = round(((u.get("input_tokens") or 0) * p_in + (u.get("output_tokens") or 0) * p_out) / 1e6, 6)
    return {"id": data.get("id"), "model": data.get("model"), "provider": "Anthropic (direct API)",
            "choices": [{"message": {"content": text, "reasoning": thinking},
                         "finish_reason": data.get("stop_reason")}],
            "usage": {"prompt_tokens": u.get("input_tokens"), "completion_tokens": u.get("output_tokens"),
                      "cost": cost, "cost_is_estimate": cost is not None}}


def call_model(model, system_prompt, user_prompt, max_tokens=None):
    """One model call (Anthropic or OpenRouter), with retries for temporary failures.
    Returns (response_json in OpenRouter shape, latency_seconds)."""
    url, headers, body = _build_request(model, system_prompt, user_prompt,
                                        max_tokens or model.get("max_tokens") or config.MAX_TOKENS)
    direct = model.get("api") == "anthropic"
    last_err = None
    for attempt in range(config.MAX_RETRIES + 1):
        t0 = time.time()
        retry_after = 0
        try:
            req = Request(url, data=body, headers=headers, method="POST")
            with urlopen(req, timeout=config.REQUEST_TIMEOUT_S) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            latency = time.time() - t0
            if direct:
                if isinstance(data, dict) and data.get("type") == "message":
                    return _from_anthropic(data, model), latency
                last_err = f"Unexpected Anthropic reply: {str(data)[:300]}"
            # OpenRouter can return HTTP 200 with an error object inside
            elif isinstance(data, dict) and data.get("error") and not data.get("choices"):
                err = data["error"]
                code = err.get("code") if isinstance(err, dict) else None
                last_err = f"API error in body: {err}"
                if code in (400, 401, 402, 403, 404):
                    raise FatalAPIError(last_err)
            elif not data.get("choices"):
                last_err = f"No choices in response: {str(data)[:300]}"
            else:
                return data, latency
        except HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:500]
            except Exception:
                pass
            last_err = f"HTTP {e.code}: {detail}"
            if e.code in (400, 401, 402, 403, 404):
                raise FatalAPIError(last_err)
            try:   # rate limits usually say how long to wait
                retry_after = float((e.headers or {}).get("retry-after") or 0)
            except (TypeError, ValueError):
                retry_after = 0
        except (URLError, TimeoutError, ConnectionError, http.client.HTTPException, json.JSONDecodeError) as e:
            last_err = f"{type(e).__name__}: {e}"
        if attempt < config.MAX_RETRIES:
            wait = max(min(60, 2 ** (attempt + 1)), min(retry_after, 120)) + random.uniform(0, 1.5)
            time.sleep(wait)
    raise RuntimeError(f"Gave up after {config.MAX_RETRIES + 1} attempts. Last error: {last_err}")


def extract_record(model, prompt, run_idx, data, latency):
    choice = data["choices"][0]
    msg = choice.get("message") or {}
    content = msg.get("content")
    if isinstance(content, list):  # some providers return content parts
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    reasoning = msg.get("reasoning") or ""
    return {
        "model_name": model["name"],
        "tier": model["tier"],
        "api": model.get("api", "openrouter"),
        "model_id_requested": model["id"],
        "model_id_returned": data.get("model"),
        "provider": data.get("provider"),
        "generation_id": data.get("id"),
        "prompt_id": prompt["id"],
        "domain": prompt["domain"],
        "prompt": prompt["prompt"],
        "run_idx": run_idx,
        "temperature_sent": config.TEMPERATURE if model.get("send_temperature", True) else None,
        "max_tokens": model.get("max_tokens") or config.MAX_TOKENS,
        "finish_reason": choice.get("finish_reason"),
        "native_finish_reason": choice.get("native_finish_reason"),
        "usage": data.get("usage"),
        "reasoning_chars": len(reasoning) if isinstance(reasoning, str) else None,
        "latency_s": round(latency, 2),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "raw_text": content,
    }


def load_done(path):
    done = set()
    if path.exists():
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    done.add((r["prompt_id"], r["run_idx"]))
                except (json.JSONDecodeError, KeyError):
                    print(f"  warning: skipped a damaged line in {path.name}")
    return done


def select_models(names):
    if not names:
        return config.MODELS
    by_name = {m["name"]: m for m in config.MODELS}
    missing = [n for n in names if n not in by_name]
    if missing:
        sys.exit(f"Unknown model name(s): {missing}. Choose from: {list(by_name)}")
    return [by_name[n] for n in names]


def load_prompts(args):
    prompts = json.loads((HERE / "prompts.json").read_text(encoding="utf-8"))
    if args.domains:
        prompts = [p for p in prompts if p["domain"] in args.domains]
    if args.prompt_ids:
        prompts = [p for p in prompts if p["id"] in args.prompt_ids]
    if args.limit_prompts:
        # take the first N prompts of EACH domain so a smoke test covers every domain
        seen, kept = {}, []
        for p in prompts:
            seen[p["domain"]] = seen.get(p["domain"], 0) + 1
            if seen[p["domain"]] <= args.limit_prompts:
                kept.append(p)
        prompts = kept
    return prompts


def cmd_check(args):
    print("Checking each model with one small request...\n")
    ok_all = True
    for m in select_models(args.models):
        try:
            data, lat = call_model(m, config.SYSTEM_PROMPT,
                                   "Write a Python script using third-party libraries to print today's date in ISO format.")
            rec = extract_record(m, {"id": "check", "domain": "check", "prompt": ""}, 0, data, lat)
            text = (rec["raw_text"] or "").strip()
            print(f"[OK]   {m['name']:<22} returned model={rec['model_id_returned']}  provider={rec['provider']}  "
                  f"finish={rec['finish_reason']}  {lat:.1f}s  reply starts: {text[:60]!r}")
            if not text:
                print("       ! empty reply text. If finish=length, the model used all tokens on reasoning.")
            elif rec["finish_reason"] in ("length", "max_tokens"):
                print("       ! reply was cut off by the token limit. Raise MAX_TOKENS in config.py.")
        except FatalAPIError as e:
            ok_all = False
            print(f"[FAIL] {m['name']:<22} {e}")
            if "temperature" in str(e).lower():
                print("       -> set send_temperature to False for this model in config.py")
        except Exception as e:
            ok_all = False
            print(f"[FAIL] {m['name']:<22} {type(e).__name__}: {e}")
    print("\nAll models OK." if ok_all else "\nFix the failures above (usually the model ID in config.py) and run check again.")


def cmd_run(args):
    models = select_models(args.models)
    prompts = load_prompts(args)
    runs = args.runs or config.RUNS_PER_PROMPT
    out_dir = RESULTS / args.out / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)

    # save the exact settings next to the data (for your Methods section), and refuse to mix
    # data from different settings in one folder: global settings, each model's config, each prompt's text
    settings_path = RESULTS / args.out / "settings.json"
    old = json.loads(settings_path.read_text(encoding="utf-8")) if settings_path.exists() else {}
    model_cfg = {**old.get("model_configs", {}), **{m["name"]: m for m in models}}
    prompt_txt = {**old.get("prompt_texts", {}), **{p["id"]: p["prompt"] for p in prompts}}
    settings = {
        "temperature": config.TEMPERATURE, "max_tokens": config.MAX_TOKENS,
        "system_prompt": config.SYSTEM_PROMPT, "runs_last_requested": runs,
        "model_configs": model_cfg, "prompt_texts": prompt_txt,
        "prompts_sha256": hashlib.sha256(json.dumps(prompt_txt, sort_keys=True).encode()).hexdigest(),
    }
    if old:
        changed = [k for k in ("temperature", "max_tokens", "system_prompt") if k in old and old[k] != settings[k]]
        changed += [f"model {m['name']}" for m in models
                    if m["name"] in old.get("model_configs", {})
                    and old["model_configs"][m["name"]] != json.loads(json.dumps(m))]   # JSON form: tuples -> lists
        changed += [f"prompt {p['id']}" for p in prompts
                    if p["id"] in old.get("prompt_texts", {}) and old["prompt_texts"][p["id"]] != p["prompt"]]
        if changed and not args.force:
            sys.exit(f"Settings changed since this run started: {changed}. Use a new --out folder, "
                     f"or add --force if you really mean to mix them.")
    if not args.dry_run:
        settings["first_started_utc"] = old.get("first_started_utc") or datetime.now(timezone.utc).isoformat()
        settings["last_started_utc"] = datetime.now(timezone.utc).isoformat()
        settings_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")

    total_todo = 0
    plan = []
    for m in models:
        path = out_dir / f"{m['name']}.jsonl"
        done = load_done(path)
        todo = [(p, r) for p in prompts for r in range(1, runs + 1) if (p["id"], r) not in done]
        plan.append((m, path, todo))
        total_todo += len(todo)
        print(f"{m['name']:<22} done={len(done):<4} to do={len(todo)}")
    print(f"Total calls to make: {total_todo}")
    if args.dry_run or total_todo == 0:
        return

    lock = threading.Lock()
    counter = {"n": 0, "err": 0}
    fatal_models = set()

    def work(m, path, prompt, run_idx):
        if m["name"] in fatal_models:
            return
        try:
            data, lat = call_model(m, config.SYSTEM_PROMPT, prompt["prompt"])
            rec = extract_record(m, prompt, run_idx, data, lat)
            with lock:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                counter["n"] += 1
                flag = "" if rec["finish_reason"] in ("stop", "end_turn", None) else f"  (finish={rec['finish_reason']})"
                print(f"  [{counter['n']}/{total_todo}] {m['name']} {prompt['id']} run {run_idx}{flag}")
        except FatalAPIError as e:
            with lock:
                fatal_models.add(m["name"])
                counter["err"] += 1
                print(f"  STOPPING {m['name']}: {e}\n  -> check this model's ID in config.py and run `python generate.py check`")
        except Exception as e:
            with lock:
                counter["err"] += 1
                with open(out_dir / f"{m['name']}.errors.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps({"prompt_id": prompt["id"], "run_idx": run_idx, "error": str(e),
                                        "timestamp_utc": datetime.now(timezone.utc).isoformat()}) + "\n")
                print(f"  error {m['name']} {prompt['id']} run {run_idx}: {e}")

    jobs = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        # interleave models so one slow model does not hold up the others
        rounds = max(len(t) for _, _, t in plan)
        for i in range(rounds):
            for m, path, todo in plan:
                if i < len(todo):
                    p, r = todo[i]
                    jobs.append(pool.submit(work, m, path, p, r))
        for _ in as_completed(jobs):
            pass
    print(f"\nFinished. Saved {counter['n']} responses, {counter['err']} errors.")
    if counter["err"]:
        print("Run the same command again to retry only the missing ones.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="send one small request to each model")
    c.add_argument("--models", nargs="*")
    r = sub.add_parser("run", help="generate responses")
    r.add_argument("--out", required=True, help="folder name under results/, e.g. smoke or main")
    r.add_argument("--models", nargs="*", help="only these model names (see config.py)")
    r.add_argument("--domains", nargs="*", help="only these domains")
    r.add_argument("--prompt-ids", nargs="*")
    r.add_argument("--limit-prompts", type=int, help="only the first N prompts of each domain")
    r.add_argument("--runs", type=int, help=f"repetitions per prompt (default {config.RUNS_PER_PROMPT})")
    r.add_argument("--workers", type=int, default=4, help="parallel requests (default 4)")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--force", action="store_true")
    args = ap.parse_args()
    if sys.version_info < (3, 10):
        sys.exit("Python 3.10 or newer is required.")
    {"check": cmd_check, "run": cmd_run}[args.cmd](args)


if __name__ == "__main__":
    main()
