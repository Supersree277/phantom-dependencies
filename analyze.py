"""
Stage 3-4: parse the saved responses, check every package on live PyPI (+ OSV.dev),
compute the metrics, and write CSVs for charts and for manual review.

Usage
  python analyze.py --run smoke
  python analyze.py --run main --labels-dir labels         # after you fill in the review sheets
Options
  --no-osv        skip the malicious-package history check
  --no-near-miss  skip checking whether hallucinated names are one typo from a real package
  --workers 8     parallel PyPI lookups
"""
import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import config
from parsing import (normalize, parse_response, split_pip_entry, classify_pip_entry,
                     extract_imports, load_mapping, match_import)
from lookups import Cache, pypi_lookup, osv_lookup, load_pypi_index, edit1_neighbors, _parse_time

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
MODEL_META = {m["name"]: m for m in config.MODELS}


# ---------------------------------------------------------------- helpers
def wilson(k, n, z=1.96):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * max(0, c - h), 2), round(100 * min(1, c + h), 2))


def pct(k, n):
    return round(100 * k / n, 2) if n else None


def write_csv(path, rows, fields=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows and not fields:
        path.write_text("", encoding="utf-8")
        return
    fields = fields or list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: (";".join(map(str, v)) if isinstance(v, (list, set, tuple)) else v) for k, v in r.items()})


def load_records(run_dir):
    recs = []
    for p in sorted((run_dir / "raw").glob("*.jsonl")):
        if p.name.endswith(".errors.jsonl"):
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        recs.append(json.loads(line))
                    except json.JSONDecodeError:
                        print(f"  warning: damaged line skipped in {p.name}")
    # keep one record per (model, prompt, run) in case a file was appended twice
    uniq = {}
    for r in recs:
        uniq[(r["model_name"], r["prompt_id"], r["run_idx"])] = r
    return list(uniq.values())


# ---------------------------------------------------------------- main stages
def parse_all(records, mapping):
    gens, refs, imps = [], [], []
    for rec in records:
        base = {k: rec.get(k) for k in ("model_name", "tier", "prompt_id", "domain", "run_idx")}
        p = parse_response(rec.get("raw_text"))
        truncated = rec.get("finish_reason") in ("length", "max_tokens") or p["truncated_code"]
        usage = rec.get("usage") or {}
        details = usage.get("completion_tokens_details") or {}
        seen, pip_names = set(), []
        n_entries = 0
        for raw in p["pip_raw"]:
            for e in split_pip_entry(raw):
                kind, name = classify_pip_entry(e)
                if kind == "EMPTY":
                    continue
                key = normalize(name) if kind in ("PYPI_NAME", "STDLIB") else name
                if (kind, key) in seen:
                    continue
                seen.add((kind, key))
                n_entries += 1
                refs.append({**base, "raw_entry": raw, "name": name, "norm": key, "kind": kind})
                if kind == "PYPI_NAME":
                    pip_names.append(name)
        found, method, dynamic = extract_imports(p["code"])
        for imp in found:
            how, dist, expected = match_import(imp, pip_names, mapping)
            imps.append({**base, "import_name": imp, "dynamic_import": imp in dynamic, "declared_how": how,
                         "matched_pip": dist, "known_dists": expected, "pip_list": pip_names})
        gens.append({**base, "parse_status": p["parse_status"], "truncated": truncated,
                     "finish_reason": rec.get("finish_reason"), "provider": rec.get("provider"),
                     "model_id_returned": rec.get("model_id_returned"),
                     "n_pip_entries": n_entries, "n_third_party_imports": len(found), "import_method": method,
                     "prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"),
                     "reasoning_tokens": details.get("reasoning_tokens"), "cost_usd": usage.get("cost"),
                     "latency_s": rec.get("latency_s")})
    return gens, refs, imps


def run_lookups(names, fn, cache, workers, label):
    names = sorted(set(names))
    out = {}
    if not names:
        return out
    print(f"{label}: {len(names)} unique names")
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for name, res in zip(names, pool.map(lambda n: fn(n, cache), names)):
            out[name] = res
            done += 1
            if done % 50 == 0:
                cache.save()
                print(f"  {done}/{len(names)}")
    cache.save()
    errs = [n for n, r in out.items() if r.get("status") == "ERROR"]
    if errs:
        print(f"  ! {len(errs)} lookups failed temporarily (not cached). Re-run analyze.py to retry: {errs[:10]}")
    return out


def annotate_refs(refs, pypi, osv, alias_map):
    for r in refs:
        r.update({"category": r["kind"], "pypi_status": "", "canonical_name": "", "summary": "", "version": "",
                  "n_releases": "", "first_release_utc": "", "age_days": "", "new_30d": False, "new_90d": False,
                  "after_model_cutoff": False, "stub_like": False, "no_repo_link": False,
                  "import_name_as_pip": "", "osv_malicious_ids": "", "flagged": False})
        if r["kind"] != "PYPI_NAME":
            continue
        info = pypi.get(r["norm"], {})
        st = info.get("status", "ERROR")
        r["pypi_status"] = st
        r["category"] = {"EXISTS": "EXISTS", "NOT_FOUND": "HALLUCINATED"}.get(st, "LOOKUP_ERROR")
        o = osv.get(r["norm"]) or {}
        r["osv_malicious_ids"] = o.get("mal_ids", []) if o.get("status") == "OK" else ""
        if r["norm"] in alias_map:
            r["import_name_as_pip"] = alias_map[r["norm"]]
        if st != "EXISTS":
            r["flagged"] = bool(r["osv_malicious_ids"])
            continue
        first = _parse_time(info.get("first_release_utc"))
        looked = _parse_time(info.get("lookup_utc")) or datetime.now(timezone.utc)
        age = (looked - first).days if first else None
        cutoff = MODEL_META.get(r["model_name"], {}).get("cutoff")
        n_rel = info.get("n_releases")
        version = info.get("version") or ""
        summary = info.get("summary") or ""
        stub = (n_rel is not None and n_rel <= 1) and (version.startswith("0.0") or len(summary) < 10
                                                         or not info.get("has_repo_link"))
        r.update({"canonical_name": info.get("canonical_name"), "summary": summary[:200], "version": version,
                  "n_releases": n_rel, "first_release_utc": info.get("first_release_utc"), "age_days": age,
                  "new_30d": age is not None and age <= config.NEW_PACKAGE_DAYS[0],
                  "new_90d": age is not None and age <= config.NEW_PACKAGE_DAYS[1],
                  "after_model_cutoff": bool(cutoff and first and first.date().isoformat() > cutoff),
                  "stub_like": stub, "no_repo_link": not info.get("has_repo_link")})
        r["flagged"] = bool(r["new_90d"] or r["after_model_cutoff"] or stub or r["import_name_as_pip"]
                            or r["osv_malicious_ids"])


def annotate_imports(imps, pypi):
    for i in imps:
        info = pypi.get(normalize(i["import_name"]), {})
        st = info.get("status", "")
        i["import_name_on_pypi"] = st
        i["import_name_pypi_project"] = info.get("canonical_name", "")
        i["import_name_pypi_summary"] = (info.get("summary") or "")[:200]
        how = i["declared_how"]
        if how == "SAME_NAME":
            outcome = "CONSISTENT"
        elif st == "ERROR" or not st:
            outcome = "LOOKUP_ERROR"
        elif how in ("MAPPED", "HEURISTIC") and \
                pypi.get(normalize(i["matched_pip"]), {}).get("status") == "NOT_FOUND":
            outcome = "FROM_HALLUCINATED_PIP"      # import belongs to a pip package that does not exist
        elif how in ("MAPPED", "HEURISTIC"):
            if st == "NOT_FOUND":
                outcome = "FALSE_404"          # FM1a: import-name scanner wrongly reports a missing package
            elif normalize(info.get("canonical_name") or "") != normalize(i["matched_pip"]):
                outcome = "NAME_COLLISION"     # FM1b: import name on PyPI belongs to a different project
            else:
                outcome = "CONSISTENT"
        else:
            outcome = "UNDECLARED_NOT_ON_PYPI" if st == "NOT_FOUND" else "UNDECLARED_EXISTS"
        i["outcome"] = outcome


def persistence(refs, gens):
    """For hallucinated names: in how many runs of the same (model, prompt) did each appear?"""
    runs_done = Counter((g["model_name"], g["prompt_id"]) for g in gens)
    triples = defaultdict(set)
    for r in refs:
        if r["category"] == "HALLUCINATED":
            triples[(r["model_name"], r["prompt_id"], r["norm"])].add(r["run_idx"])
    rows = []
    for (m, p, n), runs in triples.items():
        total = runs_done[(m, p)]
        rows.append({"model_name": m, "prompt_id": p, "name": n, "runs_with_name": len(runs), "runs_done": total,
                     "persistent_2plus": len(runs) >= 2, "in_all_runs": total > 1 and len(runs) == total})
    return rows


def summarize(group_field, gens, refs, imps, pers):
    keys = sorted({g[group_field] for g in gens})
    out = []
    for k in keys:
        G = [g for g in gens if g[group_field] == k]
        R = [r for r in refs if r[group_field] == k]
        I = [i for i in imps if i[group_field] == k]
        if group_field in ("model_name", "tier"):
            P = [p for p in pers if (MODEL_META.get(p["model_name"], {}).get("tier") if group_field == "tier"
                                     else p["model_name"]) == k]
        else:
            dom = {g["prompt_id"]: g[group_field] for g in gens}
            P = [p for p in pers if dom.get(p["prompt_id"]) == k]
        cat = Counter(r["category"] for r in R)
        checkable = cat["HALLUCINATED"] + cat["EXISTS"]
        gens_with_h = {(r["model_name"], r["prompt_id"], r["run_idx"]) for r in R if r["category"] == "HALLUCINATED"}
        ex = [r for r in R if r["category"] == "EXISTS"]
        lo, hi = wilson(cat["HALLUCINATED"], checkable)
        oc = Counter(i["outcome"] for i in I)
        cost = sum(g["cost_usd"] or 0 for g in G if isinstance(g["cost_usd"], (int, float)))
        row = {
            group_field: k,
            "generations": len(G),
            "parse_failed_or_empty": sum(g["parse_status"] in ("failed", "empty") for g in G),
            "parse_partial": sum(g["parse_status"] == "partial" for g in G),
            "truncated": sum(bool(g["truncated"]) for g in G),
            "pip_refs_checked": checkable,
            "hallucinated_refs": cat["HALLUCINATED"],
            "hallucination_rate_pct": pct(cat["HALLUCINATED"], checkable),
            "rate_ci95_low": lo, "rate_ci95_high": hi,
            "generations_with_any_hallucination_pct": pct(len(gens_with_h), len(G)),
            "unique_hallucinated_names": len({r["norm"] for r in R if r["category"] == "HALLUCINATED"}),
            "hallucinated_name_prompt_pairs": len(P),
            "persistent_2plus_runs": sum(p["persistent_2plus"] for p in P),
            "persistent_share_pct": pct(sum(p["persistent_2plus"] for p in P), len(P)),
            "in_all_runs": sum(p["in_all_runs"] for p in P),
            "non_pypi_source_refs": cat["NON_PYPI_SOURCE"], "stdlib_listed_refs": cat["STDLIB"],
            "invalid_name_refs": cat["INVALID"], "lookup_errors": cat["LOOKUP_ERROR"],
            "exists_new_30d": sum(r["new_30d"] for r in ex), "exists_new_90d": sum(r["new_90d"] for r in ex),
            "exists_after_model_cutoff": sum(r["after_model_cutoff"] for r in ex),
            "exists_stub_like": sum(r["stub_like"] for r in ex),
            "import_name_used_as_pip_name": sum(bool(r["import_name_as_pip"]) for r in ex),
            "osv_reported_malicious_refs": sum(bool(r["osv_malicious_ids"]) for r in R),
            "third_party_imports": len(I),
            "fm1_false_404": oc["FALSE_404"], "fm1_name_collision": oc["NAME_COLLISION"],
            "imports_from_hallucinated_pip": oc["FROM_HALLUCINATED_PIP"],
            "undeclared_not_on_pypi": oc["UNDECLARED_NOT_ON_PYPI"], "undeclared_exists": oc["UNDECLARED_EXISTS"],
            "imports_consistent": oc["CONSISTENT"],
            "cost_usd": round(cost, 4),
            "completion_tokens": sum(g["completion_tokens"] or 0 for g in G),
        }
        if group_field == "model_name":
            row["tier"] = MODEL_META.get(k, {}).get("tier")
            row["providers"] = dict(Counter(g["provider"] for g in G))
            row["model_ids_returned"] = sorted({str(g["model_id_returned"]) for g in G})
        out.append(row)
    return out


def apply_labels(labels_dir, refs, imps, out_dir):
    """Join your manual labels onto the data and count them per model."""
    made = []
    specs = [("review_404_names.csv", "name", refs, lambda r: r["norm"], lambda r: r["category"] == "HALLUCINATED"),
             ("review_existing_flagged.csv", "name", refs, lambda r: r["norm"],
              lambda r: r["category"] == "EXISTS" and r["flagged"]),
             ("review_imports.csv", "key", imps, lambda i: f'{i["import_name"]}|{i["outcome"]}',
              lambda i: i["outcome"] != "CONSISTENT")]
    for fname, keycol, rows, keyfn, cond in specs:
        path = Path(labels_dir) / fname
        if not path.exists():
            continue
        with open(path, encoding="utf-8-sig", newline="") as f:
            labels = {row[keycol]: (row.get("label") or "").strip().upper() for row in csv.DictReader(f)}
        table = defaultdict(Counter)
        unlabeled = 0
        for r in rows:
            if not cond(r):
                continue
            lab = labels.get(keyfn(r), "")
            if not lab:
                unlabeled += 1
                lab = "UNLABELED"
            table[r["model_name"]][lab] += 1
        all_labels = sorted({l for c in table.values() for l in c})
        out_rows = [{"model_name": m, **{l: table[m][l] for l in all_labels}, "total": sum(table[m].values())}
                    for m in sorted(table)]
        out = out_dir / f"labeled_{fname}"
        write_csv(out, out_rows, ["model_name", *all_labels, "total"])
        made.append(out.name)
        if unlabeled:
            print(f"  note: {unlabeled} rows in {fname} have no label yet")
    print("Label tables written: " + (", ".join(made) if made else "none (no files found in labels dir)"))


def write_report(path, run, by_model, by_domain, names_rows, mapping_source, n_records):
    L = [f"# Results summary: run `{run}`", "",
         f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} from {n_records} responses. "
         f"Import mapping: {mapping_source}.", "",
         "Hallucination rate = pip_packages entries that return 404 on PyPI / all entries checked on PyPI. "
         "A 404 is the slopsquatting attack surface: anyone could register that name. Use the review sheets to "
         "split 404s into fabricated names vs real libraries that are simply not on PyPI.", "",
         "## By model", "",
         "| Model | Responses | Rate % (95% CI) | Responses with ≥1 | Unique names | Persistent share % | FM1 false 404 | FM1 collisions | Flagged-new 90d | Stub-like | OSV malicious |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in by_model:
        L.append(f"| {r['model_name']} | {r['generations']} | {r['hallucination_rate_pct']} "
                 f"({r['rate_ci95_low']}–{r['rate_ci95_high']}) | {r['generations_with_any_hallucination_pct']}% | "
                 f"{r['unique_hallucinated_names']} | {r['persistent_share_pct']} | {r['fm1_false_404']} | "
                 f"{r['fm1_name_collision']} | {r['exists_new_90d']} | {r['exists_stub_like']} | "
                 f"{r['osv_reported_malicious_refs']} |")
    L += ["", "## By domain", "", "| Domain | Responses | Rate % (95% CI) | Unique names |", "|---|---|---|---|"]
    for r in by_domain:
        L.append(f"| {r['domain']} | {r['generations']} | {r['hallucination_rate_pct']} "
                 f"({r['rate_ci95_low']}–{r['rate_ci95_high']}) | {r['unique_hallucinated_names']} |")
    multi = [n for n in names_rows if n["n_models"] >= 2]
    L += ["", f"## Names hallucinated by 2+ models: {len(multi)}", ""]
    for n in sorted(multi, key=lambda x: (-x["n_models"], -x["occurrences"]))[:25]:
        L.append(f"- `{n['name']}`: {n['n_models']} models, {n['occurrences']} times, prompts {n['prompts']}")
    L += ["", "## Quality checks", ""]
    for r in by_model:
        bad = r["parse_failed_or_empty"] + r["truncated"]
        if bad:
            L.append(f"- {r['model_name']}: {r['parse_failed_or_empty']} unparseable/empty, {r['truncated']} truncated "
                     f"(see generations.csv)")
        if r["lookup_errors"]:
            L.append(f"- {r['model_name']}: {r['lookup_errors']} PyPI lookup errors. Re-run analyze.py to retry.")
    L += ["", "Confidence intervals treat references as independent; responses to the same prompt are related, "
          "so read domain and model differences as descriptive."]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, help="folder name under results/")
    ap.add_argument("--no-osv", action="store_true")
    ap.add_argument("--no-near-miss", action="store_true")
    ap.add_argument("--refresh-index", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--labels-dir")
    args = ap.parse_args()
    if sys.version_info < (3, 10):
        sys.exit("Python 3.10 or newer is required.")

    run_dir = RESULTS / args.run
    out = run_dir / "analysis"
    records = load_records(run_dir)
    if not records:
        sys.exit(f"No responses found in {run_dir / 'raw'}. Run generate.py first.")
    print(f"Loaded {len(records)} responses from {run_dir / 'raw'}")

    mapping, mapping_source = load_mapping()
    print(f"Import-name mapping: {mapping_source}")
    # pip name that is really an import alias, e.g. "Crypto" -> pycryptodome, "serial" -> pyserial
    alias_map = {}
    for imp, dists in mapping.items():
        n = normalize(imp)
        if n not in {normalize(d) for d in dists}:
            alias_map[n] = f"{imp} -> {', '.join(dists[:3])}"

    gens, refs, imps = parse_all(records, mapping)
    cache_dir = RESULTS / "cache"
    pypi_cache = Cache(cache_dir / "pypi_cache.json")
    pypi_names = {r["norm"] for r in refs if r["kind"] == "PYPI_NAME"} | \
                 {normalize(i["import_name"]) for i in imps if i["declared_how"] != "SAME_NAME"}
    pypi = run_lookups(pypi_names, pypi_lookup, pypi_cache, args.workers, "PyPI lookups")
    osv = {}
    if not args.no_osv:
        osv = run_lookups({r["norm"] for r in refs if r["kind"] == "PYPI_NAME"}, osv_lookup,
                          Cache(cache_dir / "osv_cache.json"), args.workers, "OSV malicious-history lookups")

    annotate_refs(refs, pypi, osv, alias_map)
    annotate_imports(imps, pypi)
    pers = persistence(refs, gens)

    # hallucinated names table (cross-model / universal)
    hall = [r for r in refs if r["category"] == "HALLUCINATED"]
    index = None
    if not args.no_near_miss:
        try:
            index = load_pypi_index(cache_dir / "pypi_index.txt", args.refresh_index)
        except Exception as e:
            print(f"  near-miss check skipped: {e}")
    pers_by_name = defaultdict(bool)
    for p in pers:
        pers_by_name[p["name"]] |= p["persistent_2plus"]
    names_rows = []
    for n in sorted({r["norm"] for r in hall}):
        R = [r for r in hall if r["norm"] == n]
        row = {"name": n, "occurrences": len(R), "n_models": len({r["model_name"] for r in R}),
               "models": sorted({r["model_name"] for r in R}), "n_prompts": len({r["prompt_id"] for r in R}),
               "prompts": sorted({r["prompt_id"] for r in R}), "domains": sorted({r["domain"] for r in R}),
               "persistent_in_some_model": pers_by_name[n],
               "raw_examples": sorted({r["raw_entry"] for r in R})[:3],
               "osv_malicious_ids": R[0]["osv_malicious_ids"]}
        if index is not None:
            nb = edit1_neighbors(n, index)
            row["one_edit_from_real"] = bool(nb)
            row["nearest_real_names"] = nb[:5]
        names_rows.append(row)

    by_model = summarize("model_name", gens, refs, imps, pers)
    by_domain = summarize("domain", gens, refs, imps, pers)
    by_tier = summarize("tier", gens, refs, imps, pers)
    by_prompt = summarize("prompt_id", gens, refs, imps, pers)
    pm = []
    for (m, p) in sorted({(g["model_name"], g["prompt_id"]) for g in gens}):
        R = [r for r in refs if r["model_name"] == m and r["prompt_id"] == p and r["category"] in ("HALLUCINATED", "EXISTS")]
        h = sum(r["category"] == "HALLUCINATED" for r in R)
        pm.append({"model_name": m, "prompt_id": p, "domain": next(g["domain"] for g in gens if g["prompt_id"] == p),
                   "pip_refs_checked": len(R), "hallucinated_refs": h, "rate_pct": pct(h, len(R))})

    write_csv(out / "generations.csv", gens)
    write_csv(out / "all_pip_refs.csv", refs)
    write_csv(out / "all_imports.csv", imps)
    write_csv(out / "persistence.csv", pers)
    write_csv(out / "hallucinated_names.csv", names_rows)
    write_csv(out / "summary_by_model.csv", by_model)
    write_csv(out / "summary_by_domain.csv", by_domain)
    write_csv(out / "summary_by_tier.csv", by_tier)
    write_csv(out / "summary_by_prompt.csv", by_prompt)
    write_csv(out / "rate_by_model_and_prompt.csv", pm)

    # ---- manual review sheets (copy to your labels folder before editing) ----
    rev = out / "review"
    write_csv(rev / "review_404_names.csv",
              [{**{k: n[k] for k in ("name", "occurrences", "n_models", "models", "prompts", "persistent_in_some_model",
                                     "raw_examples", "osv_malicious_ids")},
                "nearest_real_names": n.get("nearest_real_names", ""), "label": "", "notes": ""} for n in names_rows],
              ["name", "label", "notes", "occurrences", "n_models", "models", "prompts", "persistent_in_some_model",
               "raw_examples", "nearest_real_names", "osv_malicious_ids"])
    flagged = {}
    for r in refs:
        if r["category"] == "EXISTS" and r["flagged"]:
            f = flagged.setdefault(r["norm"], {**{k: r[k] for k in (
                "canonical_name", "summary", "version", "n_releases", "first_release_utc", "age_days", "new_30d",
                "new_90d", "after_model_cutoff", "stub_like", "no_repo_link", "import_name_as_pip", "osv_malicious_ids")},
                "name": r["norm"], "occurrences": 0, "models": set(), "prompts": set(), "label": "", "notes": ""})
            f["occurrences"] += 1
            f["models"].add(r["model_name"])
            f["prompts"].add(r["prompt_id"])
    write_csv(rev / "review_existing_flagged.csv",
              [{**v, "models": sorted(v["models"]), "prompts": sorted(v["prompts"]),
                "pypi_link": f"https://pypi.org/project/{k}/"} for k, v in sorted(flagged.items())],
              ["name", "label", "notes", "pypi_link", "summary", "occurrences", "models", "prompts", "canonical_name",
               "version", "n_releases", "first_release_utc", "age_days", "new_30d", "new_90d", "after_model_cutoff",
               "stub_like", "no_repo_link", "import_name_as_pip", "osv_malicious_ids"])
    ir = {}
    for i in imps:
        if i["outcome"] == "CONSISTENT":
            continue
        key = f'{i["import_name"]}|{i["outcome"]}'
        d = ir.setdefault(key, {"key": key, "import_name": i["import_name"], "outcome": i["outcome"],
                                "matched_pip": set(), "known_dists": i["known_dists"],
                                "import_name_pypi_project": i["import_name_pypi_project"],
                                "import_name_pypi_summary": i["import_name_pypi_summary"],
                                "example_pip_list": i["pip_list"], "occurrences": 0, "models": set(),
                                "label": "", "notes": ""})
        d["occurrences"] += 1
        d["models"].add(i["model_name"])
        if i["matched_pip"]:
            d["matched_pip"].add(i["matched_pip"])
    write_csv(rev / "review_imports.csv",
              [{**v, "matched_pip": sorted(v["matched_pip"]), "models": sorted(v["models"])}
               for v in sorted(ir.values(), key=lambda x: (x["outcome"], -x["occurrences"]))],
              ["key", "label", "notes", "import_name", "outcome", "occurrences", "matched_pip", "known_dists",
               "import_name_pypi_project", "import_name_pypi_summary", "example_pip_list", "models"])

    write_report(out / "report.md", args.run, by_model, by_domain, names_rows, mapping_source, len(records))
    if args.labels_dir:
        apply_labels(args.labels_dir, refs, imps, out)

    print(f"\nDone. Open {out / 'report.md'} first.")
    for r in by_model:
        print(f"  {r['model_name']:<22} responses={r['generations']:<4} hallucination rate={r['hallucination_rate_pct']}% "
              f"({r['hallucinated_refs']}/{r['pip_refs_checked']})  unparseable={r['parse_failed_or_empty']}  "
              f"truncated={r['truncated']}")


if __name__ == "__main__":
    main()
