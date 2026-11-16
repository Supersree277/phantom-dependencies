"""Print token use for each reply in a run, to see why replies were cut off.
Usage:  python peek.py main                    (one line per reply, all models)
        python peek.py main Haiku              (only models whose name contains 'Haiku')
        python peek.py main Haiku --summary    (counts + which prompts got cut off)"""
import csv, sys
from collections import Counter
from pathlib import Path
from statistics import median

args = [a for a in sys.argv[1:] if not a.startswith("--")]
summary = "--summary" in sys.argv
run = args[0] if args else "smoke"
only = args[1].lower() if len(args) > 1 else ""
path = Path(__file__).parent / "results" / run / "analysis" / "generations.csv"
if not path.exists():
    sys.exit(f"No {path} yet. Run:  python analyze.py --run {run}")
rows = [r for r in csv.DictReader(open(path, encoding="utf-8")) if not only or only in r["model_name"].lower()]
num = lambda v: int(float(v)) if v not in ("", None, "None") else None

if not summary:
    print(f"{'model':22} {'prompt':9} {'finish':8} {'parse':12} {'out_tok':>8} {'reason_tok':>10} {'pip':>4}")
    for r in rows:
        print(f"{r['model_name']:22} {r['prompt_id']:9} {str(r['finish_reason']):8} {r['parse_status']:12} "
              f"{r['completion_tokens'] or '-':>8} {r['reasoning_tokens'] or '-':>10} {r['n_pip_entries']:>4}")
    sys.exit()

for model in sorted({r["model_name"] for r in rows}):
    R = [r for r in rows if r["model_name"] == model]
    out = [num(r["completion_tokens"]) for r in R if num(r["completion_tokens"]) is not None]
    rea = [num(r["reasoning_tokens"]) for r in R if num(r["reasoning_tokens"]) is not None]
    cut = [r for r in R if r["finish_reason"] in ("length", "max_tokens")]
    print(f"\n== {model}: {len(R)} replies")
    print("  finish:", dict(Counter(r["finish_reason"] for r in R)))
    print("  parse: ", dict(Counter(r["parse_status"] for r in R)))
    if out: print(f"  output tokens: median {median(out):.0f}, max {max(out)}")
    if rea: print(f"  reasoning tokens: median {median(rea):.0f}, max {max(rea)}")
    else:   print("  reasoning tokens: none reported")
    if cut:
        cr = [num(r["reasoning_tokens"]) or 0 for r in cut]
        print(f"  cut-off replies: {len(cut)}, median reasoning in them {median(cr):.0f}")
        print("  cut off, by prompt:", dict(Counter(r["prompt_id"] for r in cut).most_common()))
