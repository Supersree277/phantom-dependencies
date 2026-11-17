# Phantom Dependencies

**Do AI coding assistants recommend Python packages that don't exist?**

When an AI assistant tells a developer to `pip install` a package that isn't on PyPI, anyone can register that
name and fill it with malware. The next developer who trusts the AI installs it. This attack is called
**slopsquatting**. This project measures how often seven current and older language models suggest such names.

Research poster for the Purdue Undergraduate Research Conference (ENGL 304), Sreekar Sreeram, Purdue University.

## Results (run in November 2026)

Seven models each answered 30 Python coding prompts 5 times (1,050 replies), run on 16 November 2026 through
OpenRouter (exact model IDs in [`config.py`](config.py)). Every package name they listed was checked against the
live PyPI index.

| Model | Tier | Package mentions checked* | Not on PyPI (95% CI) | No project by that name found |
|---|---|---|---|---|
| Claude Sonnet 5.5 | Frontier | 299 | 0.0% (0–1.3) | 0.0% |
| GPT-6 Sol | Frontier | 272 | 0.4% (0.1–2.1) | 0.4% |
| Claude Haiku 5.5 | Fast | 286 | 0.0% (0–1.3) | 0.0% |
| GPT-6 Luna | Fast | 240 | 1.3% (0.4–3.6) | 0.0% |
| DeepSeek V4.1 Flash | Open-weight | 291 | 2.1% (1.0–4.4) | 0.3% |
| Llama 4 Scout | Open-weight | 334 | **17.4%** (13.7–21.8) | 7.5% |
| GPT-4o mini | 2024 baseline | 386 | **8.8%** (6.4–12.1) | 2.1% |

\* Each package listed in a reply counts once per reply, so a name suggested in all 5 runs counts 5 times. Rates are
missing mentions ÷ mentions checked.

- **"Not on PyPI"** is the attack surface: every one of these names could be registered by anyone.
- **"No project by that name found"** is the stricter count after a manual review: names with no Python project
  by that exact name anywhere (PyPI, GitHub, other package managers). The rest were real tools that aren't Python
  packages, packages from other languages (npm, Rust), import names given instead of install names, or unsure cases.
- None of the missing names came from the five everyday "control" prompts. All of them came from the niche
  domains (cryptography, embedded/IoT, scientific data, cloud security, network protocols).
- Some invented names came back in most of the 5 runs, and a few were invented by two different models,
  which makes them predictable targets.

Replies to the same prompt are related, so read the confidence intervals and the differences between models as descriptive.

The counts behind this table are in [`data/`](data): per-model and per-domain summaries and the per-model
review-label counts. They contain no package names. The full name list is available to researchers on request.

## How it works

1. **Generate** (`generate.py`): sends each prompt to each model through OpenRouter at temperature 0.7 and saves
   the raw reply. Each reply is JSON with a `pip_packages` list and the `code`.
2. **Parse** (`parsing.py`): recovers package lists even from malformed or cut-off replies, and extracts the
   code's imports.
3. **Check** (`lookups.py`): looks up every name on the PyPI JSON API and in the OSV malicious-package database,
   and flags near-misses of real names.
4. **Analyze** (`analyze.py`): computes rates with Wilson 95% intervals, persistence across runs, names shared
   across models, and three ways a simple "does it exist?" check fails:
   - the import name differs from the install name (`import serial` comes from `pyserial`),
   - a package exists but isn't safe or relevant (placeholders, unrelated projects),
   - a package is new, which isn't the same as malicious.
5. **Review**: names that weren't on PyPI were labeled by hand (`--labels-dir`).

No package is ever installed or downloaded.

| File | What it does |
|---|---|
| `config.py` | Models, temperature, token limits, runs |
| `prompts.json` | The 30 prompts (5 niche domains + 1 control domain, 5 each) |
| `generate.py` | Calls the models (`check` and `run`) |
| `analyze.py`, `parsing.py`, `lookups.py` | Parsing, lookups, metrics, CSV reports |
| `peek.py` | Shows token use per reply, to find cut-off replies |
| `selftest.py` | Offline end-to-end test with fake APIs (free) |
| `RUNNING.md` | Full step-by-step guide, label codes, and methods details |

## Run it yourself

Needs Python 3.10+ and an [OpenRouter](https://openrouter.ai) API key. No other packages are required
(`pip install pipreqs` optionally improves import-name matching). A full run cost about $20 in November 2026.

```
python selftest.py
set OPENROUTER_API_KEY=sk-or-...        # Windows cmd
:: PowerShell: $env:OPENROUTER_API_KEY="sk-or-..."    Mac/Linux: export OPENROUTER_API_KEY="sk-or-..."
python generate.py check
python generate.py run --out main --workers 6
python analyze.py --run main
```

The key is read from the environment and is never written to any file. See [RUNNING.md](RUNNING.md) for the
details, including the manual review step.

## Limitations

- One snapshot: models and PyPI both change, so these rates describe November 2026.
- 30 prompts; rates depend heavily on the domain.
- The manual review is one person's judgment. Names suggested only once were checked against PyPI but not
  searched individually.
- Claude Haiku 5.5 and DeepSeek V4.1 Flash got a 32,000-token limit (their hidden reasoning used up 12,000), and
  DeepSeek ran at low reasoning effort. Claude Sonnet 5.5 kept 12,000; 17 of its 150 replies were cut off.

## Safety and ethics

- Never `pip install` a name from this study's results.
- No hallucinated name was registered, not even as a placeholder.
- The raw results and the full list of unregistered names are **not** in this repository, so it doesn't hand out a
  target list.

## Credits

Sreekar Sreeram designed the study and its prompts, chose the models, ran every experiment, diagnosed the
cut-off replies, did the manual review and interpreted the results. The pipeline code was developed with an AI
coding assistant (Claude, Anthropic) and tested by the author.
Thanks to Dr. Karrie Kaiser Lee (ENGL 304, Purdue University).

## References

- Churilov, A. (2026). *The range shrinks, the threat remains: Re-evaluating LLM package hallucinations on the
  2026 frontier-model cohort* [Preprint]. Zenodo. https://doi.org/10.5281/zenodo.19859120
- Korolevski, G. (2025, April 15). Malicious PyPI package hijacks MEXC orders, steals crypto tokens. *JFrog Blog*.
  https://jfrog.com/blog/malicious-pypi-package-hijacks-mexc-orders-steals-crypto-tokens/
- Krishna, A., Galinkin, E., Derczynski, L., & Martin, J. (2025). *Importing phantoms: Measuring LLM package
  hallucination vulnerabilities* (arXiv:2501.19012). arXiv. https://doi.org/10.48550/arXiv.2501.19012
- Spracklen, J., Wijewickrama, R., Sakib, A. H. M. N., Maiti, A., Viswanath, B., & Jadliwala, M. (2025). We have a
  package for you! A comprehensive analysis of package hallucinations by code generating LLMs. In *Proceedings of
  the 34th USENIX Security Symposium* (pp. 3687–3706). USENIX Association.
  https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen

The full literature review (16 sources) is available from the author.
