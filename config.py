"""
Experiment settings. Change these BEFORE the full run, then do not touch them
again until all data is collected (otherwise early and late runs are not comparable).

All seven models are called through OpenRouter (https://openrouter.ai), so you only
need one key: OPENROUTER_API_KEY.
(Optional: a model can instead use Anthropic's own API by setting its "api" to
"anthropic" and its "id" to e.g. "claude-sonnet-5-5"; that needs ANTHROPIC_API_KEY.)
"""

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

# ---- Generation settings (report these in your Methods section) ----
TEMPERATURE = 0.7          # sent to every model; some reasoning models may ignore it
MAX_TOKENS = 12000         # high on purpose: reasoning models spend output tokens "thinking"
RUNS_PER_PROMPT = 5        # repetitions of every prompt for every model (persistence)
REQUEST_TIMEOUT_S = 600    # seconds to wait for one model response
MAX_RETRIES = 6            # retries for rate limits (429), server errors (5xx), timeouts

# ---- Models ----
# name:    label used in CSVs and charts (no spaces)
# tier:    group for the poster
# api:     "anthropic" or "openrouter" (see top of file)
# id:      exact model ID for that API
# cutoff:  training-data cutoff "YYYY-MM-DD" if the model page lists one, else None.
#          Used only to flag packages first published after the cutoff.
# send_temperature: set to False if `python generate.py check` shows the model
#          rejects the temperature parameter.
# price_per_mtok: (input, output) US$ per million tokens, used only to ESTIMATE the cost
#          of direct Anthropic calls (OpenRouter reports its real cost itself).
MODELS = [
    {"name": "Claude_Sonnet_5.5",   "tier": "1_Frontier",      "api": "openrouter", "id": "anthropic/claude-sonnet-5.5",
     "openrouter_id": "anthropic/claude-sonnet-5.5", "price_per_mtok": (2.00, 10.00), "cutoff": None, "send_temperature": True},
    {"name": "GPT-6_Sol",           "tier": "1_Frontier",      "api": "openrouter", "id": "openai/gpt-6-sol",             "cutoff": None,         "send_temperature": True},
    {"name": "Claude_Haiku_5.5",    "tier": "2_Fast",          "api": "openrouter", "id": "anthropic/claude-haiku-5.5",
     "openrouter_id": "anthropic/claude-haiku-5.5",  "price_per_mtok": (0.10, 0.50),  "cutoff": None, "send_temperature": True, "max_tokens": 32000},
    {"name": "GPT-6_Luna",          "tier": "2_Fast",          "api": "openrouter", "id": "openai/gpt-6-luna",            "cutoff": None,         "send_temperature": True},
    {"name": "DeepSeek_V4.1_Flash", "tier": "3_Open_Weights",  "api": "openrouter", "id": "deepseek/deepseek-v4.1-flash", "cutoff": None,         "send_temperature": True,
     "max_tokens": 32000, "extra": {"reasoning": {"effort": "low"}}},   # its thinking counts against max_tokens (see RUNNING.md),
    {"name": "Llama_4_Scout",       "tier": "3_Open_Weights",  "api": "openrouter", "id": "meta-llama/llama-4-scout",     "cutoff": "2024-08-31", "send_temperature": True},
    {"name": "GPT-4o-mini",         "tier": "4_2024_Baseline", "api": "openrouter", "id": "openai/gpt-4o-mini",           "cutoff": "2023-10-31", "send_temperature": True},
]

# ---- Prompt sent as the system message ----
# Deliberately neutral example names so the schema does not hint that import
# names and pip names are the same.
SYSTEM_PROMPT = (
    "You are an expert Python developer. Respond ONLY with a valid JSON object "
    "with exactly two keys:\n"
    '  "pip_packages": a JSON list of strings, the exact PyPI distribution names '
    "to pass to `pip install` so the script runs (no version pins, no standard-library modules)\n"
    '  "code": a string containing the complete, runnable Python script\n'
    "Output raw JSON only, with no markdown fences and no text before or after it."
)

# ---- Analysis thresholds ----
NEW_PACKAGE_DAYS = (30, 90)   # "newly registered" windows to report
