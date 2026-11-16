"""
Turning raw model text into (pip packages, code, imports), robustly.
Every function here is offline and deterministic, so it can be tested and re-run for free.
"""
import ast
import json
import re
import sys
from pathlib import Path

STDLIB = {m.lower() for m in sys.stdlib_module_names} | {"__future__"}

# Names that are almost always the script's own local modules, not dependencies
LIKELY_LOCAL = {"app", "main", "config", "settings", "utils", "util", "helpers", "models",
                "src", "tests", "test", "lib", "common", "core", "local", "my_module", "mymodule"}

NAME_RE = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)


def normalize(name):
    """PEP 503 normalization: lowercase, runs of - _ . become one '-'."""
    return re.sub(r"[-_.]+", "-", str(name)).lower().strip("-")


# ---------------------------------------------------------------------------
# 1. Parse the model's JSON reply
# ---------------------------------------------------------------------------
def _strip_fences(text):
    t = text.strip()
    m = re.match(r"^```[a-zA-Z0-9_-]*\s*\n(.*?)\n?```\s*$", t, re.S)
    return m.group(1) if m else t


def _decode_partial_string(s, i):
    """Decode a JSON string starting just after its opening quote at index i.
    Works even if the text was cut off before the closing quote."""
    out, n = [], len(s)
    while i < n:
        ch = s[i]
        if ch == "\\":
            if i + 1 >= n:
                break
            nxt = s[i + 1]
            if nxt == "u":
                hexpart = s[i + 2:i + 6]
                if len(hexpart) < 4:
                    break
                try:
                    out.append(chr(int(hexpart, 16)))
                except ValueError:
                    pass
                i += 6
                continue
            out.append({"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f"}.get(nxt, nxt))
            i += 2
            continue
        if ch == '"':
            return "".join(out), True
        out.append(ch)
        i += 1
    return "".join(out), False


def _salvage(text):
    """Pull pip_packages and code out of broken or truncated JSON."""
    pips = []
    m = re.search(r'"pip_packages"\s*:\s*\[(.*?)(\]|$)', text, re.S)
    if m:
        parsed = None
        if m.group(2) == "]":
            try:
                parsed = json.loads("[" + m.group(1) + "]")   # complete list: keeps dict entries intact
            except json.JSONDecodeError:
                parsed = None
        pips = parsed if parsed is not None else [
            json.loads(f'"{x}"') if "\\" in x else x for x in re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))]
    code, complete = "", False
    m = re.search(r'"code"\s*:\s*"', text)
    if m:
        code, complete = _decode_partial_string(text, m.end())
    return pips, code, complete


def normalize_pip_list(value):
    """Accept whatever the model put in pip_packages and return a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        parts = re.split(r"[,\n]+", value) if ("," in value or "\n" in value) else value.split()
        return [x.strip() for x in parts if x.strip()]
    if isinstance(value, dict):
        value = list(value.keys())
    out = []
    for item in value if isinstance(value, list) else [value]:
        if isinstance(item, str):
            out.append(item.strip())
        elif isinstance(item, dict):
            name = item.get("name") or item.get("package") or item.get("pip") or item.get("distribution")
            if isinstance(name, str):
                out.append(name)
        elif item is not None:
            out.append(str(item))
    return out


def parse_response(raw_text):
    """Returns dict: pip_raw (list[str]), code (str), parse_status, truncated_code (bool)."""
    if raw_text is None or not str(raw_text).strip():
        return {"pip_raw": [], "code": "", "parse_status": "empty", "truncated_code": False}
    text = _strip_fences(str(raw_text))
    obj, status = None, "ok"
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        if start != -1:
            try:
                obj, _ = json.JSONDecoder().raw_decode(text[start:])
                status = "repaired"   # JSON was surrounded by extra text
            except json.JSONDecodeError:
                obj = None
    if isinstance(obj, dict) and ("pip_packages" in obj or "code" in obj):
        code = obj.get("code", "")
        if isinstance(code, list):
            code = "\n".join(map(str, code))
        return {"pip_raw": normalize_pip_list(obj.get("pip_packages")), "code": str(code or ""),
                "parse_status": status, "truncated_code": False}
    pips, code, complete = _salvage(text)
    if pips or code:
        return {"pip_raw": normalize_pip_list(pips), "code": code, "parse_status": "partial",
                "truncated_code": not complete}
    return {"pip_raw": [], "code": "", "parse_status": "failed", "truncated_code": False}


# ---------------------------------------------------------------------------
# 2. Clean and classify each pip entry
# ---------------------------------------------------------------------------
def split_pip_entry(entry):
    """'pip install a b==1.0' -> ['a', 'b==1.0'];  'a' -> ['a']"""
    e = str(entry).strip().strip("`'\" ,")
    e = re.sub(r"^(python3?\s+-m\s+)?pip3?\s+install\s+", "", e, flags=re.I)
    e = re.sub(r"\s*\(.*?\)\s*", " ", e).strip()   # drop notes like "(requires librtlsdr)"
    e = re.sub(r"\s+#.*$", "", e).strip()           # drop trailing comments
    if not e:
        return []
    if "://" in e or e.startswith(("git+", "/", "./", "../")) or \
            re.match(r"^(-[rce]\s|--(requirement|constraint|editable)\b)", e):
        return [e]
    e = e.split(";")[0].strip()                         # drop environment markers
    e = re.sub(r"\s*(===|==|>=|<=|!=|~=|>|<)\s*", r"\1", e)   # "numpy >= 1.24" -> "numpy>=1.24"
    e = re.sub(r"\s*,\s*", ",", e)                       # "a>=1, <2" stays one requirement
    return [p for p in e.split() if not p.startswith("-")]


def classify_pip_entry(entry):
    """Returns (kind, cleaned_name). kind: PYPI_NAME, NON_PYPI_SOURCE, STDLIB, INVALID, EMPTY"""
    e = str(entry).strip().strip("`'\" ,")
    if not e:
        return "EMPTY", ""
    low = e.lower()
    if e.startswith("-"):   # pip options: -r file, -e path are not package names; other flags are ignored
        return ("NON_PYPI_SOURCE", e) if re.match(r"^(-[rce]\b|--(requirement|constraint|editable)\b)", e) \
            else ("EMPTY", "")
    if "://" in e or low.startswith(("git+", "/", "./", "../", "file:")) or \
            low.endswith((".whl", ".tar.gz", ".zip", ".txt", ".toml", ".cfg")):
        return "NON_PYPI_SOURCE", e
    name = re.split(r"[\s\[<>=!~;@(,]", e, maxsplit=1)[0].strip()
    if not name:
        return "EMPTY", ""
    if not NAME_RE.match(name):
        return "INVALID", name
    if name.lower().replace("-", "_") in STDLIB:
        return "STDLIB", name
    return "PYPI_NAME", name


# ---------------------------------------------------------------------------
# 3. Extract third-party imports from the code
# ---------------------------------------------------------------------------
_IMPORT_LINE = re.compile(r"^\s*(?:from\s+([A-Za-z_]\w*)[\w.]*\s+import\b|import\s+(.+))", re.M)


def extract_imports(code):
    """Returns (imports: sorted list of top-level names, method, dynamic: list).
    Standard-library and obviously local modules are removed."""
    code = _strip_fences(code or "")
    found, dynamic, method = set(), set(), "none"
    if not code.strip():
        return [], method, []
    try:
        tree = ast.parse(code)
        method = "ast"
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    found.add(a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                f = node.func
                fname = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
                if fname in ("import_module", "__import__") and not node.args[0].value.startswith("."):
                    dynamic.add(node.args[0].value.split(".")[0])
    except (SyntaxError, ValueError):
        method = "regex"   # code did not parse (often because it was cut off)
        for m in _IMPORT_LINE.finditer(code):
            if m.group(1):
                found.add(m.group(1))
            else:
                for part in m.group(2).split(","):
                    tok = part.strip().split(" as ")[0].strip().split(".")[0]
                    if re.match(r"^[A-Za-z_]\w*$", tok):
                        found.add(tok)
    keep = lambda n: n and n.lower() not in STDLIB and n.lower() not in LIKELY_LOCAL and not n.startswith("_")
    found = {n for n in found if keep(n)}
    dynamic = {n for n in dynamic if keep(n)} - found
    return sorted(found | dynamic), method, sorted(dynamic)


# ---------------------------------------------------------------------------
# 4. Import name -> PyPI distribution name
# ---------------------------------------------------------------------------
# Common cases where the import name differs from the pip name.
BUILTIN_MAPPING = {
    "cv2": ["opencv-python", "opencv-python-headless", "opencv-contrib-python", "opencv-contrib-python-headless"],
    "PIL": ["pillow"], "yaml": ["pyyaml"], "sklearn": ["scikit-learn"], "skimage": ["scikit-image"],
    "bs4": ["beautifulsoup4"], "Crypto": ["pycryptodome", "pycrypto"], "Cryptodome": ["pycryptodomex"],
    "OpenSSL": ["pyopenssl"], "jwt": ["pyjwt"], "jose": ["python-jose"], "dateutil": ["python-dateutil"],
    "dotenv": ["python-dotenv"], "serial": ["pyserial"], "usb": ["pyusb"], "can": ["python-can"],
    "magic": ["python-magic"], "nmap": ["python-nmap"], "docx": ["python-docx"], "pptx": ["python-pptx"],
    "git": ["gitpython"], "github": ["pygithub"], "gitlab": ["python-gitlab"], "ldap": ["python-ldap"],
    "attr": ["attrs"], "fitz": ["pymupdf"], "Bio": ["biopython"], "nacl": ["pynacl"], "zmq": ["pyzmq"],
    "websocket": ["websocket-client"], "socketio": ["python-socketio"], "engineio": ["python-engineio"],
    "pkcs11": ["python-pkcs11"], "smartcard": ["pyscard"], "dns": ["dnspython"], "OpenGL": ["pyopengl"],
    "mpl_toolkits": ["matplotlib"], "osgeo": ["gdal"], "dicom": ["pydicom"], "ruamel": ["ruamel-yaml"],
    "win32api": ["pywin32"], "win32com": ["pywin32"], "pywintypes": ["pywin32"],
    "psycopg2": ["psycopg2", "psycopg2-binary"], "MySQLdb": ["mysqlclient"], "bluetooth": ["pybluez"],
    "rtlsdr": ["pyrtlsdr"], "hcl2": ["python-hcl2"], "hcl": ["pyhcl"], "Xlib": ["python-xlib"],
    "gi": ["pygobject"], "cyclonedx": ["cyclonedx-python-lib", "cyclonedx-bom"], "telegram": ["python-telegram-bot"],
    "slugify": ["python-slugify"], "multipart": ["python-multipart"], "jinja2": ["jinja2"], "markdown": ["markdown"],
    "Levenshtein": ["levenshtein", "python-levenshtein"], "lzf": ["python-lzf"], "snappy": ["python-snappy"],
}
# Namespace packages: any pip name starting with one of these prefixes provides the import
NAMESPACE_PREFIXES = {"google": ["google-", "protobuf", "googleapis-common-protos", "grpcio"],
                      "azure": ["azure-"], "zope": ["zope-"], "jaraco": ["jaraco-"], "sphinxcontrib": ["sphinxcontrib-"]}


def load_mapping():
    """Builtin table, plus the ~1,000-entry table from the pipreqs package if it is installed."""
    mapping = {k: list(v) for k, v in BUILTIN_MAPPING.items()}
    source = f"builtin ({len(mapping)} entries)"
    try:
        import importlib.util
        spec = importlib.util.find_spec("pipreqs")
        if spec and spec.origin:
            path = Path(spec.origin).parent / "mapping"
            if path.exists():
                added = 0
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if ":" in line:
                        imp, dist = line.strip().split(":", 1)
                        if imp and dist:
                            mapping.setdefault(imp, [])
                            if dist not in mapping[imp]:
                                mapping[imp].append(dist)
                                added += 1
                source += f" + pipreqs ({added} entries)"
    except Exception:
        pass
    return mapping, source


def match_import(imp, pip_names, mapping):
    """How is this import covered by the pip list?
    Returns (how, matched_dist, expected_dists). how: SAME_NAME, MAPPED, HEURISTIC, UNDECLARED"""
    pip_norm = {normalize(p): p for p in pip_names}
    n = normalize(imp)
    expected = mapping.get(imp, [])
    if n in pip_norm:
        return "SAME_NAME", pip_norm[n], expected
    for d in expected:
        if normalize(d) in pip_norm:
            return "MAPPED", pip_norm[normalize(d)], expected
    for prefix in NAMESPACE_PREFIXES.get(imp, []):
        for pn, p in pip_norm.items():
            if pn.startswith(normalize(prefix).rstrip("-")):
                return "MAPPED", p, expected
    variants = {f"python-{n}", f"py{n}", f"py-{n}", f"{n}-python", f"{n}py", f"{n}-py", f"python3-{n}", f"{n}-lib"}
    for v in variants:
        if v in pip_norm:
            return "HEURISTIC", pip_norm[v], expected
    if len(n) >= 4:
        for pn, p in pip_norm.items():
            if n in pn.split("-"):
                return "HEURISTIC", p, expected
    return "UNDECLARED", "", expected
