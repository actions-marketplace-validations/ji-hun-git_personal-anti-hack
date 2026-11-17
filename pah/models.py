"""Model files that run code when they are loaded, read without loading them.

Pickle, and the PyTorch, joblib and NumPy formats built on it, is a small program the loader runs: it can import any
function and call it. Keras archives can carry Python bytecode in a Lambda layer or name any function in their
config (CVE-2025-1550, CVE-2025-8747, CVE-2025-9906; .h5 files ignore safe_mode, CVE-2025-9905). A GGUF file carries a
Jinja chat template that llama-cpp-python rendered without a sandbox (CVE-2024-34359). Attackers have published models
doing these things on Hugging Face (JFrog 2024; ReversingLabs' nullifAI 2025, packed with 7z and a deliberately broken
pickle stream so scanners gave up), and model repositories that run their own code through trust_remote_code (the
Load/Mine campaign, 2026).

Each format is parsed here as data, the way Protect AI's ModelScan and Trail of Bits' fickling do: pickle opcodes are
listed with pickletools and never executed.
"""
from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import pickletools
import posixpath
import re
import struct
import zipfile
import zlib

from .model import rule

R_MODEL_CODE = rule(
    "PAH-M001", "Model file runs code when it is loaded",
    "Loading this model (torch.load, pickle.load, joblib.load, np.load with allow_pickle, keras.models.load_model) runs "
    "the function it names: a shell command, exec or eval, a file or network operation. Malicious models on Hugging Face "
    "opened reverse shells this way.",
    "Do not load it. Use a safetensors copy, or load weights only (torch.load(..., weights_only=True)) from a source "
    "you trust.", attack=("T1204.002", "T1195.002"), owasp=("LLM03",),
    refs=("https://github.com/protectai/modelscan",
          "https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/"))
R_MODEL_IMPORTS = rule(
    "PAH-M002", "Model file imports code outside known ML libraries",
    "The pickle names functions from modules no ML library uses for weights. It may be a project's own class, or a "
    "way in: loading it imports that module and calls what it names.",
    "Check that the module is the project's own code before loading the file.", attack=("T1204.002",), owasp=("LLM03",),
    refs=("https://github.com/trailofbits/fickling",))
R_KERAS_CODE = rule(
    "PAH-M003", "Keras model carries Python code",
    "A Lambda layer stores Python bytecode that runs when the model is loaded or called; .h5 files run it even with "
    "safe_mode (CVE-2025-9905).", "Load it only if you wrote it. Rebuild the layer in code instead.",
    attack=("T1204.002",), owasp=("LLM03",),
    refs=("https://github.com/keras-team/keras/security/advisories",))
R_TEMPLATE = rule(
    "PAH-M004", "GGUF chat template reaches outside the template",
    "The chat template is code (Jinja) run on every conversation. Reaching __globals__, os or popen from it ran "
    "commands in llama-cpp-python (CVE-2024-34359); text that addresses the model rewrites every conversation.",
    "Do not load the model in a runtime that renders templates without a sandbox; use a template you trust.",
    attack=("T1204.002",), owasp=("LLM03", "LLM01"), refs=("https://nvd.nist.gov/vuln/detail/CVE-2024-34359",))
R_PACKED = rule(
    "PAH-M005", "Model file packed so it cannot be checked",
    "PyTorch files are zip archives; a 7z-packed one, or a pickle stream that breaks after its first instructions, is "
    "how nullifAI got malicious models past Hugging Face's scanner: the loader runs what comes before the break.",
    "Do not load it.", attack=("T1027", "T1204.002"), owasp=("LLM03",),
    refs=("https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face",))
R_REMOTE_CODE = rule(
    "PAH-M006", "Model repository runs its own code (trust_remote_code)",
    "auto_map in config.json makes transformers import the repository's Python files when a model is loaded with "
    "trust_remote_code=True; those files then run as part of loading. The Load/Mine campaign installed miners this way "
    "from 31 fake model repositories.", "Read the files auto_map names, or load a model that does not need remote code.",
    attack=("T1204.002", "T1195.002"), owasp=("LLM03",),
    refs=("https://pluto.security/blog/hugging-face-malware-campaign-load-mine/",))

MODEL_RULES = (R_MODEL_CODE, R_MODEL_IMPORTS, R_KERAS_CODE, R_TEMPLATE, R_PACKED, R_REMOTE_CODE)

PICKLE_EXT = (".pkl", ".pickle", ".joblib", ".dill")
TORCH_EXT = (".pt", ".pth", ".bin", ".ckpt", ".mar", ".model")
MODEL_EXT = PICKLE_EXT + TORCH_EXT + (".npy", ".npz", ".keras", ".h5", ".hdf5", ".gguf", ".pb")

ZIP = b"PK\x03\x04"
SEVEN_Z = b"7z\xbc\xaf\x27\x1c"
GGUF = b"GGUF"
NUMPY = b"\x93NUMPY"
HDF5 = b"\x89HDF\r\n\x1a\n"

# What loading must never reach. Modules: any name in them (ModelScan's critical list, plus loaders of nested code).
DANGER_MODULES = {"os", "nt", "posix", "subprocess", "_posixsubprocess", "sys", "socket", "pty", "runpy", "pickle", "_pickle",
                  "cPickle", "dill", "shutil", "asyncio", "pdb", "bdb", "code", "codeop", "commands", "popen2", "importlib",
                  "ctypes", "multiprocessing", "marshal", "types", "timeit", "cProfile", "profile", "trace", "pydoc",
                  "distutils", "setuptools", "pip", "platform", "zipimport"}
DANGER_BUILTINS = {"eval", "exec", "execfile", "compile", "open", "file", "getattr", "setattr", "delattr", "__import__",
                   "breakpoint", "globals", "locals", "vars", "input", "apply", "reload"}
DANGER_PAIRS = {("operator", "attrgetter"), ("operator", "methodcaller"), ("_operator", "attrgetter"),
                ("_operator", "methodcaller"), ("numpy.testing._private.utils", "runstring"), ("torch", "load"),
                ("torch.serialization", "load"), ("numpy", "load"), ("joblib", "load"), ("torch.hub", "load"),
                ("torch.hub", "load_state_dict_from_url"), ("torch.hub", "download_url_to_file")}
NETWORK_MODULES = {"webbrowser", "http", "httplib", "requests", "aiohttp", "urllib", "urllib2", "urllib3", "ftplib", "smtplib",
                   "telnetlib", "socketserver", "xmlrpc", "httpx", "paramiko"}
# Modules ML libraries use for weights and their containers: not reported.
KNOWN_ROOTS = {"torch", "numpy", "sklearn", "scipy", "pandas", "xgboost", "lightgbm", "catboost", "transformers", "tokenizers",
               "sentencepiece", "joblib", "datetime", "decimal", "fractions", "uuid", "pathlib", "argparse", "typing", "enum",
               "omegaconf", "pytorch_lightning", "lightning", "lightning_fabric", "timm", "fastai", "keras", "tensorflow",
               "tf_keras", "spacy", "thinc", "gensim", "statsmodels", "accelerate", "peft", "diffusers", "einops",
               "torchvision", "torchaudio", "torchtext", "sentence_transformers", "huggingface_hub", "safetensors", "onnx",
               "onnxruntime", "ultralytics", "mmcv", "mmengine", "detectron2", "fairseq", "nemo", "dgl", "torch_geometric",
               "flax", "jax", "jaxlib", "optax", "haiku", "pyarrow", "polars", "re", "math", "random", "functools",
               "itertools", "copyreg", "copy_reg", "_codecs", "codecs", "collections", "builtins", "__builtin__", "numbers",
               "array", "struct", "time", "zoneinfo", "pytz", "dateutil", "dataclasses", "abc", "fasttext", "nltk",
               "sympy", "networkx", "PIL", "cv2", "skimage", "category_encoders", "imblearn", "optuna", "mlflow", "wandb"}

_STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"}
_BYTES_OPS = {"SHORT_BINBYTES", "BINBYTES", "BINBYTES8", "BYTEARRAY8"}
READ_LIMIT = 64 * 1024 * 1024


def is_pickle(data: bytes) -> bool:
    return len(data) >= 2 and data[0] == 0x80 and 2 <= data[1] <= 5


def pickle_imports(data: bytes) -> tuple[list[tuple[str, str]], list[bytes], str | None]:
    """(module, name) pairs the pickle stream(s) at the start of data import, byte strings inside them that are
    themselves pickles or zip archives (nested models), and an error if the first stream is malformed."""
    imports: list[tuple[str, str]] = []
    blobs: list[bytes] = []
    stream = io.BytesIO(data[:READ_LIMIT])
    pos, count, error = 0, 0, None
    end = min(len(data), READ_LIMIT)
    while pos < end and count < 8:
        if count and data[pos:pos + 1] != b"\x80":
            break  # legacy PyTorch files continue with raw tensor bytes after their pickles
        strings: list[str] = []
        memo: dict = {}
        stream.seek(pos)
        try:
            for op, arg, _ in pickletools.genops(stream):
                name = op.name
                if name in ("GLOBAL", "INST"):
                    mod, _, attr = str(arg).partition(" ")
                    imports.append((mod, attr))
                elif name == "STACK_GLOBAL":
                    imports.append((strings[-2], strings[-1]) if len(strings) >= 2 else ("?", "?"))
                elif name in _STRING_OPS:
                    strings.append(arg.decode("latin-1") if isinstance(arg, (bytes, bytearray)) else str(arg))
                elif name in _BYTES_OPS and isinstance(arg, (bytes, bytearray)) and (is_pickle(arg) or arg[:4] == ZIP):
                    blobs.append(bytes(arg))
                elif name == "MEMOIZE":
                    memo[len(memo)] = strings[-1] if strings else None
                elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                    memo[arg] = strings[-1] if strings else None
                elif name in ("GET", "BINGET", "LONG_BINGET") and isinstance(memo.get(arg), str):
                    strings.append(memo[arg])
        except Exception as err:  # genops raises on unknown opcodes and on truncated streams
            if count == 0:
                error = f"{err.__class__.__name__}: {str(err)[:80]}"
            break
        pos = stream.tell()
        count += 1
    return imports, blobs, error


def classify(module: str, name: str) -> str:
    """critical | high | known | unknown for one imported global."""
    root = module.split(".", 1)[0]
    if (module, name) in DANGER_PAIRS or root in DANGER_MODULES:
        return "critical"
    if root in ("builtins", "__builtin__") and name in DANGER_BUILTINS:
        return "critical"
    if root in NETWORK_MODULES:
        return "high"
    if root in KNOWN_ROOTS or module == "?":
        return "known"
    return "unknown"


def _judge_pickle(state, rel: str, data: bytes, where: str = "", depth: int = 0) -> None:
    imports, blobs, error = pickle_imports(data)
    shown = f"{rel}{'!/' + where if where else ''}"
    bad = [(m, n, classify(m, n)) for m, n in dict.fromkeys(imports)]
    danger = [x for x in bad if x[2] in ("critical", "high")]
    if danger:
        sev = "critical" if any(x[2] == "critical" for x in danger) else "high"
        names = ", ".join(f"{m}.{n}" for m, n, _ in danger[:5])
        state.add(R_MODEL_CODE, sev, rel, 0, f"{shown} imports {names} when loaded", names, "code")
    unknown = [f"{m}.{n}" for m, n, c in bad if c == "unknown"]
    if unknown and not danger:
        state.add(R_MODEL_IMPORTS, "low", rel, 0, f"{shown} imports {', '.join(unknown[:5])}", ", ".join(unknown[:5]), "code")
    if error and imports:
        sev = "high" if danger or unknown else "medium"
        state.add(R_PACKED, sev, rel, 0, f"{shown}: the pickle stream breaks after {len(imports)} import(s) ({error}); "
                                         "loaders run what comes before the break", error, "code")
    for i, blob in enumerate(blobs[:8]):
        if depth < 3:
            if blob[:4] == ZIP:
                _judge_zip(state, rel, blob, f"{where or 'pickle'}#bytes{i}", depth + 1)
            else:
                _judge_pickle(state, rel, blob, f"{where or 'pickle'}#bytes{i}", depth + 1)


def _judge_zip(state, rel: str, data_or_path, where: str = "", depth: int = 0) -> None:
    """PyTorch, NumPy .npz and Keras archives: the pickles and configs inside."""
    try:
        source = io.BytesIO(data_or_path) if isinstance(data_or_path, (bytes, bytearray)) else data_or_path
        with zipfile.ZipFile(source) as z:
            for info in z.infolist()[:5000]:
                name = info.filename
                low = name.lower()
                if info.file_size > READ_LIMIT:
                    continue
                inner = f"{where + '!/' if where else ''}{name}"
                if low.endswith((".pkl", ".pickle")) or posixpath.basename(low) == "data.pkl":
                    _judge_pickle(state, rel, z.read(info), inner, depth)
                elif low.endswith(".npy"):
                    _judge_npy(state, rel, z.read(info), inner)
                elif posixpath.basename(low) == "config.json" and rel.lower().endswith(".keras"):
                    _judge_keras_config(state, rel, z.read(info).decode("utf-8", "replace"), inner)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, RuntimeError) as err:
        state.add(R_PACKED, "medium", rel, 0, f"{rel}: the archive could not be read ({err.__class__.__name__})", "", "code")


def _judge_npy(state, rel: str, data: bytes, where: str = "") -> None:
    if data[:6] != NUMPY or len(data) < 10:
        return
    major = data[6]
    if major == 1:
        (hlen,) = struct.unpack_from("<H", data, 8)
        start = 10 + hlen
    else:
        (hlen,) = struct.unpack_from("<I", data, 8)
        start = 12 + hlen
    header = data[10 if major == 1 else 12:start].decode("latin-1", "replace")
    if re.search(r"'descr'\s*:\s*'\|O'", header):  # object arrays are stored as a pickle
        _judge_pickle(state, rel, data[start:], where or "array")


_KERAS_DANGER_TEXT = re.compile(r"enable_unsafe_deserialization|\bget_file\b")


def _judge_keras_config(state, rel: str, text: str, where: str = "config.json") -> None:
    try:
        config = json.loads(text)
    except ValueError:
        return
    stack = [config]
    lambdas, modules = [], []
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("class_name") == "Lambda":
                fn = (node.get("config") or {}).get("function")
                lambdas.append(fn)
            module = node.get("module")
            if isinstance(module, str):
                name = str(node.get("class_name") or node.get("registered_name") or "")
                modules.append((module, name))
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    for fn in lambdas:
        code = isinstance(fn, (list, tuple)) or (isinstance(fn, dict) and (fn.get("class_name") == "__lambda__"
                                                                          or "code" in (fn.get("config") or {})))
        state.add(R_KERAS_CODE, "high" if code else "medium", rel, 0,
                  f"{rel}!/{where}: Lambda layer " + ("with Python bytecode" if code else f"calling {str(fn)[:60]}"),
                  str(fn)[:120], "code")
    for module, name in modules:
        verdict = classify(module, name)
        if verdict in ("critical", "high"):
            state.add(R_MODEL_CODE, "critical", rel, 0, f"{rel}!/{where} names {module}.{name} to run when loaded "
                                                        "(CVE-2025-1550)", f"{module}.{name}", "code")
    m = _KERAS_DANGER_TEXT.search(text)
    if m:
        state.add(R_MODEL_CODE, "critical" if "unsafe" in m.group() else "high", rel, 0,
                  f"{rel}!/{where} calls {m.group()} while loading (CVE-2025-9906, CVE-2025-8747)", m.group(), "code")


_H5_LAMBDA = re.compile(rb'"class_name":\s*"Lambda"')
_H5_MODULE = re.compile(rb'"module":\s*"(os|subprocess|builtins|posix|nt|sys|importlib|runpy|socket)"')


def _judge_h5(state, rel: str, data: bytes) -> None:
    head = data[:READ_LIMIT]
    m = _H5_MODULE.search(head)
    if m:
        state.add(R_MODEL_CODE, "critical", rel, 0, f"{rel}: the Keras config names the {m.group(1).decode()} module",
                  m.group().decode("latin-1"), "code")
    if _H5_LAMBDA.search(head):
        state.add(R_KERAS_CODE, "high", rel, 0, f"{rel}: Keras HDF5 model with a Lambda layer (loading .h5 ignores "
                                                "safe_mode, CVE-2025-9905)", "Lambda", "code")


_GGUF_FIXED = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}


def gguf_templates(data: bytes) -> tuple[dict[str, str], str | None]:
    """The chat templates in a GGUF file's metadata, and an error if the metadata could not be read to the end."""
    if data[:4] != GGUF or len(data) < 24:
        return {}, "not a GGUF file"
    (version,) = struct.unpack_from("<I", data, 4)
    if version == 1:
        _, n_kv = struct.unpack_from("<II", data, 8)
        pos, len_fmt = 16, "<I"
    else:
        _, n_kv = struct.unpack_from("<QQ", data, 8)
        pos, len_fmt = 24, "<Q"
    width = struct.calcsize(len_fmt)
    out: dict[str, str] = {}

    def read_str(at: int) -> tuple[str, int]:
        (n,) = struct.unpack_from(len_fmt, data, at)
        at += width
        if n > len(data) - at:
            raise ValueError("string runs past the data read")
        return data[at:at + n].decode("utf-8", "replace"), at + n

    try:
        for _ in range(min(n_kv, 1_000_000)):
            key, pos = read_str(pos)
            (vtype,) = struct.unpack_from("<I", data, pos)
            pos += 4
            if vtype == 8:
                value, pos = read_str(pos)
                if key.startswith("tokenizer.chat_template"):
                    out[key] = value
            elif vtype == 9:
                (itype,) = struct.unpack_from("<I", data, pos)
                (count,) = struct.unpack_from(len_fmt, data, pos + 4)
                pos += 4 + width
                if itype == 8:
                    for _ in range(count):
                        (n,) = struct.unpack_from(len_fmt, data, pos)
                        pos += width + n
                elif itype in _GGUF_FIXED:
                    pos += count * _GGUF_FIXED[itype]
                else:
                    raise ValueError(f"array of type {itype}")
            elif vtype in _GGUF_FIXED:
                pos += _GGUF_FIXED[vtype]
            else:
                raise ValueError(f"value type {vtype}")
            if pos > len(data):
                raise ValueError("metadata runs past the data read")
    except (struct.error, ValueError) as err:
        return out, str(err)[:80]
    return out, None


SSTI = re.compile(r"__(?:globals|builtins|import|class|subclasses|mro|base|bases|init|getattribute|dict|code|func|self)__"
                  r"|\bos\s*\.\s*(?:popen|system)|\bpopen\s*\(|\bsubprocess\b|\beval\s*\(|\bexec\s*\("
                  r"|\b(?:cycler|joiner|namespace|lipsum|range|dict|request|config|self)\s*\.\s*_"
                  r"|\|\s*attr\s*\(\s*['\"]_|\\x5f\\x5f|\[\s*['\"]_", re.I)


def _judge_gguf(state, rel: str, data: bytes, partial: bool = False) -> None:
    from .outputs import ADDRESSED, CONCEAL, OVERRIDE

    templates, error = gguf_templates(data)
    for key, template in templates.items():
        m = SSTI.search(template)
        if m:
            state.add(R_TEMPLATE, "critical", rel, 0, f"{rel}: {key} reaches Python objects from the template",
                      template[max(0, m.start() - 40):m.end() + 60], "code")
            continue
        m = OVERRIDE.search(template) or CONCEAL.search(template) or ADDRESSED.search(template)
        if m:
            state.add(R_TEMPLATE, "medium", rel, 0, f"{rel}: {key} adds instructions to every conversation",
                      template[max(0, m.start() - 40):m.end() + 60], "code")
    if error and not templates and not partial:
        state.incomplete.append(f"{rel}: GGUF metadata could not be read ({error})")


def _decompress(data: bytes) -> bytes | None:
    try:
        if data[:2] == b"\x1f\x8b":
            return gzip.decompress(data[:READ_LIMIT])[:READ_LIMIT]
        if data[:3] == b"BZh":
            return bz2.decompress(data[:READ_LIMIT])[:READ_LIMIT]
        if data[:6] == b"\xfd7zXZ\x00" or data[:3] == b"\x5d\x00\x00":
            return lzma.decompress(data[:READ_LIMIT])[:READ_LIMIT]
        if data[:1] == b"\x78" and data[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda"):
            return zlib.decompressobj().decompress(data[:READ_LIMIT], READ_LIMIT)
    except (OSError, EOFError, ValueError, lzma.LZMAError, zlib.error):
        return None
    return None


def is_model_name(rel: str) -> bool:
    return rel.lower().endswith(MODEL_EXT)


def check(state, f) -> None:
    """Judge one collected file if it is a model, or a model repository's config.json."""
    low = f.rel.lower()
    name = posixpath.basename(low)
    if f.text is not None and name in ("config.json", "tokenizer_config.json") and '"auto_map"' in f.text:
        _remote_code(state, f)
    data = f.data
    if not data or not (low.endswith(MODEL_EXT) or (is_pickle(data) and not posixpath.splitext(low)[1])):
        return  # judged by magic bytes below, whatever the text decoder made of them
    if data[:6] == SEVEN_Z and low.endswith(MODEL_EXT):
        state.add(R_PACKED, "high", f.rel, 0, f"{f.rel} is a 7z archive named like a model file (PyTorch uses zip; "
                                              "nullifAI packed its models with 7z)", "7z", "code")
        return
    if data[:4] == ZIP and low.endswith(MODEL_EXT):
        _judge_zip(state, f.rel, data)
    elif is_pickle(data) and (low.endswith(MODEL_EXT) or not posixpath.splitext(low)[1]):
        _judge_pickle(state, f.rel, data)
    elif low.endswith(PICKLE_EXT):
        inner = _decompress(data)
        if inner is not None and is_pickle(inner):
            _judge_pickle(state, f.rel, inner, "decompressed")
        elif data[:1] in (b"(", b"c", b"}", b"]", b"\x80"):
            _judge_pickle(state, f.rel, data)  # protocol 0 and 1 pickles start with an opcode, not a header
    elif data[:6] == NUMPY:
        _judge_npy(state, f.rel, data)
    elif data[:4] == GGUF:
        _judge_gguf(state, f.rel, data)
    elif data[:8] == HDF5 and low.endswith((".h5", ".hdf5", ".keras")):
        _judge_h5(state, f.rel, data)


def check_large(state, rel: str, path: str) -> bool:
    """Judge a model file too large to read whole: only the parts that can run code (the pickles in a zip, the start
    of a pickle or HDF5 file, GGUF metadata). True if the file was handled."""
    low = rel.lower()
    if not low.endswith(MODEL_EXT):
        return False
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
            fh.seek(0)
            if head[:4] == ZIP:
                _judge_zip(state, rel, path)
            elif head[:6] == SEVEN_Z:
                state.add(R_PACKED, "high", rel, 0, f"{rel} is a 7z archive named like a model file", "7z", "code")
            elif head[:4] == GGUF:
                _judge_gguf(state, rel, fh.read(4 * READ_LIMIT), partial=True)
            elif is_pickle(head):
                _judge_pickle(state, rel, fh.read(READ_LIMIT))
            elif head[:8] == HDF5:
                _judge_h5(state, rel, fh.read(READ_LIMIT))
            elif head[:6] == NUMPY:
                _judge_npy(state, rel, fh.read(READ_LIMIT))
            else:
                return False
    except OSError as err:
        state.incomplete.append(f"{rel}: could not read ({err.strerror})")
    return True


def _remote_code(state, f) -> None:
    try:
        config = json.loads(f.text)
    except ValueError:
        return
    auto = config.get("auto_map") if isinstance(config, dict) else None
    if not isinstance(auto, dict):
        return
    refs = []
    for value in auto.values():
        refs.extend(value if isinstance(value, list) else [value])
    local, remote = set(), set()
    for ref in refs:
        if not isinstance(ref, str) or "." not in ref:
            continue
        if "--" in ref:
            remote.add(ref.split("--", 1)[0])
            continue
        module = ref.rsplit(".", 1)[0]
        target = posixpath.join(f.dir, module.replace(".", "/") + ".py") if f.dir else module.replace(".", "/") + ".py"
        local.add(target)
    for target in sorted(local):
        if target in state.files:
            state.mark_autoexec(target, f"imported by transformers when the model is loaded with trust_remote_code "
                                        f"(auto_map in {f.rel})")
    if local or remote:
        sev = "medium" if remote else "low"
        what = ", ".join(sorted(local)[:4] + [f"code from {r}" for r in sorted(remote)[:2]])
        state.add(R_REMOTE_CODE, sev, f.rel, 0, f"loading this model with trust_remote_code runs {what}", what, "config")
