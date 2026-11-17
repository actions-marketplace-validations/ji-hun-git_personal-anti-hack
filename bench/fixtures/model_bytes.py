"""Inert model files for the TrapRepo corpus and the tests, assembled opcode by opcode.

Nothing here imports torch, numpy or keras, and nothing is ever unpickled: each function returns the bytes a real
model file of that kind would have. The malicious ones name a dangerous function (os.system, builtins.exec, ...) with
a harmless argument (an echo of a marker), so a scanner has something real to find and a loader would do nothing worse
than print a line.
"""
from __future__ import annotations

import base64
import io
import json
import struct
import zipfile

MARKER = "echo PAH-CANARY-model"


# --- pickle opcodes ------------------------------------------------------------------------------------------------
def proto(n: int) -> bytes:
    return b"\x80" + bytes([n])


def glob(module: str, name: str) -> bytes:  # GLOBAL (protocols 0-3)
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def ustr(s: str) -> bytes:  # SHORT_BINUNICODE / BINUNICODE
    b = s.encode("utf-8")
    return (b"\x8c" + bytes([len(b)]) + b) if len(b) < 256 else (b"X" + struct.pack("<I", len(b)) + b)


def bstr(s: str) -> bytes:  # BINUNICODE (protocol 2 has no SHORT_BINUNICODE)
    b = s.encode("utf-8")
    return b"X" + struct.pack("<I", len(b)) + b


def num(i: int) -> bytes:
    return b"K" + bytes([i]) if 0 <= i < 256 else b"J" + struct.pack("<i", i)


MARK, TUPLE, EMPTY_TUPLE, TUPLE1, REDUCE, STOP = b"(", b"t", b")", b"\x85", b"R", b"."
EMPTY_DICT, SETITEMS, NEWFALSE, BINPERSID, BUILD, STACK_GLOBAL = b"}", b"u", b"\x89", b"Q", b"b", b"\x93"


def call_global(module: str, name: str, arg: str, protocol: int = 2) -> bytes:
    """A pickle that calls module.name(arg) when loaded."""
    if protocol >= 4:
        return proto(4) + ustr(module) + ustr(name) + STACK_GLOBAL + ustr(arg) + TUPLE1 + REDUCE + STOP
    return proto(2) + glob(module, name) + bstr(arg) + TUPLE1 + REDUCE + STOP


def broken_after(module: str, name: str, arg: str) -> bytes:
    """nullifAI's trick: the payload, then a stream that stops making sense, so scanners that give up on errors miss it."""
    return proto(2) + glob(module, name) + bstr(arg) + TUPLE1 + REDUCE + b"\x00\xffgarbage"


def state_dict_pickle() -> bytes:
    """What torch.save(model.state_dict()) writes as data.pkl: an OrderedDict of tensors rebuilt from storages."""
    storage = MARK + bstr("storage") + glob("torch", "FloatStorage") + bstr("0") + bstr("cpu") + num(4) + TUPLE + BINPERSID
    tensor = (glob("torch._utils", "_rebuild_tensor_v2") + MARK + storage + num(0) + MARK + num(2) + num(2) + TUPLE
              + MARK + num(2) + num(1) + TUPLE + NEWFALSE + glob("collections", "OrderedDict") + EMPTY_TUPLE + REDUCE
              + TUPLE + REDUCE)
    return proto(2) + glob("collections", "OrderedDict") + EMPTY_TUPLE + REDUCE + MARK + bstr("linear.weight") + tensor + SETITEMS + STOP


def sklearn_pickle() -> bytes:
    """A fitted scikit-learn estimator: its class, rebuilt with numpy arrays for the coefficients."""
    array = (glob("numpy.core.multiarray", "_reconstruct") + MARK + glob("numpy", "ndarray") + MARK + num(0) + TUPLE
             + b"C" + bytes([1]) + b"b" + TUPLE + REDUCE)
    state = EMPTY_DICT + MARK + bstr("coef_") + array + bstr("C") + num(1) + SETITEMS
    return (proto(2) + glob("copy_reg", "_reconstructor") + MARK + glob("sklearn.linear_model._logistic", "LogisticRegression")
            + glob("__builtin__", "object") + b"N" + TUPLE + REDUCE + state + BUILD + STOP)


def torch_zip(pickle_bytes: bytes, prefix: str = "archive") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(f"{prefix}/data.pkl", pickle_bytes)
        z.writestr(f"{prefix}/byteorder", "little")
        z.writestr(f"{prefix}/data/0", bytes(16))
        z.writestr(f"{prefix}/version", "3\n")
    return buf.getvalue()


def keras_archive(layers: list[dict]) -> bytes:
    config = {"module": "keras", "class_name": "Sequential", "config": {"name": "sequential", "layers": layers},
              "registered_name": None}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("metadata.json", json.dumps({"keras_version": "3.5.0", "date_saved": "2026-11-01@00:00:00"}))
        z.writestr("config.json", json.dumps(config))
        z.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n" + bytes(56))
    return buf.getvalue()


def dense(units: int, name: str) -> dict:
    return {"module": "keras.layers", "class_name": "Dense", "config": {"name": name, "units": units, "activation": "relu"},
            "registered_name": None}


def lambda_layer() -> dict:
    code = base64.b64encode(b"\xe3\x00\x00\x00PAH-CANARY inert bytecode stand-in").decode()
    return {"module": "keras.layers", "class_name": "Lambda",
            "config": {"name": "lambda", "function": {"class_name": "__lambda__", "config": {"code": code, "defaults": None,
                                                                                               "closure": None}}},
            "registered_name": None}


def gguf(template: str) -> bytes:
    def s(text: str) -> bytes:
        b = text.encode("utf-8")
        return struct.pack("<Q", len(b)) + b

    kvs = [("general.architecture", "llama"), ("general.name", "tiny-test"), ("tokenizer.chat_template", template)]
    out = b"GGUF" + struct.pack("<I", 3) + struct.pack("<QQ", 0, len(kvs) + 1)
    out += s("tokenizer.ggml.tokens") + struct.pack("<I", 9) + struct.pack("<I", 8) + struct.pack("<Q", 3)
    out += s("<s>") + s("</s>") + s("hello")
    for key, value in kvs:
        out += s(key) + struct.pack("<I", 8) + s(value)
    return out + bytes(32)


CHATML = ("{% for message in messages %}{{'<|im_start|>' + message['role'] + '\\n' + message['content'] + '<|im_end|>' + "
          "'\\n'}}{% endfor %}{% if add_generation_prompt %}{{ '<|im_start|>assistant\\n' }}{% endif %}")
SSTI_TEMPLATE = ("{% for message in messages %}{{ message['content'] }}{% endfor %}"
                 "{{ cycler.__init__.__globals__.os.popen('" + MARKER + "').read() }}")
SEVEN_Z = b"7z\xbc\xaf\x27\x1c\x00\x04" + bytes(range(64)) + call_global("os", "system", MARKER)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
