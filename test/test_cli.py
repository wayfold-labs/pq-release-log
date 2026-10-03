#!/usr/bin/env python3
"""Unit tests for dependency-free PQRL encoding and manifest helpers."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli"))

from pqrl import keccak256, manifest  # noqa: E402


class KeccakTests(unittest.TestCase):
    def test_rate_boundary_vectors(self) -> None:
        vectors = {
            135: "29e3704feeca7fb9ba229f0fa04d9b36449cf3ad6e1d85d9cfff3a10df9abc3e",
            136: "3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9",
            271: "3bb611e98ca876adc01436a582979ecfd012389033aca7dbf76dcb424fe02a0c",
        }
        for length, expected in vectors.items():
            with self.subTest(length=length):
                self.assertEqual(keccak256(bytes(length)).hex(), expected)


class ManifestTests(unittest.TestCase):
    def test_requires_https_site_and_skips_hidden_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "index.html").write_text("ok", encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git" / "HEAD").write_text("secret", encoding="utf-8")
            (root / ".nojekyll").write_text("", encoding="utf-8")
            output = root / "manifest.json"
            with self.assertRaisesRegex(ValueError, "requires --site"):
                manifest(str(root), str(output))
            with self.assertRaisesRegex(ValueError, "https"):
                manifest(str(root), str(output), "file:///tmp/site/")
            document = manifest(
                str(root), str(output), "https://example.test/", "2026-10-03T00:00:00Z"
            )
            self.assertEqual(list(document["files"]), ["index.html"])
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), document)


if __name__ == "__main__":
    unittest.main()
