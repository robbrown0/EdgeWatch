from __future__ import annotations

import unittest
from pathlib import Path


class DistributionSanitizationTests(unittest.TestCase):
    def test_public_distribution_contains_no_known_private_literals(self) -> None:
        root = Path(__file__).resolve().parents[1]
        def decode(value: str) -> str:
            return bytes.fromhex(value).decode("utf-8")
        banned = (
            decode("52 6f 62 20 42 72 6f 77 6e"),
            decode("2f 68 6f 6d 65 2f 72 6f 62"),
            decode("72 6f 62 6e 65 74 73 2e 63 6f 6d"),
            decode("50 6f 64 46 6c 69 78"),
            decode("4d 65 64 69 61 20 53 65 72 76 65 72"),
            decode("4f 76 65 72 73 65 65 72"),
            decode("54 6f 77 65 72"),
            decode("31 30 30 2e 31 2e 33 39 2e 35 34"),
            decode("37 36 2e 33 34 2e 31 30 2e 31 35 36"),
            decode("31 35 33 2e 36 36 2e 38 31 2e 35 34"),
            decode("31 30 2e 36 36 2e 36 36 2e"),
            decode("31 39 32 2e 31 36 38 2e 31 2e 31 31 37"),
            decode("31 39 32 2e 31 36 38 2e 31 2e 31 34 34"),
            decode("34 39 31 31 31"),
            decode("34 39 31 31 35"),
            decode("6d 6f 72 61 79 73 2e 6d 69 73 73 69 76 65 30 35"),
            decode("40 69 63 6c 6f 75 64 2e 63 6f 6d"),
        )
        suffixes = {
            ".py", ".js", ".css", ".html", ".md", ".toml", ".yml",
            ".yaml", ".json", ".sh", ".service", ".timer", ".txt",
            ".svg", ".example", "",
        }
        findings: list[str] = []

        current_test = Path(__file__).resolve()
        excluded_parts = {"venv", ".venv", ".git", "__pycache__", ".pytest_cache"}
        for path in root.rglob("*"):
            if excluded_parts.intersection(path.parts):
                continue
            if not path.is_file() or path.resolve() == current_test:
                continue
            if "static/maps" in path.as_posix() or "static/vendor" in path.as_posix():
                continue
            if path.suffix.lower() not in suffixes and path.name not in {"LICENSE", "VERSION"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for literal in banned:
                if literal.lower() in text.lower():
                    findings.append(f"{path.relative_to(root)}: {literal}")

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
