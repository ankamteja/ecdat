"""Source code discovery.

Three passes run over every candidate file:

1. **Python AST pass.** For ``.py`` files the source is parsed with the standard
   library ``ast`` module and walked for real call nodes. This is genuine
   syntax tree analysis, not text matching: it resolves ``hashlib.md5(...)``
   through the call node and reads the literal argument of ``key_size=1024``
   from the keyword node.
2. **Pattern pass.** Rules from ``rules.yaml`` applied per line, for every
   supported language. This is what covers Java and JavaScript in the
   prototype.
3. **Entropy pass.** Shannon entropy over quoted literals, for key material
   that no signature would catch.

Scope honesty: full multi language AST coverage is the job of Semgrep or
tree-sitter and is roadmap. The prototype does real AST work for Python and
pattern work elsewhere, and the ``analysis`` field on each finding records
which pass produced it so no report overstates the method used.
"""

from __future__ import annotations

import ast
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.knowledge.loader import load
from app.models.schemas import RawFinding
from app.scanners import pubkeys, secrets
from app.scanners.base import Scanner, ScanError, ScanJob

# Python call targets that map directly to an algorithm.
_PY_HASH_CALLS = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "new": None,  # hashlib.new("md5"), resolved from the argument
}


class CodeScanner(Scanner):
    """Walks a directory tree and reports cryptographic usage."""

    kind = "code"

    def __init__(self) -> None:
        """Load the knowledge base once, not per file.

        ``load()`` is cached, so this is cheap, but holding the reference keeps
        the hot path in :meth:`run` free of lookups.
        """
        self.kb = load()
        self.cfg = self.kb.entropy

    # ---------------------------------------------------------------- validate

    def validate(self, job: ScanJob) -> None:
        """Confirm the target exists and is readable.

        Raises:
            ScanError: if the path is missing or is neither a file nor a
                directory.
        """
        path = Path(job.target).expanduser()
        if not path.exists():
            raise ScanError(f"Target path does not exist: {job.target}")
        if not path.is_dir() and not path.is_file():
            raise ScanError(f"Target is neither a file nor a directory: {job.target}")

    # --------------------------------------------------------------------- run

    def run(self, job: ScanJob) -> Iterator[RawFinding]:
        """Walk the target and yield every cryptographic observation.

        Three passes run over each candidate file. Findings stream rather than
        accumulating, so memory stays flat regardless of repository size.

        Yields:
            RawFinding: one per observation, tagged in ``asset_meta`` with the
            pass that produced it.
        """
        if job.fixture:
            yield from self.fixture_findings(job)
            return

        root = Path(job.target).expanduser().resolve()
        for file_path in self._candidate_files(root):
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel = str(file_path.relative_to(root)) if root.is_dir() else file_path.name
            # Context is judged on the path *inside* the scan target, never the
            # absolute path. Otherwise a repository that happens to live under
            # a directory called "samples" or "test" has every finding in it
            # silently downweighted to test context, which is both wrong and
            # invisible: the findings still appear, just at the wrong severity.
            context = self._context_for(Path(rel))

            if file_path.suffix == ".py":
                yield from self._python_ast_pass(text, rel, context)
            yield from self._pattern_pass(text, rel, file_path.suffix.lstrip("."), context)
            yield from self._entropy_pass(text, rel, context)
            yield from self._embedded_key_pass(text, rel, context)

    # ----------------------------------------------------------- file selection

    def _candidate_files(self, root: Path) -> Iterator[Path]:
        """Yield files worth reading, skipping vendor and dependency trees."""
        extensions = {f".{e}" for e in self.cfg["scan_extensions"]}
        skip = set(self.cfg["skip_dirs"])

        if root.is_file():
            if root.suffix in extensions:
                yield root
            return

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")]
            for name in filenames:
                candidate = Path(dirpath) / name
                if candidate.suffix not in extensions:
                    continue
                try:
                    if candidate.stat().st_size > settings.max_file_bytes:
                        continue
                except OSError:
                    continue
                yield candidate

    def _context_for(self, path: Path) -> str:
        """Classify a file as test or security context from its path.

        This is what stops a fixture using MD5 from paging somebody at two in
        the morning, and it is the concrete form of the CWSS environmental
        metric group.
        """
        markers = set(self.cfg["test_dir_markers"])
        parts = {p.lower() for p in path.parts}
        stem = path.stem.lower()
        if parts & markers or stem.startswith("test_") or stem.endswith("_test"):
            return "test"
        return "security"

    # ------------------------------------------------------------- AST pass

    def _python_ast_pass(self, text: str, rel: str, context: str) -> Iterator[RawFinding]:
        """Real syntax tree analysis for Python sources."""
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            target = _dotted_name(node.func)
            if target is None:
                continue

            algorithm = self._algorithm_for_call(target, node)
            if algorithm:
                yield RawFinding(
                    rule_id="ECDAT-AST-PY",
                    algorithm=algorithm,
                    locator=rel,
                    asset_kind="code",
                    primitive=self.kb.algorithm(algorithm).primitive,
                    context=context,
                    exposure="internal",
                    file_path=rel,
                    line_no=node.lineno,
                    evidence_masked=f"{target}(...)",
                    confidence=0.95,
                    asset_meta={"analysis": "python-ast"},
                )

            # RSA key size read from the keyword argument node, not from text.
            key_size = _keyword_int(node, "key_size")
            if key_size is not None and "generate_private_key" in target:
                yield RawFinding(
                    rule_id="ECDAT-006",
                    algorithm="RSA",
                    locator=rel,
                    asset_kind="code",
                    primitive="public-key",
                    key_size=key_size,
                    context=context,
                    exposure="internal",
                    file_path=rel,
                    line_no=node.lineno,
                    evidence_masked=f"key_size={key_size}",
                    confidence=0.95,
                    asset_meta={"analysis": "python-ast"},
                )

    def _algorithm_for_call(self, target: str, node: ast.Call) -> Optional[str]:
        """Map a dotted call target to an algorithm name."""
        tail = target.rsplit(".", 1)[-1]
        if target.startswith("hashlib."):
            if tail in ("md5", "sha1"):
                return "MD5" if tail == "md5" else "SHA-1"
            if tail == "new" and node.args:
                literal = _string_literal(node.args[0])
                if literal:
                    return {"md5": "MD5", "sha1": "SHA-1"}.get(literal.lower())
        return None

    # --------------------------------------------------------- pattern pass

    def _pattern_pass(self, text: str, rel: str, ext: str, context: str) -> Iterator[RawFinding]:
        """Apply the rule catalogue line by line.

        This is what covers Java and JavaScript, where no AST pass exists yet.
        At most one finding is emitted per rule per line, so a line matching
        several patterns of the same rule is reported once rather than four
        times.
        """
        lines = text.splitlines()
        for rule in self.kb.rules:
            if rule.entropy_rule or (rule.langs and ext not in rule.langs):
                continue
            for number, line in enumerate(lines, start=1):
                for pattern in rule.compiled:
                    match = pattern.search(line)
                    if not match:
                        continue
                    key_size = None
                    if rule.key_size_from_match:
                        for group in match.groups():
                            if group and group.isdigit():
                                key_size = int(group)
                                break
                    yield RawFinding(
                        rule_id=rule.id,
                        algorithm=rule.algorithm,
                        locator=rel,
                        asset_kind="code",
                        primitive=self.kb.algorithm(rule.algorithm).primitive,
                        key_size=key_size,
                        context=context,
                        exposure="internal",
                        file_path=rel,
                        line_no=number,
                        evidence_masked=_safe_excerpt(line, rule.group),
                        confidence=rule.confidence,
                        asset_meta={"analysis": "pattern", "rule": rule.name},
                    )
                    break  # one finding per rule per line

    # --------------------------------------------------------- entropy pass

    def _entropy_pass(self, text: str, rel: str, context: str) -> Iterator[RawFinding]:
        """Report high-entropy string literals as possible key material.

        Catches secrets that match no signature. Deduplicated by fingerprint
        within a file, so the same constant referenced repeatedly is one
        finding.

        Emitted at the minimum confidence, because entropy is suggestive rather
        than conclusive: a finding from this pass can never reach CRITICAL on
        its own.
        """
        min_len = int(self.cfg["min_length"])
        min_entropy = float(self.cfg["min_entropy"])
        allowlist = list(self.cfg["allowlist_patterns"])
        seen: set[str] = set()

        for number, line in enumerate(text.splitlines(), start=1):
            for literal in secrets.candidate_literals(line):
                if len(literal) < min_len or secrets.is_allowlisted(literal, allowlist):
                    continue
                if secrets.looks_like_prose(literal):
                    continue
                entropy = secrets.shannon_entropy(literal)
                if entropy < min_entropy:
                    continue
                digest = secrets.fingerprint(literal)
                if digest in seen:
                    continue
                seen.add(digest)
                yield RawFinding(
                    rule_id="ECDAT-018",
                    algorithm="HARDCODED-SECRET",
                    locator=rel,
                    asset_kind="code",
                    primitive="key-material",
                    context=context,
                    exposure="internal",
                    file_path=rel,
                    line_no=number,
                    # The literal never leaves this call.
                    evidence_masked=secrets.mask(literal),
                    entropy=round(entropy, 2),
                    fingerprint=digest,
                    confidence=float(self.cfg["confidence"]),
                    asset_meta={"analysis": "entropy"},
                )

    # --------------------------------------------------- embedded key pass

    def _embedded_key_pass(self, text: str, rel: str, context: str) -> Iterator[RawFinding]:
        """Report PEM public keys pinned inside source files.

        The fingerprint emitted here is the same SubjectPublicKeyInfo digest the
        certificate scanner produces, which is what lets the correlation engine
        state that a key in a repository is the key in a certificate.
        """
        for key in pubkeys.find_embedded_keys(text):
            yield RawFinding(
                rule_id="ECDAT-EMBEDDED-KEY",
                algorithm=key.algorithm,
                locator=rel,
                asset_kind="code",
                primitive=self.kb.algorithm(key.algorithm).primitive,
                key_size=key.key_size,
                context=context,
                exposure="internal",
                file_path=rel,
                line_no=key.line_no,
                fingerprint=key.fingerprint,
                evidence_masked=f"embedded {key.kind}, {key.algorithm} {key.key_size or ''}".strip(),
                confidence=0.95,
                asset_meta={"analysis": "embedded-pem", "spki_sha256": key.fingerprint},
            )

    # ------------------------------------------------------------- fixtures

    def fixture_findings(self, job: ScanJob) -> Iterator[RawFinding]:
        """Canned findings for when the scanner cannot run.

        Marked ``analysis: fixture`` so the interface can label it and nobody
        mistakes a demonstration for a real scan.
        """
        yield RawFinding(
            rule_id="ECDAT-001",
            algorithm="MD5",
            locator="fixture/app.py",
            asset_kind="code",
            primitive="hash",
            file_path="fixture/app.py",
            line_no=12,
            evidence_masked="hashlib.md5(...)",
            confidence=0.95,
            asset_meta={"analysis": "fixture"},
        )


# --------------------------------------------------------------------- helpers


def _dotted_name(node: ast.AST) -> Optional[str]:
    """Reconstruct a dotted call target such as ``hashlib.md5``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _string_literal(node: ast.AST) -> Optional[str]:
    """Return the value of a string constant node, or None if it is not one.

    Used to resolve ``hashlib.new("md5")``, where the algorithm is an argument
    rather than part of the call target.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword_int(call: ast.Call, name: str) -> Optional[int]:
    """Read an integer keyword argument from a call node.

    This is how ``key_size=1024`` is recovered structurally rather than by
    matching text, so a reformatted call or one split across lines still
    reports the right key size.
    """
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant):
            if isinstance(keyword.value.value, int):
                return keyword.value.value
    return None


def _safe_excerpt(line: str, group: str) -> str:
    """Return a short excerpt, masked when the rule is a secret rule."""
    stripped = line.strip()
    if group == "secret":
        return "[redacted secret literal]"
    return stripped[:120]
