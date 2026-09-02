"""The dual axis risk scoring model.

There is no CVSS equivalent for cryptographic weakness. MITRE's own CWSS
documentation states the consequence directly: automated tools each perform
their own custom scoring, so multiple tools produce inconsistent scores.

So this model is assembled from published work rather than invented:

===============  =========================================================
Borrowed         From
===============  =========================================================
Structure        MITRE CWSS. Separate base finding, attack surface and
                 environmental groups rather than one flat number.
Mechanics        Qualys SSL Labs rating guide. Weighted inputs, numeric to
                 band mapping, and cap rules where one disqualifying defect
                 overrides an otherwise acceptable score.
Quantum timeline NIST IR 8547 ipd. Published deprecation dates rather than
                 an invented urgency value.
Algorithm status NIST SP 800-131A Rev 2, FIPS 180-4, 197, 203, 204, 205.
Taxonomy         CWE-310, CWE-326, CWE-327.
===============  =========================================================

The formula::

    classical = clamp(base_classical + param_penalty, 0, 10) * w_context * w_exposure
    quantum   = base_quantum                                 * w_context * w_exposure
    severity  = band(max(classical, quantum))    subject to the cap rules

**The two axes are never averaged.** Averaging destroys exactly the signal this
project exists to surface: RSA-2048 is classically acceptable today and
disallowed by NIST after 2035. A blended score renders that finding
unremarkable, which is the failure mode ECDAT was built to correct.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass
from typing import Optional

from app.knowledge.loader import KnowledgeBase, load
from app.models.schemas import RawFinding

#: Minimum key sizes below which a parameter penalty applies, per SP 800-131A.
_KEY_FLOORS: dict[str, int] = {
    "RSA": 2048,
    "DSA": 2048,
    "DH": 2048,
    "ECDSA": 224,
    "ECDH": 224,
}

#: Findings below this confidence are reported but never escalated.
_MANUAL_REVIEW_BELOW = 0.70


@dataclass
class Score:
    """The scored result for one finding."""

    classical: float
    quantum: float
    severity: str
    pqc_vulnerable: bool
    capped_by: Optional[str] = None
    deprecated_after: Optional[int] = None
    disallowed_after: Optional[int] = None
    standard_refs: str = ""
    cwe: Optional[str] = None
    requires_manual_review: bool = False

    @property
    def years_remaining(self) -> Optional[int]:
        """Years until NIST disallows this algorithm, or None if not applicable."""
        if self.disallowed_after is None:
            return None
        return max(0, self.disallowed_after - dt.date.today().year)


class RiskEngine:
    """Scores a :class:`RawFinding` against the knowledge base."""

    def __init__(self, kb: Optional[KnowledgeBase] = None) -> None:
        """Bind the engine to a knowledge base.

        Args:
            kb: Override for testing. Defaults to the cached production
                knowledge base, so a test can score against a custom policy
                without touching the YAML on disk.
        """
        self.kb = kb or load()
        self.policy = self.kb.policy

    # ------------------------------------------------------------------ public

    def score(self, finding: RawFinding) -> Score:
        """Score one finding on both axes.

        The order of operations is deliberate and load-bearing:

        1. Look up the algorithm's base risk on each axis.
        2. Add a parameter penalty for an undersized key.
        3. Apply context and exposure weights, independently per axis.
        4. Band on the *maximum*, never the mean.
        5. Apply cap rules, which override the arithmetic entirely.
        6. Demote anything below the confidence floor.

        Step 4 is the one that matters most. Averaging 3.0 and 9.5 gives 6.25,
        which bands as MEDIUM and makes RSA-2048 disappear into the noise. That
        is the exact finding this tool exists to surface.

        Returns:
            Score: both axes, the banded severity, whether a cap fired, and the
            NIST transition dates where they apply.
        """
        entry = self.kb.algorithm(finding.algorithm)

        w_context = self.policy.context_weights.get(finding.context, 1.0)
        w_exposure = self.policy.exposure_weights.get(finding.exposure, 1.0)

        penalty = self._parameter_penalty(finding)
        classical = _clamp(entry.base_classical + penalty, 0.0, 10.0) * w_context * w_exposure
        quantum = entry.base_quantum * w_context * w_exposure

        classical = _clamp(classical, 0.0, 10.0)
        quantum = _clamp(quantum, 0.0, 10.0)

        severity = self._band(max(classical, quantum))
        capped_by: Optional[str] = None
        manual_review = finding.confidence < _MANUAL_REVIEW_BELOW

        # Cap rules, applied after the arithmetic. Some defects are
        # disqualifying regardless of context, and a weighted average must not
        # be allowed to argue them down.
        escalation = self._escalation_reason(finding, entry)
        if escalation and finding.confidence >= self.policy.min_confidence_for_critical:
            severity = "CRITICAL"
            capped_by = escalation

        # The inverse cap: a finding with nothing on either axis cannot be
        # inflated into a warning by weighting alone.
        if classical == 0.0 and quantum == 0.0:
            severity = "LOW"
            capped_by = capped_by or "clean-asset-floor"

        # A low confidence finding is reported honestly rather than guessed at.
        # This is the implementation of the "requires manual review" behaviour.
        if manual_review and severity == "CRITICAL":
            severity = "HIGH"
            capped_by = "confidence-below-threshold"

        return Score(
            classical=round(classical, 2),
            quantum=round(quantum, 2),
            severity=severity,
            pqc_vulnerable=entry.is_quantum_vulnerable,
            capped_by=capped_by,
            deprecated_after=entry.deprecated_after,
            disallowed_after=entry.disallowed_after,
            standard_refs=", ".join(entry.refs),
            cwe=entry.cwe,
            requires_manual_review=manual_review,
        )

    # ----------------------------------------------------------------- helpers

    def _parameter_penalty(self, finding: RawFinding) -> float:
        """Extra classical risk from an undersized key.

        A 1024 bit RSA key is not merely "RSA", it is RSA below the floor that
        SP 800-131A sets, so it carries more classical risk than the algorithm
        row alone describes.
        """
        floor = _KEY_FLOORS.get(finding.algorithm)
        if floor is None or finding.key_size is None:
            return 0.0
        if finding.key_size >= floor:
            return 0.0
        # Half the floor or smaller is treated as fully broken.
        if finding.key_size <= floor // 2:
            return 7.0
        return 5.0

    def _escalation_reason(self, finding: RawFinding, entry) -> Optional[str]:
        """Return the cap rule that forces CRITICAL, if any."""
        if finding.algorithm in self.policy.critical_algorithms and finding.context == "security":
            return f"broken-algorithm:{finding.algorithm}"
        if finding.rule_id in self.policy.critical_rules:
            return f"cap-rule:{finding.rule_id}"
        if finding.algorithm == "HARDCODED-SECRET" and finding.context != "test":
            return "hardcoded-key-material"
        if finding.algorithm == "CERT-VERIFY-DISABLED":
            return "certificate-verification-disabled"
        return None

    def _band(self, value: float) -> str:
        """Map a numeric score to a severity label."""
        bands = self.policy.bands
        for label in ("CRITICAL", "HIGH", "MEDIUM"):
            if value >= bands[label]:
                return label
        return "LOW"


def dedupe_key(finding: RawFinding) -> str:
    """Stable identity for a finding.

    Deliberately excludes anything that changes between runs, so re-scanning an
    unchanged target produces an identical inventory rather than duplicates.
    """
    parts = [
        finding.asset_kind,
        finding.locator,
        finding.algorithm,
        finding.rule_id,
        str(finding.line_no or ""),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _clamp(value: float, low: float, high: float) -> float:
    """Constrain a value to a range.

    Applied after weighting so that internet exposure, which multiplies by
    1.15, cannot push an already-maximal score above 10.
    """
    return max(low, min(high, value))
