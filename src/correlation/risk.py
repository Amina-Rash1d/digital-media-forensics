from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from src.correlation.evidence import EvidenceItem, EvidenceState


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"


# ---------------------------------------------------------------------------
# Risk weights
# ---------------------------------------------------------------------------

# These weights represent evidentiary significance.
# They are NOT probabilities and do not represent malware likelihood.

STATE_WEIGHTS = {
    EvidenceState.OBSERVATION: 0,
    EvidenceState.CANDIDATE: 1,
    EvidenceState.EXTRACTED: 2,
    EvidenceState.PLAUSIBLE: 2,
    EvidenceState.VERIFIED: 4,
    EvidenceState.INCONCLUSIVE: 0,
}


CATEGORY_WEIGHTS = {
    "extraction_attempt": 0,
    "payload_accessibility": 0,
    "file_type": 0,
    "magic_signature": 0,
    "printable_strings": 0,
    "metadata": 0,
    "archive_container": 1,
    "nested_content": 1,
    "yara_match": 2,
    "possible_embedded_file": 2,
    "possible_text_interpretation": 1,
}


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

@dataclass
class RiskContribution:

    finding_id: str
    category: str
    evidence_state: str
    points: int
    reason: str


@dataclass
class RiskResult:

    score: int = 0

    risk_level: str = RISK_LOW

    confidence: str = "LOW"

    contributions: list[RiskContribution] = field(
        default_factory=list
    )

    contributing_findings: list[str] = field(
        default_factory=list
    )

    rationale: list[str] = field(
        default_factory=list
    )

    warnings: list[str] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _state_weight(
    evidence_state: EvidenceState,
) -> int:

    return STATE_WEIGHTS.get(
        evidence_state,
        0,
    )


def _category_weight(
    category: str,
) -> int:

    return CATEGORY_WEIGHTS.get(
        category,
        0,
    )


def _risk_level(
    score: int,
) -> str:

    if score >= 7:
        return RISK_HIGH

    if score >= 3:
        return RISK_MEDIUM

    return RISK_LOW


def _confidence(
    evidence: list[EvidenceItem],
    score: int,
) -> str:

    verified = sum(
        1
        for item in evidence
        if item.evidence_state == EvidenceState.VERIFIED
    )

    plausible = sum(
        1
        for item in evidence
        if item.evidence_state == EvidenceState.PLAUSIBLE
    )

    extracted = sum(
        1
        for item in evidence
        if item.evidence_state == EvidenceState.EXTRACTED
    )

    if verified >= 2:
        return "HIGH"

    if verified >= 1:
        return "HIGH"

    if plausible > 0 or extracted > 0:
        return "MEDIUM"

    if score >= 3:
        return "MEDIUM"

    return "LOW"


def _corroborated_finding_ids(
    correlation_result: Any | None,
) -> set[str]:

    ids: set[str] = set()

    if correlation_result is None:
        return ids

    for group in getattr(
        correlation_result,
        "corroboration_groups",
        [],
    ):
        for finding_id in getattr(
            group,
            "evidence_ids",
            [],
        ):
            ids.add(finding_id)

    return ids


# ---------------------------------------------------------------------------
# Main risk calculation
# ---------------------------------------------------------------------------

def calculate_risk(
    evidence: list[EvidenceItem],
    correlation_result: Any | None = None,
) -> RiskResult:

    result = RiskResult()

    if not evidence:
        result.rationale.append(
            "No forensic evidence was supplied to the risk engine."
        )

        return result

    corroborated_ids = _corroborated_finding_ids(
        correlation_result
    )

    # ------------------------------------------------------------------
    # Evidence contributions
    # ------------------------------------------------------------------

    for item in evidence:

        # RISK-04:
        # Respect the normalizer's explicit score eligibility decision
        # for ALL evidence states. Candidate/verified/etc. evidence
        # marked score_eligible=False must not contribute risk points.
        if not item.score_eligible:
            continue

        state_points = _state_weight(
            item.evidence_state
        )

        category_points = _category_weight(
            item.category
        )

        # Inconclusive and observation-only evidence do not contribute
        # state points. Eligible indicator observations may contribute
        # their category weight conservatively.
        if state_points == 0 and category_points == 0:
            continue

        if (
            item.evidence_state
            in {
                EvidenceState.OBSERVATION,
                EvidenceState.INCONCLUSIVE,
            }
            and category_points > 0
        ):
            # Observation/inconclusive evidence receives only its
            # explicitly permitted category contribution.
            points = category_points
        else:
            points = state_points + category_points

        if points <= 0:
            continue

        reason_parts: list[str] = []

        if state_points > 0:
            reason_parts.append(
                f"{item.evidence_state.value} evidence "
                f"contributes {state_points} point(s)"
            )

        if category_points > 0:
            reason_parts.append(
                f"category '{item.category}' contributes "
                f"{category_points} point(s)"
            )

        reason = "; ".join(reason_parts)

        contribution = RiskContribution(
            finding_id=item.finding_id,
            category=item.category,
            evidence_state=item.evidence_state.value,
            points=points,
            reason=reason,
        )

        result.contributions.append(
            contribution
        )

        result.contributing_findings.append(
            item.finding_id
        )

        result.score += points

    # ------------------------------------------------------------------
    # Corroboration bonus
    # ------------------------------------------------------------------

    corroborated_groups = []

    if correlation_result is not None:
        corroborated_groups = [
            group
            for group in getattr(
                correlation_result,
                "corroboration_groups",
                [],
            )
            if len(
                getattr(
                    group,
                    "evidence_ids",
                    [],
                )
            ) >= 2
        ]

    verified_corrob_groups = []

    for group in corroborated_groups:

        evidence_ids = set(
            getattr(
                group,
                "evidence_ids",
                [],
            )
        )

        has_verified = any(
            item.finding_id in evidence_ids
            and item.evidence_state
            == EvidenceState.VERIFIED
            for item in evidence
        )

        if has_verified:
            verified_corrob_groups.append(
                group
            )

    # Only verified corroboration receives a bonus.
    # This prevents multiple weak observations from artificially
    # producing a high score.

    if verified_corrob_groups:

        bonus = len(
            verified_corrob_groups
        )

        result.score += bonus

        result.rationale.append(
            f"{len(verified_corrob_groups)} corroborated "
            f"verified evidence group(s) contributed "
            f"{bonus} additional point(s)."
        )

    # ------------------------------------------------------------------
    # Final classification
    # ------------------------------------------------------------------

    result.risk_level = _risk_level(
        result.score
    )

    result.confidence = _confidence(
        evidence,
        result.score,
    )

    # ------------------------------------------------------------------
    # Explainable rationale
    # ------------------------------------------------------------------

    if result.score == 0:

        result.rationale.append(
            "No evidence met the threshold for a positive "
            "risk contribution."
        )

    else:

        result.rationale.append(
            f"The evidence produced an aggregate score of "
            f"{result.score}."
        )

        result.rationale.append(
            f"The resulting evidentiary risk level is "
            f"{result.risk_level}."
        )

    if any(
        item.evidence_state == EvidenceState.VERIFIED
        for item in evidence
    ):

        result.rationale.append(
            "Verified hidden-data evidence carries greater "
            "weight because the underlying content was successfully "
            "recovered and validated."
        )

    if any(
        item.evidence_state == EvidenceState.INCONCLUSIVE
        for item in evidence
    ):

        result.warnings.append(
            "Inconclusive analysis does not prove that hidden "
            "content is absent."
        )

    if any(
        item.category == "yara_match"
        for item in evidence
    ):

        result.warnings.append(
            "YARA matches are indicators requiring contextual "
            "validation; they are not automatic proof of maliciousness."
        )

    result.warnings.append(
        "The risk score represents evidentiary suspicion and "
        "concealed-content significance; it is not a probability "
        "of maliciousness."
    )

    return result

# ---------------------------------------------------------------------------
# Human-readable report
# ---------------------------------------------------------------------------

def print_risk_report(
    result: RiskResult,
) -> None:

    print("Module 11 Risk Assessment")
    print("=========================")

    print(
        f"Score: {result.score}"
    )

    print(
        f"Risk level: {result.risk_level}"
    )

    print(
        f"Confidence: {result.confidence}"
    )

    print()

    print("Contributions")
    print("-------------")

    if not result.contributions:
        print("No positive contributions.")

    else:
        for contribution in result.contributions:
            print(
                f"- {contribution.finding_id}: "
                f"+{contribution.points} "
                f"({contribution.category})"
            )

    print()

    print("Rationale")
    print("---------")

    for reason in result.rationale:
        print(
            f"- {reason}"
        )

    if result.warnings:
        print()

        print("Warnings")
        print("--------")

        for warning in result.warnings:
            print(
                f"- {warning}"
            )


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    observation = EvidenceItem(
        finding_id="TEST-OBS-001",
        source_module="Module 9",
        source_tool="file",
        category="file_type",
        description="Payload identified as ASCII text.",
        evidence_state=EvidenceState.OBSERVATION,
    )

    verified = EvidenceItem(
        finding_id="TEST-VER-001",
        source_module="Module 8",
        source_tool="steghide",
        category="extraction_attempt",
        description="Hidden payload successfully recovered.",
        evidence_state=EvidenceState.VERIFIED,
        artifact="/tmp/payload.bin",
    )

    result = calculate_risk(
        [
            observation,
            verified,
        ]
    )

    print_risk_report(
        result
    )
