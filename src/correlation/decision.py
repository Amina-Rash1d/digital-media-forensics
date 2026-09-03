from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.correlation.evidence import EvidenceItem, EvidenceState


# ---------------------------------------------------------------------------
# Decision labels
# ---------------------------------------------------------------------------

ASSESSMENT_NO_EVIDENCE = "NO_CORRELATED_EVIDENCE"

ASSESSMENT_INCONCLUSIVE = "INCONCLUSIVE"

ASSESSMENT_INDICATORS = "SUSPICIOUS_INDICATORS_PRESENT"

ASSESSMENT_HIDDEN_DATA = "VERIFIED_HIDDEN_DATA"

ASSESSMENT_CORROBORATED_HIDDEN_DATA = (
    "CORROBORATED_VERIFIED_HIDDEN_DATA"
)


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

@dataclass
class DecisionResult:

    assessment: str = ASSESSMENT_NO_EVIDENCE

    evidence_count: int = 0

    observation_count: int = 0
    candidate_count: int = 0
    extracted_count: int = 0
    plausible_count: int = 0
    verified_count: int = 0
    inconclusive_count: int = 0

    verified_evidence: list[str] = field(default_factory=list)

    corroborated_groups: list[str] = field(default_factory=list)

    indicator_findings: list[str] = field(default_factory=list)

    further_analysis_required: bool = False

    rationale: list[str] = field(default_factory=list)

    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Evidence-state counting
# ---------------------------------------------------------------------------

def _count_states(
    evidence: list[EvidenceItem],
) -> dict[EvidenceState, int]:

    counts = {
        state: 0
        for state in EvidenceState
    }

    for item in evidence:
        counts[item.evidence_state] += 1

    return counts


# ---------------------------------------------------------------------------
# Indicator identification
# ---------------------------------------------------------------------------

def _identify_indicators(
    evidence: list[EvidenceItem],
) -> list[str]:

    indicators: list[str] = []

    indicator_categories = {
        "yara_match",
        "nested_content",
        "archive_container",
        "possible_embedded_file",
        "possible_text_interpretation",
    }

    for item in evidence:
        if item.category in indicator_categories:
            indicators.append(item.finding_id)

    return indicators


# ---------------------------------------------------------------------------
# Corroboration extraction
# ---------------------------------------------------------------------------

def _extract_corroborated_groups(
    correlation_result: Any,
) -> list[str]:

    groups: list[str] = []

    for group in getattr(
        correlation_result,
        "corroboration_groups",
        [],
    ):
        group_id = getattr(
            group,
            "group_id",
            None,
        )

        evidence_ids = getattr(
            group,
            "evidence_ids",
            [],
        )

        verified_ids = getattr(
            group,
            "verified_ids",
            [],
        )

        if (
            group_id
            and len(evidence_ids) >= 2
            and verified_ids
        ):
            groups.append(group_id)

    return groups

# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

def decide_from_correlated_evidence(
    evidence: list[EvidenceItem],
    correlation_result: Any | None = None,
) -> DecisionResult:

    result = DecisionResult(
        evidence_count=len(evidence),
    )

    if not evidence:
        result.assessment = ASSESSMENT_NO_EVIDENCE

        result.rationale.append(
            "No normalized forensic evidence was supplied "
            "to the Module 11 decision layer."
        )

        result.further_analysis_required = False

        return result

    counts = _count_states(evidence)

    result.observation_count = counts[
        EvidenceState.OBSERVATION
    ]

    result.candidate_count = counts[
        EvidenceState.CANDIDATE
    ]

    result.extracted_count = counts[
        EvidenceState.EXTRACTED
    ]

    result.plausible_count = counts[
        EvidenceState.PLAUSIBLE
    ]

    result.verified_count = counts[
        EvidenceState.VERIFIED
    ]

    result.inconclusive_count = counts[
        EvidenceState.INCONCLUSIVE
    ]

    # ------------------------------------------------------------------
    # Verified evidence
    # ------------------------------------------------------------------

    result.verified_evidence = [
        item.finding_id
        for item in evidence
        if item.evidence_state == EvidenceState.VERIFIED
    ]

    # Root-cause fix (DEC-07): only VERIFIED evidence that actually
    # represents a hidden-data extraction/recovery event should be
    # able to trigger the VERIFIED_HIDDEN_DATA assessment below. As
    # normalization currently stands, only Module 8 ever produces
    # VERIFIED evidence and it always uses this category, so this is
    # a defensive guard rather than a behavior change today — but it
    # prevents a future VERIFIED item from an unrelated category
    # (e.g. a hypothetical verified metadata finding) from silently
    # being interpreted as verified hidden-data recovery.
    hidden_data_categories = {"extraction_attempt"}

    verified_hidden_data_evidence = [
        item.finding_id
        for item in evidence
        if item.evidence_state == EvidenceState.VERIFIED
        and item.category in hidden_data_categories
    ]

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    result.indicator_findings = _identify_indicators(
        evidence
    )

    # ------------------------------------------------------------------
    # Corroboration
    # ------------------------------------------------------------------

    if correlation_result is not None:
        result.corroborated_groups = (
            _extract_corroborated_groups(
                correlation_result
            )
        )

    # ------------------------------------------------------------------
    # Highest-confidence decision
    # ------------------------------------------------------------------

    if verified_hidden_data_evidence:

        if result.corroborated_groups:
            result.assessment = (
                ASSESSMENT_CORROBORATED_HIDDEN_DATA
            )

            result.rationale.append(
                "Verified forensic evidence is present and "
                "multiple related evidence items were correlated."
            )

            result.rationale.append(
                "The evidence supports a corroborated assessment "
                "of recovered hidden data."
            )

        else:
            result.assessment = ASSESSMENT_HIDDEN_DATA

            result.rationale.append(
                "At least one forensic finding reached VERIFIED "
                "state through the tested analysis technique."
            )

            result.rationale.append(
                "The evidence supports the conclusion that hidden "
                "data was successfully recovered."
            )

        result.rationale.append(
            "Verification of hidden data does not by itself "
            "establish that the recovered payload is malicious."
        )

        result.further_analysis_required = True

        result.rationale.append(
            "Further payload analysis is required to characterize "
            "the recovered artifact and determine whether additional "
            "investigation is warranted."
        )

        return result

    # ------------------------------------------------------------------
    # Suspicious indicators without verification
    # ------------------------------------------------------------------

    if result.indicator_findings:

        result.assessment = ASSESSMENT_INDICATORS

        result.rationale.append(
            "One or more investigative indicators were observed, "
            "but no finding reached VERIFIED state."
        )

        result.rationale.append(
            "These indicators require contextual analysis and "
            "must not be treated as proof of hidden data or "
            "maliciousness."
        )

        result.further_analysis_required = True

        return result

    # ------------------------------------------------------------------
    # Extraction/candidate evidence without verification
    # ------------------------------------------------------------------

    if (
        result.candidate_count > 0
        or result.extracted_count > 0
        or result.plausible_count > 0
    ):
        result.assessment = ASSESSMENT_INCONCLUSIVE

        result.rationale.append(
            "Candidate, extracted, or plausible evidence exists, "
            "but no finding reached VERIFIED state."
        )

        result.rationale.append(
            "The current evidence is insufficient to confirm "
            "hidden data."
        )

        result.further_analysis_required = True

        return result

    # ------------------------------------------------------------------
    # Observations / inconclusive attempts only
    # ------------------------------------------------------------------

    result.assessment = ASSESSMENT_INCONCLUSIVE

    result.rationale.append(
        "The available evidence consists of observations and/or "
        "inconclusive analysis results."
    )

    result.rationale.append(
        "No verified hidden-data recovery was established."
    )

    result.further_analysis_required = False

    if result.inconclusive_count > 0:
        result.warnings.append(
            "Inconclusive extraction results do not prove that "
            "hidden data is absent."
        )

    return result


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def decide_from_correlation(
    correlation_result: Any,
) -> DecisionResult:

    evidence = list(
        getattr(
            correlation_result,
            "evidence",
            [],
        )
    )

    return decide_from_correlated_evidence(
        evidence=evidence,
        correlation_result=correlation_result,
    )


# ---------------------------------------------------------------------------
# Human-readable report
# ---------------------------------------------------------------------------

def print_decision_report(
    result: DecisionResult,
) -> None:

    print("Module 11 Evidence Decision")
    print("===========================")

    print(
        f"Assessment: {result.assessment}"
    )

    print(
        f"Evidence items: {result.evidence_count}"
    )

    print(
        f"Verified: {result.verified_count}"
    )

    print(
        f"Observations: {result.observation_count}"
    )

    print(
        f"Candidates: {result.candidate_count}"
    )

    print(
        f"Extracted: {result.extracted_count}"
    )

    print(
        f"Plausible: {result.plausible_count}"
    )

    print(
        f"Inconclusive: {result.inconclusive_count}"
    )

    print(
        f"Corroborated groups: "
        f"{len(result.corroborated_groups)}"
    )

    print(
        f"Further analysis required: "
        f"{result.further_analysis_required}"
    )

    print()

    print("Rationale")
    print("---------")

    if not result.rationale:
        print("No rationale generated.")
    else:
        for reason in result.rationale:
            print(f"- {reason}")

    if result.verified_evidence:
        print()
        print("Verified Evidence")
        print("-----------------")

        for finding_id in result.verified_evidence:
            print(f"- {finding_id}")

    if result.indicator_findings:
        print()
        print("Indicators")
        print("----------")

        for finding_id in result.indicator_findings:
            print(f"- {finding_id}")

    if result.warnings:
        print()
        print("Warnings")
        print("--------")

        for warning in result.warnings:
            print(f"- {warning}")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    observation = EvidenceItem(
        finding_id="TEST-OBS-001",
        source_module="Module 9",
        source_tool="file",
        category="file_type",
        description="Recovered payload identified as ASCII text.",
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

    decision = decide_from_correlated_evidence(
        [
            observation,
            verified,
        ]
    )

    print_decision_report(decision)
