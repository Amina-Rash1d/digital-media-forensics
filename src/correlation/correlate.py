from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .evidence import EvidenceItem, EvidenceState


# ---------------------------------------------------------------------------
# Result structures
# ---------------------------------------------------------------------------

@dataclass
class CorroborationGroup:

    group_id: str

    evidence_ids: list[str] = field(default_factory=list)

    verified_ids: list[str] = field(default_factory=list)

    indicator_ids: list[str] = field(default_factory=list)

    observation_ids: list[str] = field(default_factory=list)

    inconclusive_ids: list[str] = field(default_factory=list)


@dataclass
class CorrelationResult:

    evidence: list[EvidenceItem] = field(default_factory=list)

    by_artifact: dict[str, list[str]] = field(default_factory=dict)

    corroboration_groups: list[CorroborationGroup] = field(
        default_factory=list
    )

    verified_evidence: list[str] = field(default_factory=list)

    indicator_evidence: list[str] = field(default_factory=list)

    observation_evidence: list[str] = field(default_factory=list)

    inconclusive_evidence: list[str] = field(default_factory=list)

    correlation_count: int = 0

    summary: str = ""


# ---------------------------------------------------------------------------
# Evidence classification
# ---------------------------------------------------------------------------

def _classify_state(
    evidence: EvidenceItem,
    result: CorrelationResult,
) -> None:

    finding_id = evidence.finding_id

    if evidence.evidence_state == EvidenceState.VERIFIED:
        result.verified_evidence.append(finding_id)

    elif evidence.evidence_state == EvidenceState.INDICATOR:
        result.indicator_evidence.append(finding_id)

    elif evidence.evidence_state == EvidenceState.OBSERVATION:
        result.observation_evidence.append(finding_id)

    elif evidence.evidence_state == EvidenceState.INCONCLUSIVE:
        result.inconclusive_evidence.append(finding_id)


# ---------------------------------------------------------------------------
# Artifact grouping
# ---------------------------------------------------------------------------

def _group_by_artifact(
    evidence_items: list[EvidenceItem],
) -> dict[str, list[str]]:

    grouped: dict[str, list[str]] = {}

    for evidence in evidence_items:
        artifact = evidence.target_artifact or "<unknown>"

        grouped.setdefault(
            artifact,
            [],
        ).append(
            evidence.finding_id
        )

    return grouped


# ---------------------------------------------------------------------------
# Corroboration grouping
# ---------------------------------------------------------------------------

def _build_corroboration_groups(
    evidence_items: list[EvidenceItem],
) -> list[CorroborationGroup]:

    groups: dict[str, CorroborationGroup] = {}

    for evidence in evidence_items:
        group_id = evidence.corroboration_group

        if not group_id:
            continue

        if group_id not in groups:
            groups[group_id] = CorroborationGroup(
                group_id=group_id
            )

        group = groups[group_id]

        group.evidence_ids.append(
            evidence.finding_id
        )

        if evidence.evidence_state == EvidenceState.VERIFIED:
            group.verified_ids.append(
                evidence.finding_id
            )

        elif evidence.evidence_state == EvidenceState.INDICATOR:
            group.indicator_ids.append(
                evidence.finding_id
            )

        elif evidence.evidence_state == EvidenceState.OBSERVATION:
            group.observation_ids.append(
                evidence.finding_id
            )

        elif evidence.evidence_state == EvidenceState.INCONCLUSIVE:
            group.inconclusive_ids.append(
                evidence.finding_id
            )

    return list(groups.values())


# ---------------------------------------------------------------------------
# Correlation logic
# ---------------------------------------------------------------------------

def correlate_evidence(
    evidence_items: list[EvidenceItem],
) -> CorrelationResult:

    result = CorrelationResult(
        evidence=list(evidence_items)
    )

    for evidence in evidence_items:
        _classify_state(
            evidence,
            result,
        )

    result.by_artifact = _group_by_artifact(
        evidence_items
    )

    result.corroboration_groups = (
        _build_corroboration_groups(
            evidence_items
        )
    )

    result.correlation_count = sum(
        1
        for group in result.corroboration_groups
        if len(group.evidence_ids) >= 2
    )

    # ---------------------------------------------------------------
    # Conservative summary
    # ---------------------------------------------------------------

    if not evidence_items:
        result.summary = (
            "No normalized forensic evidence was supplied "
            "for correlation."
        )

    elif result.correlation_count > 0:
        result.summary = (
            f"{result.correlation_count} corroboration group(s) "
            "contain multiple evidence items. The grouped findings "
            "should be evaluated together while preserving the "
            "original evidence states. Correlation alone does not "
            "establish maliciousness."
        )

    elif result.verified_evidence:
        result.summary = (
            "Verified evidence is present, but no explicit "
            "multi-item corroboration groups were established. "
            "Verified evidence should be retained as independently "
            "supported evidence and evaluated by later decision "
            "logic."
        )

    else:
        result.summary = (
            "Evidence was normalized successfully, but no "
            "multi-item corroboration was established. "
            "Observations, indicators, and inconclusive results "
            "remain individually classified."
        )

    return result


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def get_evidence_for_artifact(
    result: CorrelationResult,
    target_artifact: str,
) -> list[EvidenceItem]:

    finding_ids = set(
        result.by_artifact.get(
            target_artifact,
            []
        )
    )

    return [
        evidence
        for evidence in result.evidence
        if evidence.finding_id in finding_ids
    ]


def get_verified_evidence(
    result: CorrelationResult,
) -> list[EvidenceItem]:

    verified_ids = set(
        result.verified_evidence
    )

    return [
        evidence
        for evidence in result.evidence
        if evidence.finding_id in verified_ids
    ]


def get_corroborated_groups(
    result: CorrelationResult,
) -> list[CorroborationGroup]:

    return [
        group
        for group in result.corroboration_groups
        if len(group.evidence_ids) >= 2
    ]
