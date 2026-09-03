from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Optional

from src.correlation.evidence import EvidenceItem, EvidenceState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize_result(result: Any) -> dict[str, Any]:

    if is_dataclass(result):
        return asdict(result)

    if hasattr(result, "__dict__"):
        return dict(result.__dict__)

    return {}


def _module8_state(result: Any) -> EvidenceState:

    def value(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)

        return getattr(obj, key, default)

    # ---------------------------------------------------------------
    # Top-level Module 8 result
    # ---------------------------------------------------------------

    if bool(value(result, "verified", False)):
        return EvidenceState.VERIFIED

    if bool(value(result, "plausible", False)):
        return EvidenceState.PLAUSIBLE

    if bool(value(result, "extracted", False)):
        return EvidenceState.EXTRACTED

    # ---------------------------------------------------------------
    # Technique-specific results
    #
    # Module 8 may contain:
    #     steghide
    #     stegseek
    #     zsteg
    #
    # Examine each technique and preserve the strongest state.
    # ---------------------------------------------------------------

    strongest_state = EvidenceState.INCONCLUSIVE

    state_rank = {
        EvidenceState.INCONCLUSIVE: 0,
        EvidenceState.EXTRACTED: 1,
        EvidenceState.PLAUSIBLE: 2,
        EvidenceState.VERIFIED: 3,
    }

    for technique in (
        "steghide",
        "stegseek",
        "zsteg",
    ):
        technique_result = value(
            result,
            technique,
            None,
        )

        if technique_result is None:
            continue

        if bool(value(technique_result, "verified", False)) or bool(
            value(technique_result, "confirmed", False)
        ):
            candidate_state = EvidenceState.VERIFIED

        elif bool(
            value(technique_result, "plausible", False)
        ):
            candidate_state = EvidenceState.PLAUSIBLE

        elif bool(
            value(technique_result, "extracted", False)
        ):
            candidate_state = EvidenceState.EXTRACTED

        else:
            candidate_state = EvidenceState.INCONCLUSIVE

        if state_rank[candidate_state] > state_rank[strongest_state]:
            strongest_state = candidate_state

    return strongest_state


def _module8_corroboration_group(
    result: Any,
) -> Optional[str]:

    def value(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)

        return getattr(obj, key, default)

    # ---------------------------------------------------------------
    # Top-level verification
    # ---------------------------------------------------------------

    if bool(value(result, "verified", False)):
        return "HIDDEN_DATA_RECOVERY"

    # ---------------------------------------------------------------
    # Technique-specific verification
    # ---------------------------------------------------------------

    for technique in (
        "steghide",
        "stegseek",
        "zsteg",
    ):
        technique_result = value(
            result,
            technique,
            None,
        )

        if technique_result is None:
            continue

        if bool(
            value(technique_result, "verified", False)
        ) or bool(
            value(technique_result, "confirmed", False)
        ):
            return "HIDDEN_DATA_RECOVERY"

    return None

# ---------------------------------------------------------------------------
# Module 8 normalization
# ---------------------------------------------------------------------------

def normalize_module8_result(
    result: Any,
    finding_id: str,
    target_artifact: Optional[str] = None,
) -> EvidenceItem:

    def value(
        obj: Any,
        key: str,
        default: Any = None,
    ) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)

        return getattr(obj, key, default)

    def result_type_name(obj: Any) -> str:
        if isinstance(obj, dict):
            return "dict"

        return obj.__class__.__name__

    # ---------------------------------------------------------------
    # Determine strongest evidence state
    # ---------------------------------------------------------------

    state = _module8_state(result)

    # ---------------------------------------------------------------
    # Determine the technique/source
    # ---------------------------------------------------------------

    technique = value(
        result,
        "technique",
        None,
    )

    source_tool = "module8"

    if technique:
        technique_text = str(technique).lower()

        if "zsteg" in technique_text or "lsb" in technique_text:
            source_tool = "zsteg"

        elif "steghide" in technique_text:
            source_tool = "steghide"

        elif "stegseek" in technique_text:
            source_tool = "stegseek"

        else:
            source_tool = "module8"

    else:
        # Look for a verified technique result.
        for technique_name in (
            "zsteg",
            "steghide",
            "stegseek",
        ):
            technique_result = value(
                result,
                technique_name,
                None,
            )

            if technique_result is None:
                continue

            if (
                value(
                    technique_result,
                    "verified",
                    False,
                )
                or value(
                    technique_result,
                    "confirmed",
                    False,
                )
                or value(
                    technique_result,
                    "extracted",
                    False,
                )
            ):
                source_tool = technique_name
                break

    # ---------------------------------------------------------------
    # Locate recovered artifact
    # ---------------------------------------------------------------

    artifact = value(
        result,
        "extracted_path",
        None,
    )

    # Prefer the canonical field written by verify_and_extract()
    # (src/analysis/verify_extract.py). That function already knows
    # which technique-specific result actually verified/extracted, so
    # it is the single source of truth for "which artifact was
    # recovered". Falling back to the old per-technique search only
    # covers older/serialized results that predate the canonical field.
    if not artifact:
        artifact = value(
            result,
            "extracted_path",
            None,
        )

    if not artifact:
        for technique_name in (
            "steghide",
            "stegseek",
            "zsteg",
        ):
            technique_result = value(
                result,
                technique_name,
                None,
            )

            if technique_result is None:
                continue

            candidate = value(
                technique_result,
                "extracted_path",
                None,
            )

            if candidate:
                artifact = candidate
                break

    # ---------------------------------------------------------------
    # Confidence
    # ---------------------------------------------------------------

    if state == EvidenceState.VERIFIED:

        # Canonical field: the score belonging to whichever technique
        # actually verified. Do NOT fall back to scanning
        # zsteg/steghide/stegseek in a fixed order here — that is what
        # previously let an unrelated technique's default score (e.g.
        # zsteg's best_score=0.0 when zsteg found nothing) get reported
        # as the confidence for a Steghide-verified extraction.
        best_score = value(
            result,
            "verification_score",
            None,
        )

        if best_score is None:
            # Legacy fallback for results that predate the canonical
            # field: only trust a technique-specific score when that
            # SAME technique is the one that actually verified.
            source_tool = value(
                result,
                "source_tool",
                None,
            ) or value(
                result,
                "technique",
                "",
            )

            for technique_name in (
                "steghide",
                "stegseek",
                "zsteg",
            ):
                if (
                    source_tool
                    and technique_name not in str(source_tool).lower()
                    and source_tool != technique_name
                ):
                    continue

                technique_result = value(
                    result,
                    technique_name,
                    None,
                )

                if technique_result is None:
                    continue

                if not value(technique_result, "verified", False):
                    continue

                candidate_score = value(
                    technique_result,
                    "best_score",
                    None,
                )

                best_score = (
                    candidate_score
                    if candidate_score is not None
                    else 1.0
                )
                break

        confidence = (
            float(best_score)
            if best_score is not None
            else 1.0
        )

        description = (
            "Module 8 successfully recovered and verified "
            "hidden data."
        )

        rationale = (
            "Module 8 produced a verified hidden-data recovery "
            "result under the tested technique and conditions."
        )

    elif state == EvidenceState.PLAUSIBLE:

        best_score = value(
            result,
            "best_score",
            None,
        )

        if best_score is None:
            for technique_name in (
                "zsteg",
                "steghide",
                "stegseek",
            ):
                technique_result = value(
                    result,
                    technique_name,
                    None,
                )

                if technique_result is None:
                    continue

                candidate_score = value(
                    technique_result,
                    "best_score",
                    None,
                )

                if candidate_score is not None:
                    best_score = candidate_score
                    break

        confidence = (
            float(best_score)
            if best_score is not None
            else None
        )

        description = (
            "Module 8 produced a plausible hidden-data "
            "candidate, but verification was not established."
        )

        rationale = (
            "Module 8 produced a plausible hidden-data "
            "candidate, but the available evidence does not "
            "establish verified recovery."
        )

    elif state == EvidenceState.EXTRACTED:

        confidence = None

        description = (
            "Module 8 recovered data, but the available "
            "result does not establish verification."
        )

        rationale = (
            "Module 8 recovered data, but verification was "
            "not established by the available evidence."
        )

    else:

        confidence = None
        artifact = None

        description = (
            "Module 8 extraction attempt was inconclusive."
        )

        rationale = (
            "Module 8 did not recover verified hidden data "
            "under the tested conditions. This is inconclusive "
            "and must not be interpreted as proof of absence."
        )

    # ---------------------------------------------------------------
    # Preserve complete Module 8 provenance
    # ---------------------------------------------------------------

    serialized_result = _serialize_result(
        result
    )

    # Add useful top-level technique context when present.
    if isinstance(serialized_result, dict):
        serialized_result = dict(
            serialized_result
        )

        serialized_result.setdefault(
            "technique",
            technique,
        )

        serialized_result.setdefault(
            "extracted_path",
            artifact,
        )

    return EvidenceItem(
        finding_id=finding_id,
        source_module="Module 8",
        source_tool=source_tool,
        category="extraction_attempt",
        description=description,
        evidence_state=state,
        confidence=confidence,
        target_artifact=target_artifact,
        artifact=artifact,
        provenance={
            "module": "Module 8",
            "source_result_type": result_type_name(
                result
            ),
            "technique": technique,
            "source_result": serialized_result,
        },
        corroboration_group=(
            _module8_corroboration_group(
                result
            )
        ),
        score_eligible=False,
        weight=None,
        rationale=rationale,
    )

# ---------------------------------------------------------------------------
# Module 9 normalization helpers
# ---------------------------------------------------------------------------

def _payload_state(result: Any) -> EvidenceState:

    exists = bool(getattr(result, "exists", False))
    readable = bool(getattr(result, "readable", False))

    if exists and readable:
        return EvidenceState.OBSERVATION

    if exists:
        return EvidenceState.INCONCLUSIVE

    return EvidenceState.INCONCLUSIVE


def _payload_confidence(result: Any) -> Optional[float]:

    exists = bool(getattr(result, "exists", False))
    readable = bool(getattr(result, "readable", False))

    if exists and readable:
        return 1.0

    if exists:
        return 0.5

    return None


# ---------------------------------------------------------------------------
# Module 9 corroboration helpers
# ---------------------------------------------------------------------------

def _module9_corroboration_group(
    category: str,
    result: Any,
) -> Optional[str]:

    exists = bool(getattr(result, "exists", False))
    readable = bool(getattr(result, "readable", False))

    if category == "payload_accessibility" and exists and readable:
        return "HIDDEN_DATA_RECOVERY"

    if category in {
        "file_type",
        "magic_signature",
        "printable_strings",
        "metadata",
        "archive_container",
        "nested_content",
    }:
        return "PAYLOAD_CHARACTERIZATION"

    return None


# ---------------------------------------------------------------------------
# Module 9 normalization
# ---------------------------------------------------------------------------

def normalize_module9_result(
    result: Any,
    finding_id: str,
    target_artifact: Optional[str] = None,
) -> list[EvidenceItem]:

    evidence: list[EvidenceItem] = []

    payload_path = getattr(
        result,
        "payload_path",
        None,
    )

    artifact = payload_path or target_artifact

    base_provenance = {
        "module": "Module 9",
        "source_result_type": result.__class__.__name__,
        "payload_path": payload_path,
    }

    # ------------------------------------------------------------------
    # Payload accessibility
    # ------------------------------------------------------------------

    state = _payload_state(result)

    evidence.append(
        EvidenceItem(
            finding_id=f"{finding_id}-ACCESS",
            source_module="Module 9",
            source_tool="payload_analysis",
            category="payload_accessibility",
            description=(
                "Recovered payload exists and is readable."
                if getattr(result, "exists", False)
                and getattr(result, "readable", False)
                else
                "Recovered payload could not be fully accessed."
            ),
            evidence_state=state,
            confidence=_payload_confidence(result),
            target_artifact=target_artifact,
            artifact=artifact,
            provenance={
                **base_provenance,
                "exists": getattr(result, "exists", False),
                "readable": getattr(result, "readable", False),
                "size_bytes": getattr(result, "size_bytes", 0),
            },
            corroboration_group=_module9_corroboration_group(
                "payload_accessibility",
                result,
            ),
            score_eligible=False,
            rationale=(
                "Payload accessibility is an evidentiary observation "
                "and does not establish maliciousness."
            ),
        )
    )

    # ------------------------------------------------------------------
    # File type
    # ------------------------------------------------------------------

    file_type = getattr(
        result,
        "file_type",
        "",
    )

    if file_type:
        evidence.append(
            EvidenceItem(
                finding_id=f"{finding_id}-TYPE",
                source_module="Module 9",
                source_tool="file",
                category="file_type",
                description=(
                    f"Recovered payload identified as: {file_type}"
                ),
                evidence_state=EvidenceState.OBSERVATION,
                confidence=1.0,
                target_artifact=target_artifact,
                artifact=artifact,
                provenance={
                    **base_provenance,
                    "file_type": file_type,
                },
                corroboration_group=_module9_corroboration_group(
                    "file_type",
                    result,
                ),
                score_eligible=False,
                rationale=(
                    "File-type identification characterizes the "
                    "recovered artifact and does not independently "
                    "establish maliciousness."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Magic signature
    # ------------------------------------------------------------------

    magic_signature = getattr(
        result,
        "magic_signature",
        "",
    )

    magic_match = bool(
        getattr(
            result,
            "magic_match",
            False,
        )
    )

    if magic_signature:
        evidence.append(
            EvidenceItem(
                finding_id=f"{finding_id}-MAGIC",
                source_module="Module 9",
                source_tool="magic-signature",
                category="magic_signature",
                description=(
                    f"Magic/signature result: {magic_signature}"
                ),
                evidence_state=EvidenceState.OBSERVATION,
                confidence=1.0,
                target_artifact=target_artifact,
                artifact=artifact,
                provenance={
                    **base_provenance,
                    "magic_signature": magic_signature,
                    "magic_match": magic_match,
                },
                corroboration_group=_module9_corroboration_group(
                    "magic_signature",
                    result,
                ),
                score_eligible=False,
                rationale=(
                    "Magic-byte analysis characterizes the artifact "
                    "format and may support other findings."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Printable strings
    # ------------------------------------------------------------------

    strings = getattr(
        result,
        "strings",
        [],
    )

    strings_count = int(
        getattr(
            result,
            "strings_count",
            len(strings),
        )
        or 0
    )

    if strings_count > 0:
        evidence.append(
            EvidenceItem(
                finding_id=f"{finding_id}-STRINGS",
                source_module="Module 9",
                source_tool="strings",
                category="printable_strings",
                description=(
                    f"Recovered payload contains "
                    f"{strings_count} printable string(s)."
                ),
                evidence_state=EvidenceState.OBSERVATION,
                confidence=1.0,
                target_artifact=target_artifact,
                artifact=artifact,
                provenance={
                    **base_provenance,
                    "strings_count": strings_count,
                    "strings": strings,
                },
                corroboration_group=_module9_corroboration_group(
                    "printable_strings",
                    result,
                ),
                score_eligible=False,
                rationale=(
                    "Printable strings are preserved as forensic "
                    "observations. Their meaning requires contextual "
                    "analysis."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    if getattr(result, "metadata_available", False):
        metadata_summary = getattr(
            result,
            "metadata_summary",
            [],
        )

        evidence.append(
            EvidenceItem(
                finding_id=f"{finding_id}-META",
                source_module="Module 9",
                source_tool="metadata",
                category="metadata",
                description=(
                    "Metadata was available for the recovered payload."
                ),
                evidence_state=EvidenceState.OBSERVATION,
                confidence=1.0,
                target_artifact=target_artifact,
                artifact=artifact,
                provenance={
                    **base_provenance,
                    "metadata_summary": metadata_summary,
                },
                corroboration_group=_module9_corroboration_group(
                    "metadata",
                    result,
                ),
                score_eligible=False,
                rationale=(
                    "Metadata availability is an observation; "
                    "individual metadata values require separate "
                    "interpretation."
                ),
            )
        )

    # ------------------------------------------------------------------
    # YARA
    # ------------------------------------------------------------------

    yara_matches = getattr(
        result,
        "yara_matches",
        [],
    )

    if yara_matches:
        serialized_matches = [
            _serialize_result(match)
            for match in yara_matches
        ]

        evidence.append(
            EvidenceItem(
                finding_id=f"{finding_id}-YARA",
                source_module="Module 9",
                source_tool="yara",
                category="yara_match",
                description=(
                    f"YARA reported {len(yara_matches)} "
                    f"matching rule(s) against the recovered payload."
                ),
                evidence_state=EvidenceState.OBSERVATION,
                confidence=None,
                target_artifact=target_artifact,
                artifact=artifact,
                provenance={
                    **base_provenance,
                    "yara_available": getattr(
                        result,
                        "yara_available",
                        False,
                    ),
                    "yara_rules_path": getattr(
                        result,
                        "yara_rules_path",
                        None,
                    ),
                    "matches": serialized_matches,
                },
                corroboration_group=None,
                score_eligible=False,
                rationale=(
                    "A YARA match is an indicator requiring contextual "
                    "validation. It is not automatic proof that the "
                    "payload is malicious."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Archive/container
    # ------------------------------------------------------------------

    if getattr(result, "archive_container", False):
        archive_type = getattr(
            result,
            "archive_type",
            "",
        )

        archive_entries = getattr(
            result,
            "archive_entries",
            [],
        )

        evidence.append(
            EvidenceItem(
                finding_id=f"{finding_id}-ARCHIVE",
                source_module="Module 9",
                source_tool="archive-analysis",
                category="archive_container",
                description=(
                    f"Recovered payload identified as an archive/container"
                    f"{': ' + archive_type if archive_type else '.'}"
                ),
                evidence_state=EvidenceState.OBSERVATION,
                confidence=1.0,
                target_artifact=target_artifact,
                artifact=artifact,
                provenance={
                    **base_provenance,
                    "archive_type": archive_type,
                    "archive_entries": [
                        _serialize_result(entry)
                        for entry in archive_entries
                    ],
                },
                corroboration_group=_module9_corroboration_group(
                    "archive_container",
                    result,
                ),
                score_eligible=False,
                rationale=(
                    "Container identification establishes artifact "
                    "structure and may justify deeper examination."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Nested content
    # ------------------------------------------------------------------

    if getattr(result, "nested_content_suspected", False):
        evidence.append(
            EvidenceItem(
                finding_id=f"{finding_id}-NESTED",
                source_module="Module 9",
                source_tool="payload-analysis",
                category="nested_content",
                description=(
                    "Nested content indicators were observed "
                    "inside the recovered payload."
                ),
                evidence_state=EvidenceState.OBSERVATION,
                confidence=None,
                target_artifact=target_artifact,
                artifact=artifact,
                provenance={
                    **base_provenance,
                    "nested_content_suspected": True,
                },
                corroboration_group=_module9_corroboration_group(
                    "nested_content",
                    result,
                ),
                score_eligible=False,
                rationale=(
                    "Nested content is an investigative indicator "
                    "and should be examined before drawing conclusions."
                ),
            )
        )

    return evidence

def normalize_module2_result(
    result: dict[str, Any],
    finding_id: str,
    target_artifact: Optional[str] = None,
) -> EvidenceItem:

    string_count = result.get("string_count", 0)
    file_type = result.get("file_type", "unknown")

    return EvidenceItem(
        finding_id=finding_id,
        source_module="Module 2",
        source_tool="file/strings",
        category="file_type",
        description=(
            f"File triage identified the file as '{file_type}' "
            f"with {string_count} extracted printable strings."
        ),
        evidence_state=EvidenceState.OBSERVATION,
        confidence=None,
        target_artifact=target_artifact,
        artifact=result.get("sha256"),
        provenance={
            "filename": result.get("filename"),
            "file_size": result.get("file_size"),
            "sha256": result.get("sha256"),
            "file_type": file_type,
            "string_count": string_count,
        },
        score_eligible=False,
        rationale=(
            "Triage establishes baseline evidence only; it does not "
            "confirm or rule out hidden data."
        ),
    )


def normalize_module3_result(
    result: dict[str, Any],
    finding_id: str,
    target_artifact: Optional[str] = None,
) -> EvidenceItem:

    assessment = result.get("assessment", {}) or {}
    assessment_text = assessment.get("assessment", "NO IMMEDIATE ANOMALY")
    notable_findings = assessment.get("notable_findings", []) or []

    is_notable = assessment_text != "NO IMMEDIATE ANOMALY"

    return EvidenceItem(
        finding_id=finding_id,
        source_module="Module 3",
        source_tool="exiftool",
        category="metadata",
        description=(
            f"Metadata assessment: {assessment_text}. "
            + ("; ".join(notable_findings) if notable_findings else
               "No notable metadata fields were found.")
        ),
        evidence_state=(
            EvidenceState.CANDIDATE
            if is_notable
            else EvidenceState.OBSERVATION
        ),
        confidence=None,
        target_artifact=target_artifact,
        artifact=None,
        provenance={
            "assessment": assessment_text,
            "notable_findings": notable_findings,
        },
        score_eligible=False,
        rationale=(
            "Metadata anomalies (editing software, GPS, comments) are "
            "common in legitimately edited files and are not proof of "
            "concealment on their own."
        ),
    )


def normalize_module4_result(
    result: dict[str, Any],
    finding_id: str,
    target_artifact: Optional[str] = None,
) -> EvidenceItem:

    assessment = result.get("assessment", {}) or {}
    severity = assessment.get("severity", "LOW")
    assessment_text = assessment.get("assessment", "NO IMMEDIATE ANOMALY")
    findings = assessment.get("findings", []) or []

    has_anomaly = bool(findings)

    return EvidenceItem(
        finding_id=finding_id,
        source_module="Module 4",
        source_tool="binwalk/xxd",
        category="magic_signature",
        description=(
            f"Structure assessment: {assessment_text}. "
            + ("; ".join(findings) if findings else
               "No structural anomalies were found.")
        ),
        evidence_state=(
            EvidenceState.CANDIDATE
            if has_anomaly
            else EvidenceState.OBSERVATION
        ),
        confidence=None,
        severity=severity,
        target_artifact=target_artifact,
        artifact=None,
        provenance={
            "assessment": assessment_text,
            "severity": severity,
            "findings": findings,
        },
        score_eligible=False,
        rationale=(
            "A structural signature can occur naturally (e.g. inside "
            "compressed image data) and requires interpretation before "
            "it can be treated as embedded content."
        ),
    )


def normalize_module7_result(
    result: dict[str, Any],
    finding_id: str,
    target_artifact: Optional[str] = None,
) -> EvidenceItem:

    finding_count = result.get("finding_count", 0)
    interpretation = result.get("interpretation", "") or ""

    has_candidates = finding_count > 0

    return EvidenceItem(
        finding_id=finding_id,
        source_module="Module 7",
        source_tool="zsteg",
        category="possible_text_interpretation",
        description=(
            f"zsteg reported {finding_count} candidate finding(s). "
            f"{interpretation}".strip()
        ),
        evidence_state=(
            EvidenceState.CANDIDATE
            if has_candidates
            else EvidenceState.OBSERVATION
        ),
        confidence=None,
        target_artifact=target_artifact,
        artifact=None,
        provenance={
            "finding_count": finding_count,
            "findings": result.get("findings", []),
        },
        score_eligible=False,
        rationale=(
            "zsteg candidate output is a detection/ranking result. It "
            "is superseded by Module 8's explicit verification/"
            "extraction outcome for the same artifact."
        ),
    )


def normalize_module10_result(
    result: Any,
    finding_id: str,
    target_artifact: Optional[str] = None,
) -> list[EvidenceItem]:

    scan_completed = bool(getattr(result, "scan_completed", False))
    matches = list(getattr(result, "matches", []) or [])
    assessment = getattr(result, "assessment", "NOT ANALYZED")

    if not scan_completed:
        return [
            EvidenceItem(
                finding_id=finding_id,
                source_module="Module 10",
                source_tool="yara",
                category="yara_match",
                description=(
                    f"YARA analysis did not complete: {assessment}."
                ),
                evidence_state=EvidenceState.INCONCLUSIVE,
                confidence=None,
                target_artifact=target_artifact,
                artifact=None,
                provenance={"assessment": assessment},
                score_eligible=False,
                rationale=(
                    "An incomplete YARA scan (e.g. YARA unavailable "
                    "or no rules found) does not establish the "
                    "absence of matching content."
                ),
            )
        ]

    if not matches:
        return [
            EvidenceItem(
                finding_id=finding_id,
                source_module="Module 10",
                source_tool="yara",
                category="yara_match",
                description="No YARA rules matched the evidence file.",
                evidence_state=EvidenceState.OBSERVATION,
                confidence=None,
                target_artifact=target_artifact,
                artifact=None,
                provenance={
                    "rule_count": getattr(result, "rule_count", 0),
                    "assessment": assessment,
                },
                score_eligible=False,
                rationale=(
                    "Absence of a YARA match does not prove the "
                    "absence of concealed content."
                ),
            )
        ]

    evidence: list[EvidenceItem] = []

    for index, match in enumerate(matches):
        rule_name = getattr(match, "rule_name", "unknown_rule")
        metadata = getattr(match, "metadata", None)
        severity = getattr(metadata, "severity", None) if metadata else None
        description_text = (
            getattr(metadata, "description", None) if metadata else None
        )

        evidence.append(
            EvidenceItem(
                finding_id=f"{finding_id}-{index}",
                source_module="Module 10",
                source_tool="yara",
                category="yara_match",
                description=(
                    f"YARA rule '{rule_name}' matched the evidence "
                    f"file"
                    + (f": {description_text}" if description_text else ".")
                ),
                evidence_state=EvidenceState.CANDIDATE,
                confidence=None,
                severity=severity,
                target_artifact=target_artifact,
                artifact=target_artifact,
                provenance={
                    "rule": rule_name,
                    "namespace": getattr(match, "namespace", None),
                    "tags": getattr(match, "tags", []),
                },
                score_eligible=False,
                rationale=(
                    "A YARA match is a structural/string indicator "
                    "and requires contextual validation; it is not "
                    "automatic proof of malware."
                ),
            )
        )

    return evidence
