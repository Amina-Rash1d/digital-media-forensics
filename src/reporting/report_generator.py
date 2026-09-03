from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

MODULE_NAME = "Module 12 — Forensic Report Generation"
MODULE_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

SECTION_CASE = "case_information"
SECTION_EVIDENCE = "evidence_summary"
SECTION_FINDINGS = "analysis_findings"
SECTION_CORRELATION = "correlation"
SECTION_DECISION = "decision"
SECTION_RISK = "risk_assessment"
SECTION_LIMITATIONS = "limitations"
SECTION_CONCLUSION = "conclusion"


# ---------------------------------------------------------------------------
# Generic serialization helpers
# ---------------------------------------------------------------------------

def _safe_value(value: Any) -> Any:

    if value is None:
        return None

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, dict):
        return {
            str(key): _safe_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            _safe_value(item)
            for item in value
        ]

    if hasattr(value, "value"):
        try:
            return _safe_value(value.value)
        except Exception:
            pass

    if hasattr(value, "__dataclass_fields__"):
        return {
            key: _safe_value(getattr(value, key))
            for key in value.__dataclass_fields__
        }

    return str(value)


def _object_to_dict(value: Any) -> dict[str, Any]:

    if value is None:
        return {}

    if isinstance(value, dict):
        return {
            str(key): _safe_value(item)
            for key, item in value.items()
        }

    if hasattr(value, "__dataclass_fields__"):
        return {
            key: _safe_value(getattr(value, key))
            for key in value.__dataclass_fields__
        }

    if hasattr(value, "__dict__"):
        return {
            key: _safe_value(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }

    return {
        "value": _safe_value(value)
    }


# ---------------------------------------------------------------------------
# Report structures
# ---------------------------------------------------------------------------

@dataclass
class ReportFinding:

    finding_id: str

    source_module: str

    source_tool: Optional[str]

    category: str

    evidence_state: str

    description: str

    severity: Optional[str] = None

    confidence: Optional[float] = None

    target_artifact: Optional[str] = None

    artifact: Optional[str] = None

    rationale: Optional[str] = None

    corroboration_group: Optional[str] = None


@dataclass
class ReportSection:

    title: str

    content: list[str] = field(default_factory=list)


@dataclass
class ForensicReport:

    report_title: str = "Digital Media Forensic Investigation Report"

    module_name: str = MODULE_NAME

    module_version: str = MODULE_VERSION

    case_information: dict[str, Any] = field(
        default_factory=dict
    )

    evidence_summary: dict[str, Any] = field(
        default_factory=dict
    )

    findings: list[ReportFinding] = field(
        default_factory=list
    )

    correlation: dict[str, Any] = field(
        default_factory=dict
    )

    decision: dict[str, Any] = field(
        default_factory=dict
    )

    risk_assessment: dict[str, Any] = field(
        default_factory=dict
    )

    limitations: list[str] = field(
        default_factory=list
    )

    conclusion: list[str] = field(
        default_factory=list
    )

    sections: list[ReportSection] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Evidence conversion
# ---------------------------------------------------------------------------

def _convert_evidence_item(
    evidence: Any,
) -> ReportFinding:

    evidence_state = getattr(
        evidence,
        "evidence_state",
        "",
    )

    if hasattr(evidence_state, "value"):
        evidence_state = evidence_state.value

    return ReportFinding(
        finding_id=str(
            getattr(
                evidence,
                "finding_id",
                "UNKNOWN",
            )
        ),
        source_module=str(
            getattr(
                evidence,
                "source_module",
                "Unknown",
            )
        ),
        source_tool=getattr(
            evidence,
            "source_tool",
            None,
        ),
        category=str(
            getattr(
                evidence,
                "category",
                "unknown",
            )
        ),
        evidence_state=str(
            evidence_state
        ),
        description=str(
            getattr(
                evidence,
                "description",
                "",
            )
        ),
        severity=getattr(
            evidence,
            "severity",
            None,
        ),
        confidence=getattr(
            evidence,
            "confidence",
            None,
        ),
        target_artifact=getattr(
            evidence,
            "target_artifact",
            None,
        ),
        artifact=getattr(
            evidence,
            "artifact",
            None,
        ),
        rationale=getattr(
            evidence,
            "rationale",
            None,
        ),
        corroboration_group=getattr(
            evidence,
            "corroboration_group",
            None,
        ),
    )


def _convert_evidence(
    evidence: list[Any],
) -> list[ReportFinding]:

    findings: list[ReportFinding] = []

    for item in evidence:
        findings.append(
            _convert_evidence_item(item)
        )

    return findings


# ---------------------------------------------------------------------------
# Evidence summary
# ---------------------------------------------------------------------------

def _build_evidence_summary(
    evidence: list[Any],
) -> dict[str, Any]:

    summary = {
        "total": len(evidence),
        "OBSERVATION": 0,
        "INDICATOR": 0,
        "CANDIDATE": 0,
        "EXTRACTION_ATTEMPT": 0,
        "INCONCLUSIVE": 0,
        "EXTRACTED": 0,
        "PLAUSIBLE": 0,
        "VERIFIED": 0,
    }

    for item in evidence:
        state = getattr(
            item,
            "evidence_state",
            None,
        )

        if hasattr(state, "value"):
            state = state.value

        if state in summary:
            summary[state] += 1

    return summary


# ---------------------------------------------------------------------------
# Correlation report
# ---------------------------------------------------------------------------

def _build_correlation_summary(
    correlation_result: Any | None,
) -> dict[str, Any]:

    if correlation_result is None:
        return {
            "available": False,
            "correlation_count": 0,
            "summary": "No correlation result was supplied.",
            "by_artifact": {},
            "corroboration_groups": [],
            "verified_evidence": [],
            "indicator_evidence": [],
            "observation_evidence": [],
            "inconclusive_evidence": [],
        }

    groups = []

    for group in getattr(
        correlation_result,
        "corroboration_groups",
        [],
    ):
        groups.append(
            {
                "group_id": getattr(
                    group,
                    "group_id",
                    None,
                ),
                "evidence_ids": list(
                    getattr(
                        group,
                        "evidence_ids",
                        [],
                    )
                ),
                "verified_ids": list(
                    getattr(
                        group,
                        "verified_ids",
                        [],
                    )
                ),
                "indicator_ids": list(
                    getattr(
                        group,
                        "indicator_ids",
                        [],
                    )
                ),
                "observation_ids": list(
                    getattr(
                        group,
                        "observation_ids",
                        [],
                    )
                ),
                "inconclusive_ids": list(
                    getattr(
                        group,
                        "inconclusive_ids",
                        [],
                    )
                ),
            }
        )

    return {
        "available": True,
        "correlation_count": getattr(
            correlation_result,
            "correlation_count",
            0,
        ),
        "summary": getattr(
            correlation_result,
            "summary",
            "",
        ),
        "by_artifact": _safe_value(
            getattr(
                correlation_result,
                "by_artifact",
                {},
            )
        ),
        "corroboration_groups": groups,
        "verified_evidence": list(
            getattr(
                correlation_result,
                "verified_evidence",
                [],
            )
        ),
        "indicator_evidence": list(
            getattr(
                correlation_result,
                "indicator_evidence",
                [],
            )
        ),
        "observation_evidence": list(
            getattr(
                correlation_result,
                "observation_evidence",
                [],
            )
        ),
        "inconclusive_evidence": list(
            getattr(
                correlation_result,
                "inconclusive_evidence",
                [],
            )
        ),
    }


# ---------------------------------------------------------------------------
# Decision report
# ---------------------------------------------------------------------------

def _build_decision_summary(
    decision_result: Any | None,
) -> dict[str, Any]:

    if decision_result is None:
        return {
            "available": False,
            "assessment": "NOT_AVAILABLE",
            "further_analysis_required": False,
            "rationale": [],
            "warnings": [],
        }

    return {
        "available": True,
        "assessment": getattr(
            decision_result,
            "assessment",
            "UNKNOWN",
        ),
        "evidence_count": getattr(
            decision_result,
            "evidence_count",
            0,
        ),
        "observation_count": getattr(
            decision_result,
            "observation_count",
            0,
        ),
        "candidate_count": getattr(
            decision_result,
            "candidate_count",
            0,
        ),
        "extracted_count": getattr(
            decision_result,
            "extracted_count",
            0,
        ),
        "plausible_count": getattr(
            decision_result,
            "plausible_count",
            0,
        ),
        "verified_count": getattr(
            decision_result,
            "verified_count",
            0,
        ),
        "inconclusive_count": getattr(
            decision_result,
            "inconclusive_count",
            0,
        ),
        "verified_evidence": list(
            getattr(
                decision_result,
                "verified_evidence",
                [],
            )
        ),
        "corroborated_groups": list(
            getattr(
                decision_result,
                "corroborated_groups",
                [],
            )
        ),
        "indicator_findings": list(
            getattr(
                decision_result,
                "indicator_findings",
                [],
            )
        ),
        "further_analysis_required": getattr(
            decision_result,
            "further_analysis_required",
            False,
        ),
        "rationale": list(
            getattr(
                decision_result,
                "rationale",
                [],
            )
        ),
        "warnings": list(
            getattr(
                decision_result,
                "warnings",
                [],
            )
        ),
    }


# ---------------------------------------------------------------------------
# Risk report
# ---------------------------------------------------------------------------

def _build_risk_summary(
    risk_result: Any | None,
) -> dict[str, Any]:

    if risk_result is None:
        return {
            "available": False,
            "score": 0,
            "risk_level": "NOT_AVAILABLE",
            "confidence": "LOW",
            "contributions": [],
            "contributing_findings": [],
            "rationale": [],
            "warnings": [],
        }

    contributions = []

    for contribution in getattr(
        risk_result,
        "contributions",
        [],
    ):
        contributions.append(
            {
                "finding_id": getattr(
                    contribution,
                    "finding_id",
                    None,
                ),
                "category": getattr(
                    contribution,
                    "category",
                    None,
                ),
                "evidence_state": getattr(
                    contribution,
                    "evidence_state",
                    None,
                ),
                "points": getattr(
                    contribution,
                    "points",
                    0,
                ),
                "reason": getattr(
                    contribution,
                    "reason",
                    "",
                ),
            }
        )

    return {
        "available": True,
        "score": getattr(
            risk_result,
            "score",
            0,
        ),
        "risk_level": getattr(
            risk_result,
            "risk_level",
            "UNKNOWN",
        ),
        "confidence": getattr(
            risk_result,
            "confidence",
            "LOW",
        ),
        "contributions": contributions,
        "contributing_findings": list(
            getattr(
                risk_result,
                "contributing_findings",
                [],
            )
        ),
        "rationale": list(
            getattr(
                risk_result,
                "rationale",
                [],
            )
        ),
        "warnings": list(
            getattr(
                risk_result,
                "warnings",
                [],
            )
        ),
    }


# ---------------------------------------------------------------------------
# Limitations
# ---------------------------------------------------------------------------

def _build_limitations(
    evidence: list[Any],
    decision_result: Any | None,
    risk_result: Any | None,
) -> list[str]:

    limitations: list[str] = []

    states = set()

    for item in evidence:
        state = getattr(
            item,
            "evidence_state",
            None,
        )

        if hasattr(state, "value"):
            state = state.value

        states.add(state)

    if "INCONCLUSIVE" in states:
        limitations.append(
            "One or more analysis attempts were inconclusive. "
            "Inconclusive results do not establish that hidden "
            "content is absent."
        )

    if "CANDIDATE" in states:
        limitations.append(
            "Candidate evidence represents an investigative lead "
            "and should not be treated as verified hidden content."
        )

    if "PLAUSIBLE" in states:
        limitations.append(
            "Plausible findings remain below the verification "
            "threshold and require additional validation."
        )

    if "EXTRACTED" in states and "VERIFIED" not in states:
        limitations.append(
            "Extracted content was reported, but no VERIFIED "
            "evidence state was established in the supplied results."
        )

    if any(
        getattr(item, "category", None) == "yara_match"
        for item in evidence
    ):
        limitations.append(
            "YARA matches are contextual indicators and do not "
            "automatically establish maliciousness."
        )

    if risk_result is not None:
        limitations.append(
            "The reported risk score represents evidentiary "
            "suspicion and concealed-content significance; it is "
            "not a probability of maliciousness."
        )

    if decision_result is not None:
        if getattr(
            decision_result,
            "further_analysis_required",
            False,
        ):
            limitations.append(
                "The decision layer identified a need for further "
                "analysis of the available evidence or recovered "
                "artifacts."
            )

    if not evidence:
        limitations.append(
            "No normalized forensic evidence was available for "
            "reporting."
        )

    return limitations


# ---------------------------------------------------------------------------
# Conclusion
# ---------------------------------------------------------------------------

def _build_conclusion(
    report: ForensicReport,
) -> list[str]:

    conclusion: list[str] = []

    decision = report.decision
    risk = report.risk_assessment

    assessment = decision.get(
        "assessment",
        "NOT_AVAILABLE",
    )

    risk_level = risk.get(
        "risk_level",
        "NOT_AVAILABLE",
    )

    risk_score = risk.get(
        "score",
        0,
    )

    if assessment == "CORROBORATED_VERIFIED_HIDDEN_DATA":
        conclusion.append(
            "The investigation established verified hidden-data "
            "recovery with corroboration from multiple related "
            "evidence items."
        )

    elif assessment == "VERIFIED_HIDDEN_DATA":
        conclusion.append(
            "The investigation established verified hidden-data "
            "recovery through the tested forensic analysis."
        )

    elif assessment == "SUSPICIOUS_INDICATORS_PRESENT":
        conclusion.append(
            "The investigation identified suspicious forensic "
            "indicators, but the supplied evidence did not establish "
            "verified hidden-data recovery."
        )

    elif assessment == "INCONCLUSIVE":
        conclusion.append(
            "The investigation did not establish verified hidden-data "
            "recovery from the supplied evidence."
        )

    elif assessment == "NO_CORRELATED_EVIDENCE":
        conclusion.append(
            "No normalized forensic evidence was available to support "
            "a substantive correlated assessment."
        )

    else:
        conclusion.append(
            f"The final evidence assessment was: {assessment}."
        )

    if risk.get("available"):
        conclusion.append(
            f"The evidentiary risk assessment was {risk_level} "
            f"with a score of {risk_score}."
        )

    if decision.get(
        "further_analysis_required",
        False,
    ):
        conclusion.append(
            "Further forensic analysis is recommended based on the "
            "existing evidence and decision-layer assessment."
        )
    else:
        conclusion.append(
            "No additional analysis requirement was identified by "
            "the supplied decision result."
        )

    conclusion.append(
        "The findings describe the forensic evidence recovered "
        "during analysis and do not by themselves establish "
        "malicious intent."
    )

    return conclusion


# ---------------------------------------------------------------------------
# Report section construction
# ---------------------------------------------------------------------------

def _build_sections(
    report: ForensicReport,
) -> list[ReportSection]:

    sections: list[ReportSection] = []

    # Case information
    case_lines: list[str] = []

    if report.case_information:
        for key, value in report.case_information.items():
            case_lines.append(
                f"{key}: {value}"
            )
    else:
        case_lines.append(
            "No case information was supplied."
        )

    sections.append(
        ReportSection(
            title="Case Information",
            content=case_lines,
        )
    )

    # Evidence summary
    evidence_lines = [
        f"Total evidence items: "
        f"{report.evidence_summary.get('total', 0)}",
    ]

    for state in (
        "OBSERVATION",
        "INDICATOR",
        "CANDIDATE",
        "EXTRACTION_ATTEMPT",
        "INCONCLUSIVE",
        "EXTRACTED",
        "PLAUSIBLE",
        "VERIFIED",
    ):
        evidence_lines.append(
            f"{state}: "
            f"{report.evidence_summary.get(state, 0)}"
        )

    sections.append(
        ReportSection(
            title="Evidence Summary",
            content=evidence_lines,
        )
    )

    # Findings
    finding_lines: list[str] = []

    if not report.findings:
        finding_lines.append(
            "No normalized findings were supplied."
        )
    else:
        for finding in report.findings:
            finding_lines.append(
                f"{finding.finding_id} | "
                f"{finding.evidence_state} | "
                f"{finding.category} | "
                f"{finding.description}"
            )

    sections.append(
        ReportSection(
            title="Analysis Findings",
            content=finding_lines,
        )
    )

    # Correlation
    correlation_lines = []

    correlation_lines.append(
        f"Correlation groups: "
        f"{report.correlation.get('correlation_count', 0)}"
    )

    correlation_summary = report.correlation.get(
        "summary",
        "",
    )

    if correlation_summary:
        correlation_lines.append(
            correlation_summary
        )

    sections.append(
        ReportSection(
            title="Evidence Correlation",
            content=correlation_lines,
        )
    )

    # Decision
    decision_lines = [
        "Assessment: "
        f"{report.decision.get('assessment', 'NOT_AVAILABLE')}",
        "Further analysis required: "
        f"{report.decision.get('further_analysis_required', False)}",
    ]

    for reason in report.decision.get(
        "rationale",
        [],
    ):
        decision_lines.append(
            f"Rationale: {reason}"
        )

    sections.append(
        ReportSection(
            title="Evidence Decision",
            content=decision_lines,
        )
    )

    # Risk
    risk_lines = [
        "Score: "
        f"{report.risk_assessment.get('score', 0)}",
        "Risk level: "
        f"{report.risk_assessment.get('risk_level', 'NOT_AVAILABLE')}",
         "Confidence: "
        f"{report.risk_assessment.get('confidence', 'LOW')}",
    ]

    for contribution in report.risk_assessment.get(
        "contributions",
        [],
    ):
        risk_lines.append(
            f"Contribution: "
            f"{contribution['finding_id']} "
            f"+{contribution['points']} "
            f"({contribution['category']})"
        )

    for reason in report.risk_assessment.get(
        "rationale",
        [],
    ):
        risk_lines.append(
            f"Rationale: {reason}"
        )

    sections.append(
        ReportSection(
            title="Risk Assessment",
            content=risk_lines,
        )
    )

    # Limitations
    sections.append(
        ReportSection(
            title="Limitations",
            content=(
                report.limitations
                if report.limitations
                else ["No additional limitations recorded."]
            ),
        )
    )

    # Conclusion
    sections.append(
        ReportSection(
            title="Conclusion",
            content=(
                report.conclusion
                if report.conclusion
                else ["No conclusion generated."]
            ),
        )
    )

    return sections


# ---------------------------------------------------------------------------
# Main report generation
# ---------------------------------------------------------------------------

def generate_report(
    case_info: Optional[dict[str, Any]] = None,
    evidence: Optional[list[Any]] = None,
    correlation_result: Any | None = None,
    decision_result: Any | None = None,
    risk_result: Any | None = None,
    module_results: Optional[dict[str, Any]] = None,
) -> ForensicReport:

    evidence = list(
        evidence
        if evidence is not None
        else []
    )

    report = ForensicReport()

    # ------------------------------------------------------------------
    # Case information
    # ------------------------------------------------------------------

    report.case_information = _safe_value(
        case_info or {}
    )

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    report.evidence_summary = _build_evidence_summary(
        evidence
    )

    report.findings = _convert_evidence(
        evidence
    )

    # ------------------------------------------------------------------
    # Earlier module outputs
    # ------------------------------------------------------------------

    if module_results:
        report.case_information[
            "analysis_modules_available"
        ] = list(
            module_results.keys()
        )

        report.case_information[
            "module_results"
        ] = _safe_value(
            module_results
        )

    # ------------------------------------------------------------------
    # Module 11 outputs
    # ------------------------------------------------------------------

    report.correlation = _build_correlation_summary(
        correlation_result
    )

    report.decision = _build_decision_summary(
        decision_result
    )

    report.risk_assessment = _build_risk_summary(
        risk_result
    )

    # ------------------------------------------------------------------
    # Limitations
    # ------------------------------------------------------------------

    report.limitations = _build_limitations(
        evidence=evidence,
        decision_result=decision_result,
        risk_result=risk_result,
    )

    # ------------------------------------------------------------------
    # Conclusion
    # ------------------------------------------------------------------

    report.conclusion = _build_conclusion(
        report
    )

    # ------------------------------------------------------------------
    # Human-readable sections
    # ------------------------------------------------------------------

    report.sections = _build_sections(
        report
    )

    return report


# ---------------------------------------------------------------------------
# Dictionary / JSON serialization
# ---------------------------------------------------------------------------

def report_to_dict(
    report: ForensicReport,
) -> dict[str, Any]:

    return _safe_value(
        report
    )


def save_json_report(
    report: ForensicReport,
    output_path: str | Path,
) -> Path:

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report_to_dict(report),
            file,
            indent=4,
            ensure_ascii=False,
        )

        file.write("\n")

    return output_path


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

def render_text_report(
    report: ForensicReport,
) -> str:

    lines: list[str] = []

    lines.append(
        report.report_title
    )

    lines.append(
        "=" * len(report.report_title)
    )

    lines.append(
        f"Generator: {report.module_name}"
    )

    lines.append(
        f"Version: {report.module_version}"
    )

    lines.append("")

    for section in report.sections:

        lines.append(
            section.title
        )

        lines.append(
            "-" * len(section.title)
        )

        for content in section.content:
            lines.append(
                f"- {content}"
            )

        lines.append("")

    return "\n".join(
        lines
    ).rstrip() + "\n"


def save_text_report(
    report: ForensicReport,
    output_path: str | Path,
) -> Path:

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        render_text_report(report),
        encoding="utf-8",
    )

    return output_path

# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------

def _pdf_safe_text(value: Any) -> str:

    if value is None:
        return ""

    text = str(value)

    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _pdf_header_footer(
    canvas,
    doc,
) -> None:

    canvas.saveState()

    width, height = A4

    navy = colors.HexColor("#17324D")
    medium_gray = colors.HexColor("#66737F")
    border = colors.HexColor("#CAD3DA")

    case_id = getattr(
        doc,
        "case_id",
        "",
    )

    # Header
    canvas.setStrokeColor(border)
    canvas.setLineWidth(0.5)

    canvas.line(
        20 * mm,
        height - 15 * mm,
        width - 20 * mm,
        height - 15 * mm,
    )

    canvas.setFont(
        "Helvetica-Bold",
        7.5,
    )

    canvas.setFillColor(navy)

    canvas.drawString(
        20 * mm,
        height - 11 * mm,
        "DIGITAL MEDIA FORENSIC REPORT",
    )

    if case_id:
        canvas.setFont(
            "Helvetica",
            7,
        )

        canvas.setFillColor(medium_gray)

        canvas.drawRightString(
            width - 20 * mm,
            height - 11 * mm,
            str(case_id),
        )

    # Footer
    canvas.setStrokeColor(border)

    canvas.line(
        20 * mm,
        15 * mm,
        width - 20 * mm,
        15 * mm,
    )

    canvas.setFont(
        "Helvetica",
        7,
    )

    canvas.setFillColor(medium_gray)

    canvas.drawString(
        20 * mm,
        9 * mm,
        "Digital Media Forensics & Steganalysis Framework",
    )

    canvas.drawRightString(
        width - 20 * mm,
        9 * mm,
        f"Page {doc.page}",
    )

    canvas.restoreState()

def _pdf_module_result(
    report: ForensicReport,
    module_name: str,
) -> dict[str, Any]:

    if not isinstance(report.case_information, dict):
        return {}

    module_results = report.case_information.get(
        "module_results",
        {},
    )

    if not isinstance(module_results, dict):
        return {}

    result = module_results.get(
        module_name,
        {},
    )

    if isinstance(result, dict):
        return result

    return {
        "value": result,
    }


def _build_pdf_styles():

    styles = getSampleStyleSheet()

    navy = colors.HexColor("#17324D")
    blue = colors.HexColor("#2A6F97")
    light_blue = colors.HexColor("#EEF4F8")
    light_gray = colors.HexColor("#F5F7F9")
    medium_gray = colors.HexColor("#66737F")
    dark_gray = colors.HexColor("#28343F")
    border = colors.HexColor("#CAD3DA")
    white = colors.white

    styles.add(
        ParagraphStyle(
            name="ForensicTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=navy,
            alignment=TA_CENTER,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ForensicSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=medium_gray,
            alignment=TA_CENTER,
            spaceAfter=18,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ForensicSection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12.5,
            leading=15,
            textColor=navy,
            spaceBefore=10,
            spaceAfter=7,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ForensicSubsection",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=12,
            textColor=blue,
            spaceBefore=6,
            spaceAfter=4,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ForensicBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=dark_gray,
            spaceAfter=4,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ForensicSmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7.7,
            leading=10,
            textColor=dark_gray,
            spaceAfter=2,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ForensicMuted",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=medium_gray,
            spaceAfter=3,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ForensicMono",
            parent=styles["BodyText"],
            fontName="Courier",
            fontSize=7.2,
            leading=9.5,
            textColor=dark_gray,
            spaceAfter=2,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ForensicCallout",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=navy,
            spaceAfter=2,
        )
    )

    return styles

def _pdf_section_heading(
    title: str,
    styles,
):

    return Paragraph(
        _pdf_safe_text(title),
        styles["ForensicSection"],
    )


def _pdf_key_value_table(
    values: dict[str, Any],
    styles,
):

    rows = []

    for key, value in values.items():

        rows.append(
            [
                Paragraph(
                    _pdf_safe_text(key),
                    styles["ForensicSmall"],
                ),
                Paragraph(
                    _pdf_safe_text(value),
                    styles["ForensicSmall"],
                ),
            ]
        )

    if not rows:
        rows.append(
            [
                Paragraph(
                    "Information",
                    styles["ForensicSmall"],
                ),
                Paragraph(
                    "No information supplied.",
                    styles["ForensicSmall"],
                ),
            ]
        )

    table = Table(
        rows,
        colWidths=[
            52 * mm,
            118 * mm,
        ],
        repeatRows=0,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#EEF4F8"),
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, -1),
                    colors.white,
                ),
                (
                    "LINEBELOW",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor("#D6DEE5"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    return table

def _pdf_bullet_list(
    items: list[str],
    styles,
):

    flowables = []

    if not items:
        items = ["No information supplied."]

    for item in items:
        flowables.append(
            Paragraph(
                f"• {_pdf_safe_text(item)}",
                styles["ForensicBody"],
            )
        )

    return flowables

def save_pdf_report(
    report: ForensicReport,
    output_path: str | Path,
) -> Path:

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ------------------------------------------------------------------
    # Visual design system
    # ------------------------------------------------------------------

    styles = getSampleStyleSheet()

    NAVY = colors.HexColor("#102A43")
    BLUE = colors.HexColor("#1976A3")
    CYAN = colors.HexColor("#36A3C9")
    DARK = colors.HexColor("#243B53")
    TEXT = colors.HexColor("#334E68")
    MUTED = colors.HexColor("#627D98")
    LIGHT = colors.HexColor("#F4F7FA")
    LIGHT_BLUE = colors.HexColor("#EAF4F8")
    BORDER = colors.HexColor("#D9E2EC")
    WHITE = colors.white
    GREEN = colors.HexColor("#218739")
    LIGHT_GREEN = colors.HexColor("#EAF6EC")
    AMBER = colors.HexColor("#B7791F")
    LIGHT_AMBER = colors.HexColor("#FFF7E6")
    RED = colors.HexColor("#C53030")
    LIGHT_RED = colors.HexColor("#FDECEC")

    styles.add(
        ParagraphStyle(
            name="PDFCoverTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=25,
            leading=29,
            textColor=NAVY,
            spaceAfter=4,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFCoverSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=MUTED,
            spaceAfter=2,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFSection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=NAVY,
            spaceBefore=8,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFSubsection",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=12,
            textColor=BLUE,
            spaceBefore=5,
            spaceAfter=4,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=TEXT,
            spaceAfter=4,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFSmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=TEXT,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFLabel",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            textColor=MUTED,
            spaceAfter=1,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFValue",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=DARK,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFMono",
            parent=styles["BodyText"],
            fontName="Courier",
            fontSize=7,
            leading=9,
            textColor=DARK,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFStatus",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=15,
            alignment=TA_CENTER,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFMetric",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=19,
            alignment=TA_CENTER,
            textColor=NAVY,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFMetricLabel",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=6.8,
            leading=8,
            alignment=TA_CENTER,
            textColor=MUTED,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PDFMuted",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7.2,
            leading=10,
            textColor=MUTED,
            spaceAfter=3,
        )
    )

    # ------------------------------------------------------------------
    # Helper functions local to the PDF renderer
    # ------------------------------------------------------------------

    def safe(value: Any) -> str:
        return _pdf_safe_text(value)

    def section(title: str):
        return Paragraph(
            safe(title),
            styles["PDFSection"],
        )

    def small_label(value: Any):
        return Paragraph(
            safe(value),
            styles["PDFLabel"],
        )

    def value_text(value: Any):
        return Paragraph(
            safe(value),
            styles["PDFValue"],
        )

    def make_info_table(
        rows: list[tuple[str, Any]],
    ):
        data = []

        for label, value in rows:
            data.append(
                [
                    Paragraph(
                        safe(label),
                        styles["PDFLabel"],
                    ),
                    Paragraph(
                        safe(value),
                        styles["PDFSmall"],
                    ),
                ]
            )

        table = Table(
            data,
            colWidths=[
                48 * mm,
                122 * mm,
            ],
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        LIGHT_BLUE,
                    ),
                    (
                        "BACKGROUND",
                        (1, 0),
                        (1, -1),
                        WHITE,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.35,
                        BORDER,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ]
            )
        )

        return table

    def make_metric_card(
        label: str,
        value: Any,
        background=LIGHT,
        value_color=NAVY,
    ):
        metric_style = ParagraphStyle(
            name="PDFMetricDynamic",
            parent=styles["PDFMetric"],
            textColor=value_color,
        )

        card = Table(
            [
                [
                    Paragraph(
                        safe(value),
                        metric_style,
                    )
                ],
                [
                    Paragraph(
                        safe(label),
                        styles["PDFMetricLabel"],
                    )
                ],
            ],
            colWidths=[
                52 * mm,
            ],
            rowHeights=[
                11 * mm,
                7 * mm,
            ],
        )

        card.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        background,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.7,
                        BORDER,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                ]
            )
        )

        return card

    def make_status_card(
        status: str,
        background,
        foreground,
        subtitle: str,
    ):
        card = Table(
            [
                [
                    Paragraph(
                        safe(status),
                        ParagraphStyle(
                            name="PDFDynamicStatus",
                            parent=styles["PDFStatus"],
                            textColor=foreground,
                        ),
                    )
                ],
                [
                    Paragraph(
                        safe(subtitle),
                        ParagraphStyle(
                            name="PDFDynamicStatusSmall",
                            parent=styles["PDFSmall"],
                            alignment=TA_CENTER,
                            textColor=foreground,
                            fontName="Helvetica",
                        ),
                    )
                ],
            ],
            colWidths=[
                170 * mm,
            ],
        )

        card.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        background,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        1,
                        foreground,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        10,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        10,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                ]
            )
        )

        return card

    def make_data_table(
        headers: list[str],
        rows: list[list[Any]],
        widths: list[float],
    ):
        table_data = [
            [
                Paragraph(
                    safe(header),
                    ParagraphStyle(
                        name="PDFTableHeader",
                        parent=styles["PDFSmall"],
                        fontName="Helvetica-Bold",
                        textColor=WHITE,
                        alignment=0,
                    ),
                )
                for header in headers
            ]
        ]

        for row in rows:
            table_data.append(
                [
                    Paragraph(
                        safe(value),
                        styles["PDFSmall"],
                    )
                    for value in row
                ]
            )

        table = Table(
            table_data,
            colWidths=widths,
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        NAVY,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        WHITE,
                    ),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [
                            WHITE,
                            LIGHT,
                        ],
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.35,
                        BORDER,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ]
            )
        )

        return table

    def add_bullets(
        items: Any,
        limit: int | None = None,
    ):
        if not isinstance(
            items,
            list,
        ):
            return

        selected = (
            items[:limit]
            if limit is not None
            else items
        )

        for item in selected:
            if isinstance(
                item,
                dict,
            ):
                text = item.get(
                    "description",
                    item.get(
                        "title",
                        "",
                    ),
                )
            else:
                text = item

            if not text:
                continue

            story.append(
                Paragraph(
                    f"• {safe(text)}",
                    styles["PDFBody"],
                )
            )

    # ------------------------------------------------------------------
    # Case information
    # ------------------------------------------------------------------

    case = (
        report.case_information
        if isinstance(
            report.case_information,
            dict,
        )
        else {}
    )

    case_id = case.get(
        "case_id",
        "NOT_AVAILABLE",
    )

    filename = case.get(
        "original_filename",
        "NOT_AVAILABLE",
    )

    file_size = case.get(
        "file_size",
        0,
    )

    file_type = case.get(
        "file_type",
        "NOT_AVAILABLE",
    )

    sha256 = case.get(
        "sha256",
        "NOT_AVAILABLE",
    )

    # ------------------------------------------------------------------
    # Module results
    # ------------------------------------------------------------------

    module1 = _pdf_module_result(
        report,
        "Module 1",
    )

    module2 = _pdf_module_result(
        report,
        "Module 2",
    )

    module3 = _pdf_module_result(
        report,
        "Module 3",
    )

    module4 = _pdf_module_result(
        report,
        "Module 4",
    )

    module5 = _pdf_module_result(
        report,
        "Module 5",
    )

    module6 = _pdf_module_result(
        report,
        "Module 6",
    )

    module7 = _pdf_module_result(
        report,
        "Module 7",
    )

    module8 = _pdf_module_result(
        report,
        "Module 8",
    )

    module9 = _pdf_module_result(
        report,
        "Module 9",
    )

    module10 = _pdf_module_result(
        report,
        "Module 10",
    )

    # ------------------------------------------------------------------
    # Decision / risk
    # ------------------------------------------------------------------

    decision = report.decision or {}
    risk = report.risk_assessment or {}

    final_assessment = decision.get(
        "assessment",
        "NOT_AVAILABLE",
    )

    risk_level = risk.get(
        "risk_level",
        "NOT_AVAILABLE",
    )

    risk_score = risk.get(
        "score",
        0,
    )

    confidence = risk.get(
        "confidence",
        "LOW",
    )

    further_analysis = decision.get(
        "further_analysis_required",
        False,
    )

    # ------------------------------------------------------------------
    # Module 8 — canonical verification state
    # ------------------------------------------------------------------

    zsteg_result = module8.get(
        "zsteg",
        {},
    )

    if not isinstance(
        zsteg_result,
        dict,
    ):
        zsteg_result = {}

    steghide_result = module8.get(
        "steghide",
        {},
    )

    if not isinstance(
        steghide_result,
        dict,
    ):
        steghide_result = {}

    verified = bool(
        module8.get(
            "verified",
            False,
        )
    )

    technique = module8.get(
        "technique",
        "NOT_AVAILABLE",
    )

    if not isinstance(
        technique,
        str,
    ):
        technique = str(
            technique
        )

    verification_score = module8.get(
        "verification_score",
        "NOT_AVAILABLE",
    )

    extracted_path = module8.get(
        "extracted_path",
        "",
    ) or ""

    recovered_text = module8.get(
        "recovered_content",
        "",
    ) or ""

    # ------------------------------------------------------------------
    # Payload information
    # ------------------------------------------------------------------

    payload_path = module9.get(
        "payload_path",
        extracted_path,
    )

    payload_size = module9.get(
        "size_bytes",
        0,
    )

    payload_hash = module9.get(
        "sha256",
        "NOT_AVAILABLE",
    )

    payload_type = module9.get(
        "classification",
        module9.get(
            "file_type",
            "NOT_AVAILABLE",
        ),
    )

    payload_magic = module9.get(
        "magic_signature",
        "Unknown / no known signature",
    )

    payload_strings = module9.get(
        "strings_count",
        0,
    )

    payload_yara = module9.get(
        "yara_matches",
        [],
    )

    if isinstance(
        payload_yara,
        list,
    ):
        payload_yara_count = len(
            payload_yara
        )
    else:
        payload_yara_count = 0

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    try:
        file_size_mb = (
            float(file_size)
            / (1024 * 1024)
        )

        file_size_display = (
            f"{file_size_mb:.2f} MB"
        )

    except (
        TypeError,
        ValueError,
    ):

        file_size_display = str(
            file_size
        )

    try:
        payload_size_display = (
            f"{int(payload_size):,} bytes"
        )

    except (
        TypeError,
        ValueError,
    ):

        payload_size_display = str(
            payload_size
        )

    try:
        score_display = (
            f"{float(verification_score):.3f}"
        )

    except (
        TypeError,
        ValueError,
    ):

        score_display = str(
            verification_score
        )

    hidden_status = (
        "VERIFIED"
        if verified
        else "NOT VERIFIED"
    )

    recovered_content_display = (
        str(
            recovered_text
        ).strip()
        if (
            recovered_text
            and verified
        )
        else
        "No validated recovered text was supplied."
    )

    # ------------------------------------------------------------------
    # Document
    # ------------------------------------------------------------------

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=21 * mm,
        bottomMargin=19 * mm,
        title=report.report_title,
        author=(
            "Digital Media Forensics & "
            "Steganalysis Framework"
        ),
    )

    document.case_id = case_id

    story = []

    # ------------------------------------------------------------------
    # COVER PAGE
    # ------------------------------------------------------------------

    story.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    identity_band = Table(
        [
            [
                Paragraph(
                    "DIGITAL MEDIA",
                    ParagraphStyle(
                        name="PDFCoverBand1",
                        parent=styles["PDFSmall"],
                        fontName="Helvetica-Bold",
                        fontSize=8,
                        textColor=WHITE,
                    ),
                ),
                Paragraph(
                    "FORENSIC INVESTIGATION",
                    ParagraphStyle(
                        name="PDFCoverBand2",
                        parent=styles["PDFSmall"],
                        fontName="Helvetica-Bold",
                        fontSize=8,
                        textColor=WHITE,
                        alignment=2,
                    ),
                ),
            ]
        ],
        colWidths=[
            85 * mm,
            85 * mm,
        ],
    )

    identity_band.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    NAVY,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        identity_band
    )

    story.append(
        Spacer(
            1,
            16 * mm,
        )
    )

    story.append(
        Paragraph(
            "DIGITAL MEDIA",
            ParagraphStyle(
                name="PDFCoverLarge1",
                parent=styles["PDFCoverTitle"],
                fontSize=27,
                leading=30,
                textColor=NAVY,
            ),
        )
    )

    story.append(
        Paragraph(
            "FORENSIC REPORT",
            ParagraphStyle(
                name="PDFCoverLarge2",
                parent=styles["PDFCoverTitle"],
                fontSize=27,
                leading=30,
                textColor=BLUE,
            ),
        )
    )

    story.append(
        Spacer(
            1,
            3 * mm,
        )
    )

    story.append(
        Paragraph(
            "Forensic Media Investigation",
            styles["PDFCoverSubtitle"],
        )
    )

    story.append(
        Spacer(
            1,
            11 * mm,
        )
    )

    case_panel = Table(
        [
            [
                Paragraph(
                    "CASE",
                    styles["PDFLabel"],
                ),
                Paragraph(
                    safe(case_id),
                    styles["PDFValue"],
                ),
            ],
            [
                Paragraph(
                    "EVIDENCE",
                    styles["PDFLabel"],
                ),
                Paragraph(
                    safe(filename),
                    styles["PDFValue"],
                ),
            ],
            [
                Paragraph(
                    "FILE TYPE",
                    styles["PDFLabel"],
                ),
                Paragraph(
                    safe(file_type),
                    styles["PDFSmall"],
                ),
            ],
            [
                Paragraph(
                    "FILE SIZE",
                    styles["PDFLabel"],
                ),
                Paragraph(
                    safe(file_size_display),
                    styles["PDFSmall"],
                ),
            ],
            [
                Paragraph(
                    "SHA-256",
                    styles["PDFLabel"],
                ),
                Paragraph(
                    safe(sha256),
                    styles["PDFMono"],
                ),
            ],
        ],
        colWidths=[
            32 * mm,
            138 * mm,
        ],
    )

    case_panel.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    LIGHT_BLUE,
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, -1),
                    WHITE,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        case_panel
    )

    story.append(
        Spacer(
            1,
            10 * mm,
        )
    )

    if verified:
        status_background = LIGHT_GREEN
        status_foreground = GREEN
        status_subtitle = (
            "Verified hidden-data recovery established"
        )
    else:
        status_background = LIGHT_AMBER
        status_foreground = AMBER
        status_subtitle = (
            "No verified hidden-data recovery established"
        )

    story.append(
        make_status_card(
            hidden_status,
            status_background,
            status_foreground,
            status_subtitle,
        )
    )

    story.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    executive_cards = Table(
        [
            [
                make_metric_card(
                    "FINAL ASSESSMENT",
                    final_assessment,
                    LIGHT_BLUE,
                    NAVY,
                ),
                make_metric_card(
                    "RISK",
                    risk_level,
                    (
                        LIGHT_GREEN
                        if str(risk_level).upper()
                        == "LOW"
                        else LIGHT_AMBER
                    ),
                    (
                        GREEN
                        if str(risk_level).upper()
                        == "LOW"
                        else AMBER
                    ),
                ),
                make_metric_card(
                    "CONFIDENCE",
                    confidence,
                    LIGHT,
                    NAVY,
                ),
            ]
        ],
        colWidths=[
            55 * mm,
            55 * mm,
            55 * mm,
        ],
    )

    executive_cards.setStyle(
        TableStyle(
            [
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    0,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    3,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    0,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    0,
                ),
            ]
        )
    )

    story.append(
        executive_cards
    )

    story.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    if verified:
        executive_text = (
            "The investigation established verified hidden-data "
            "recovery from the supplied evidence."
        )
    else:
        executive_text = (
            "The investigation did not establish verified "
            "hidden-data recovery from the supplied evidence."
        )

    story.append(
        Paragraph(
            safe(executive_text),
            styles["PDFBody"],
        )
    )

    if recovered_text and verified:

        story.append(
            Spacer(
                1,
                2 * mm,
            )
        )

        story.append(
            Paragraph(
                "Recovered Content",
                styles["PDFSubsection"],
            )
        )

        recovered_box = Table(
            [
                [
                    Paragraph(
                        safe(
                            recovered_content_display
                        ),
                        styles["PDFMono"],
                    )
                ]
            ],
            colWidths=[
                170 * mm,
            ],
        )

        recovered_box.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        LIGHT,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.8,
                        BLUE,
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                ]
            )
        )

        story.append(
            recovered_box
        )

    story.append(
        PageBreak()
    )

    # ------------------------------------------------------------------
    # 1. FILE IDENTIFICATION
    # ------------------------------------------------------------------

    story.append(
        section(
            "01  File Identification"
        )
    )

    story.append(
        make_info_table(
            [
                (
                    "Filename",
                    filename,
                ),
                (
                    "File type",
                    file_type,
                ),
                (
                    "File size",
                    file_size_display,
                ),
                (
                    "SHA-256",
                    sha256,
                ),
            ]
        )
    )

    story.append(
        Spacer(
            1,
            5 * mm,
        )
    )

    # ------------------------------------------------------------------
    # 2. TRIAGE
    # ------------------------------------------------------------------

    story.append(
        section(
            "02  Triage"
        )
    )

    string_count = module2.get(
        "string_count",
        "NOT_AVAILABLE",
    )

    story.append(
        make_info_table(
            [
                (
                    "Printable strings identified",
                    string_count,
                ),
                (
                    "Raw string output",
                    (
                        "Preserved in structured analysis artifacts; "
                        "not reproduced in this report."
                    ),
                ),
            ]
        )
    )

    # ------------------------------------------------------------------
    # 3. METADATA FORENSICS
    # ------------------------------------------------------------------

    story.append(
        section(
            "03  Metadata Forensics"
        )
    )

    metadata_assessment = module3.get(
        "assessment",
        {},
    )

    if not isinstance(
        metadata_assessment,
        dict,
    ):
        metadata_assessment = {}

    story.append(
        make_info_table(
            [
                (
                    "Assessment",
                    metadata_assessment.get(
                        "assessment",
                        "NOT_AVAILABLE",
                    ),
                ),
                (
                    "GPS present",
                    (
                        "Yes"
                        if metadata_assessment.get(
                            "gps_present",
                            False,
                        )
                        else "No"
                    ),
                ),
                (
                    "XMP present",
                    (
                        "Yes"
                        if metadata_assessment.get(
                            "xmp_present",
                            False,
                        )
                        else "No"
                    ),
                ),
                (
                    "Editing software detected",
                    (
                        "Yes"
                        if metadata_assessment.get(
                            "editing_software_detected",
                            False,
                        )
                        else "No"
                    ),
                ),
                (
                    "Comments present",
                    (
                        "Yes"
                        if metadata_assessment.get(
                            "comments_present",
                            False,
                        )
                        else "No"
                    ),
                ),
                (
                    "Author present",
                    (
                        "Yes"
                        if metadata_assessment.get(
                            "author_present",
                            False,
                        )
                        else "No"
                    ),
                ),
            ]
        )
    )

    # ------------------------------------------------------------------
    # 4. STRUCTURE ANALYSIS
    # ------------------------------------------------------------------

    story.append(
        section(
            "04  Structure Analysis"
        )
    )

    structure = module4.get(
        "structure",
        {},
    )

    if not isinstance(
        structure,
        dict,
    ):
        structure = {}

    embedded = module4.get(
        "embedded_signatures",
        [],
    )

    embedded_count = (
        len(embedded)
        if isinstance(
            embedded,
            list,
        )
        else 0
    )

    trailing_bytes = structure.get(
        "trailing_bytes",
        0,
    )

    structure_assessment = module4.get(
        "assessment",
        {},
    )

    if isinstance(
        structure_assessment,
        dict,
    ):
        structure_assessment = (
            structure_assessment.get(
                "assessment",
                "NO IMMEDIATE ANOMALY",
            )
        )
    else:
        structure_assessment = (
            "NO IMMEDIATE ANOMALY"
        )

    story.append(
        make_info_table(
            [
                (
                    "Format",
                    structure.get(
                        "format",
                        "NOT_AVAILABLE",
                    ),
                ),
                (
                    "Valid signature",
                    (
                        "Yes"
                        if structure.get(
                            "valid_signature",
                            False,
                        )
                        else "No"
                    ),
                ),
                (
                    "Trailing data",
                    f"{trailing_bytes:,} bytes",
                ),
                (
                    "Embedded file signatures",
                    (
                        "None detected"
                        if embedded_count == 0
                        else str(
                            embedded_count
                        )
                    ),
                ),
                (
                    "Assessment",
                    structure_assessment,
                ),
            ]
        )
    )

    # ------------------------------------------------------------------
    # 5. VISUAL & BIT-PLANE ANALYSIS
    # ------------------------------------------------------------------

    story.append(
        section(
            "05  Visual & Bit-Plane Analysis"
        )
    )

    visual_statistics = module5.get(
        "statistics",
        {},
    )

    if not isinstance(
        visual_statistics,
        dict,
    ):
        visual_statistics = {}

    channel_statistics = visual_statistics.get(
        "channels",
        {},
    )

    if not isinstance(
        channel_statistics,
        dict,
    ):
        channel_statistics = {}

    lsb_stats_visual = visual_statistics.get(
        "bit_planes",
        {},
    )

    if not isinstance(
        lsb_stats_visual,
        dict,
    ):
        lsb_stats_visual = {}

    visual_rows = []

    for channel in (
        "red",
        "green",
        "blue",
    ):

        stats = channel_statistics.get(
            channel,
            {},
        )

        if not isinstance(
            stats,
            dict,
        ):
            stats = {}

        bit_channel = lsb_stats_visual.get(
            channel,
            {},
        )

        if not isinstance(
            bit_channel,
            dict,
        ):
            bit_channel = {}

        bit0 = bit_channel.get(
            "bit_0",
            {},
        )

        if not isinstance(
            bit0,
            dict,
        ):
            bit0 = {}

        visual_rows.append(
            [
                channel.capitalize(),
                f"{stats.get('mean', 0):.4f}",
                f"{stats.get('std_dev', 0):.4f}",
                f"{bit0.get('one_ratio', 0):.4f}",
            ]
        )

    story.append(
        make_data_table(
            [
                "Channel",
                "Mean",
                "Std. deviation",
                "LSB one-ratio",
            ],
            visual_rows,
            [
                38 * mm,
                43 * mm,
                45 * mm,
                44 * mm,
            ],
        )
    )

    visual_findings = module5.get(
        "findings",
        [],
    )

    if isinstance(
        visual_findings,
        list,
    ):

        for item in visual_findings[:3]:

            if not isinstance(
                item,
                dict,
            ):
                continue

            title = item.get(
                "title",
                "",
            )

            description = item.get(
                "description",
                "",
            )

            if title or description:

                story.append(
                    Paragraph(
                        (
                            f"<b>{safe(title)}</b> "
                            f"{safe(description)}"
                        ),
                        styles["PDFBody"],
                    )
                )

    # ------------------------------------------------------------------
    # 6. STATISTICAL ANALYSIS
    # ------------------------------------------------------------------

    story.append(
        section(
            "06  Statistical Analysis"
        )
    )

    lsb_statistics = module6.get(
        "lsb_statistics",
        {},
    )

    if not isinstance(
        lsb_statistics,
        dict,
    ):
        lsb_statistics = {}

    channel_entropy = module6.get(
        "channel_entropy",
        {},
    )

    if not isinstance(
        channel_entropy,
        dict,
    ):
        channel_entropy = {}

    statistical_rows = []

    for channel in (
        "red",
        "green",
        "blue",
    ):

        lsb = lsb_statistics.get(
            channel,
            {},
        )

        if not isinstance(
            lsb,
            dict,
        ):
            lsb = {}

        statistical_rows.append(
            [
                channel.capitalize(),
                f"{lsb.get('one_ratio', 0):.4f}",
                f"{channel_entropy.get(channel, 0):.4f}",
            ]
        )

    story.append(
        make_data_table(
            [
                "Channel",
                "LSB one-ratio",
                "Entropy",
            ],
            statistical_rows,
            [
                55 * mm,
                57 * mm,
                58 * mm,
            ],
        )
    )

    statistical_findings = module6.get(
        "findings",
        [],
    )

    if isinstance(
        statistical_findings,
        list,
    ):

        for item in statistical_findings:

            if not isinstance(
                item,
                dict,
            ):
                continue

            description = item.get(
                "description",
                "",
            )

            if description:
                story.append(
                    Paragraph(
                        safe(description),
                        styles["PDFBody"],
                    )
                )

    story.append(
        Paragraph(
            (
                "<b>Interpretation:</b> Statistical and LSB "
                "measurements are supporting observations and are "
                "not independently treated as proof of hidden data."
            ),
            styles["PDFMuted"],
        )
    )

    # ------------------------------------------------------------------
    # 7. ZSTEG ANALYSIS
    # ------------------------------------------------------------------

    story.append(
        section(
            "07  Automated Steganalysis"
        )
    )

    zsteg_findings = module7.get(
        "findings",
        [],
    )

    zsteg_count = (
        len(zsteg_findings)
        if isinstance(
            zsteg_findings,
            list,
        )
        else module7.get(
            "finding_count",
            0,
        )
    )

    story.append(
        make_metric_card(
            "CANDIDATE OBSERVATIONS",
            zsteg_count,
            LIGHT_BLUE,
            NAVY,
        )
    )

    story.append(
        Spacer(
            1,
            3 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                "Automated steganalysis results are treated as "
                "candidate observations. Confirmation is established "
                "separately through the verification stage."
            ),
            styles["PDFMuted"],
        )
    )

    # ------------------------------------------------------------------
    # 8. VERIFICATION / EXTRACTION
    # ------------------------------------------------------------------

    story.append(
        section(
            "08  Verification & Extraction"
        )
    )

    verification_rows = [
        [
            "Verification status",
            hidden_status,
        ],
        [
            "Technique",
            technique,
        ],
        [
            "Verification score",
            score_display,
        ],
        [
            "Extraction successful",
            (
                "Yes"
                if (verified and extracted_path)
                else "No"
            ),
        ],
        [
            "Recovered payload",
            (
                extracted_path
                or "Not available"
            ),
        ],
    ]

    story.append(
        make_info_table(
            verification_rows
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    if verified:

        story.append(
            make_status_card(
                "VERIFIED RECOVERY",
                LIGHT_GREEN,
                GREEN,
                (
                    "The recovered artifact passed the "
                    "Module 8 verification state."
                ),
            )
        )

    else:

        story.append(
            make_status_card(
                "NO VERIFIED RECOVERY",
                LIGHT_AMBER,
                AMBER,
                (
                    "Extraction attempts did not establish "
                    "verified hidden-data recovery."
                ),
            )
        )

    if recovered_text and verified:

        story.append(
            Spacer(
                1,
                4 * mm,
            )
        )

        story.append(
            Paragraph(
                "Validated Recovered Content",
                styles["PDFSubsection"],
            )
        )

        content_box = Table(
            [
                [
                    Paragraph(
                        safe(
                            recovered_content_display
                        ),
                        styles["PDFMono"],
                    )
                ]
            ],
            colWidths=[
                170 * mm,
            ],
        )

        content_box.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        LIGHT,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.8,
                        BLUE,
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                ]
            )
        )

        story.append(
            content_box
        )

    # Technique-specific Steghide detail remains supporting evidence.
    if isinstance(
        steghide_result,
        dict,
    ):

        steghide_extracted = steghide_result.get(
            "extracted",
            False,
        )

        story.append(
            Spacer(
                1,
                3 * mm,
            )
        )

        story.append(
            Paragraph(
                (
                    "<b>Steghide:</b> "
                    +
                    (
                        "Extraction succeeded under tested conditions."
                        if steghide_extracted
                        else
                        "Extraction was unsuccessful under the tested "
                        "conditions; this does not establish absence "
                        "of hidden data."
                    )
                ),
                styles["PDFBody"],
            )
        )

    # ------------------------------------------------------------------
    # 9. PAYLOAD ANALYSIS
    # ------------------------------------------------------------------

    story.append(
        section(
            "09  Payload Analysis"
        )
    )

    payload_exists = bool(
        module9.get(
            "exists",
            False,
        )
    )

    payload_rows = [
        [
            "Payload status",
            (
                "IDENTIFIED"
                if payload_exists
                else "NOT IDENTIFIED"
            ),
        ],
        [
            "Classification",
            payload_type,
        ],
        [
            "File type",
            module9.get(
                "file_type",
                "NOT_AVAILABLE",
            ),
        ],
        [
            "Size",
            payload_size_display,
        ],
        [
            "Payload SHA-256",
            payload_hash,
        ],
        [
            "Magic signature",
            payload_magic,
        ],
        [
            "Printable strings",
            payload_strings,
        ],
        [
            "YARA matches",
            payload_yara_count,
        ],
        [
            "Archive container",
            (
                "Yes"
                if module9.get(
                    "archive_container",
                    False,
                )
                else "No"
            ),
        ],
    ]

    story.append(
        make_info_table(
            payload_rows
        )
    )

    payload_findings = module9.get(
        "findings",
        [],
    )

    if isinstance(
        payload_findings,
        list,
    ):

        for finding in payload_findings[:4]:

            if finding:
                story.append(
                    Paragraph(
                        f"• {safe(finding)}",
                        styles["PDFBody"],
                    )
                )

    # ------------------------------------------------------------------
    # 10. YARA DETECTION
    # ------------------------------------------------------------------

    story.append(
        section(
            "10  YARA Detection"
        )
    )

    yara_available = module10.get(
        "available",
        False,
    )

    yara_rules = module10.get(
        "rules_loaded",
        0,
    )

    yara_matches = module10.get(
        "matches",
        [],
    )

    if isinstance(
        yara_matches,
        list,
    ):
        yara_match_count = len(
            yara_matches
        )
    else:
        yara_match_count = 0

    yara_assessment = module10.get(
        "assessment",
        {},
    )

    if isinstance(
        yara_assessment,
        dict,
    ):
        yara_assessment = yara_assessment.get(
            "assessment",
            "NOT_AVAILABLE",
        )

    story.append(
        Table(
            [
                [
                    make_metric_card(
                        "YARA AVAILABLE",
                        (
                            "YES"
                            if yara_available
                            else "NO"
                        ),
                        LIGHT_BLUE,
                        NAVY,
                    ),
                    make_metric_card(
                        "RULES LOADED",
                        yara_rules,
                        LIGHT,
                        NAVY,
                    ),
                    make_metric_card(
                        "MATCHES",
                        yara_match_count,
                        (
                            LIGHT_GREEN
                            if yara_match_count == 0
                            else LIGHT_RED
                        ),
                        (
                            GREEN
                            if yara_match_count == 0
                            else RED
                        ),
                    ),
                ]
            ],
            colWidths=[
                55 * mm,
                55 * mm,
                55 * mm,
            ],
        )
    )

    story.append(
        Spacer(
            1,
            3 * mm,
        )
    )

    story.append(
        Paragraph(
            safe(yara_assessment),
            styles["PDFBody"],
        )
    )

    # ------------------------------------------------------------------
    # 11. EVIDENCE CORRELATION, DECISION & RISK
    # ------------------------------------------------------------------

    story.append(
        section(
            "11  Evidence Correlation, Decision & Risk"
        )
    )

    correlation_count = report.correlation.get(
        "correlation_count",
        0,
    )

    story.append(
        Table(
            [
                [
                    make_metric_card(
                        "CORRELATION GROUPS",
                        correlation_count,
                        LIGHT_BLUE,
                        NAVY,
                    ),
                    make_metric_card(
                        "RISK SCORE",
                        risk_score,
                        (
                            LIGHT_GREEN
                            if str(risk_level).upper()
                            == "LOW"
                            else LIGHT_AMBER
                        ),
                        (
                            GREEN
                            if str(risk_level).upper()
                            == "LOW"
                            else AMBER
                        ),
                    ),
                    make_metric_card(
                        "FURTHER ANALYSIS",
                        (
                            "YES"
                            if further_analysis
                            else "NO"
                        ),
                        (
                            LIGHT_AMBER
                            if further_analysis
                            else LIGHT_GREEN
                        ),
                        (
                            AMBER
                            if further_analysis
                            else GREEN
                        ),
                    ),
                ]
            ],
            colWidths=[
                55 * mm,
                55 * mm,
                55 * mm,
            ],
        )
    )

    story.append(
        Spacer(
            1,
            5 * mm,
        )
    )

    correlation_summary = report.correlation.get(
        "summary",
        "",
    )

    if correlation_summary:

        story.append(
            Paragraph(
                safe(correlation_summary),
                styles["PDFBody"],
            )
        )

    story.append(
        Paragraph(
            "Decision",
            styles["PDFSubsection"],
        )
    )

    story.append(
        make_info_table(
            [
                (
                    "Final decision",
                    final_assessment,
                ),
                (
                    "Further analysis required",
                    (
                        "Yes"
                        if further_analysis
                        else "No"
                    ),
                ),
            ]
        )
    )

    decision_rationale = decision.get(
        "rationale",
        [],
    )

    if isinstance(
        decision_rationale,
        list,
    ) and decision_rationale:

        story.append(
            Paragraph(
                "Decision rationale",
                styles["PDFSubsection"],
            )
        )

        add_bullets(
            decision_rationale
        )

    risk_rationale = risk.get(
        "rationale",
        [],
    )

    if isinstance(
        risk_rationale,
        list,
    ) and risk_rationale:

        story.append(
            Paragraph(
                "Risk rationale",
                styles["PDFSubsection"],
            )
        )

        add_bullets(
            risk_rationale
        )

    # ------------------------------------------------------------------
    # 12. INVESTIGATOR CONCLUSION
    # ------------------------------------------------------------------

    story.append(
        section(
            "12  Investigator Conclusion"
        )
    )

    if isinstance(
        report.conclusion,
        list,
    ):

        add_bullets(
            report.conclusion
        )

    # ------------------------------------------------------------------
    # LIMITATIONS
    # ------------------------------------------------------------------

    story.append(
        section(
            "Limitations"
        )
    )

    if isinstance(
        report.limitations,
        list,
    ):

        add_bullets(
            report.limitations
        )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                "Full machine-readable module results and raw tool "
                "artifacts are preserved separately. This PDF presents "
                "only selected evidence required for investigator "
                "interpretation and case-level reporting."
            ),
            styles["PDFMuted"],
        )
    )

    # ------------------------------------------------------------------
    # Professional header / footer
    # ------------------------------------------------------------------

    def draw_page_chrome(
        canvas,
        doc,
    ) -> None:

        canvas.saveState()

        width, height = A4

        canvas.setFillColor(
            NAVY
        )

        canvas.rect(
            0,
            height - 5 * mm,
            width,
            5 * mm,
            stroke=0,
            fill=1,
        )

        canvas.setFont(
            "Helvetica-Bold",
            7.5,
        )

        canvas.setFillColor(
            NAVY
        )

        canvas.drawString(
            20 * mm,
            height - 12 * mm,
            "DIGITAL MEDIA FORENSIC REPORT",
        )

        canvas.setFont(
            "Helvetica",
            7,
        )

        canvas.setFillColor(
            MUTED
        )

        canvas.drawRightString(
            width - 20 * mm,
            height - 12 * mm,
            str(case_id),
        )

        canvas.setStrokeColor(
            BORDER
        )

        canvas.setLineWidth(
            0.5
        )

        canvas.line(
            20 * mm,
            13 * mm,
            width - 20 * mm,
            13 * mm,
        )

        canvas.setFont(
            "Helvetica",
            6.8,
        )

        canvas.setFillColor(
            MUTED
        )

        canvas.drawString(
            20 * mm,
            8 * mm,
            "Digital Media Forensics & Steganalysis Framework",
        )

        canvas.drawRightString(
            width - 20 * mm,
            8 * mm,
            f"PAGE {doc.page}",
        )

        canvas.restoreState()

    # ------------------------------------------------------------------
    # Build PDF
    # ------------------------------------------------------------------

    document.build(
        story,
        onFirstPage=draw_page_chrome,
        onLaterPages=draw_page_chrome,
    )

    return output_path

# ---------------------------------------------------------------------------
# Console report
 # ---------------------------------------------------------------------------

def print_report(
    report: ForensicReport,
) -> None:

    print(
        render_text_report(report)
    )


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def generate_and_save_report(
    case_info: Optional[dict[str, Any]] = None,
    evidence: Optional[list[Any]] = None,
    correlation_result: Any | None = None,
    decision_result: Any | None = None,
    risk_result: Any | None = None,
    module_results: Optional[dict[str, Any]] = None,
    output_directory: str | Path = "reports",
    report_name: str = "forensic_report",
) -> ForensicReport:

    report = generate_report(
        case_info=case_info,
        evidence=evidence,
        correlation_result=correlation_result,
        decision_result=decision_result,
        risk_result=risk_result,
        module_results=module_results,
    )

    output_directory = Path(
        output_directory
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    save_json_report(
        report,
        output_directory / f"{report_name}.json",
    )

    save_text_report(
        report,
        output_directory / f"{report_name}.txt",
    )

    save_pdf_report(
        report,
        output_directory / f"{report_name}.pdf",
    )

    return report

# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    import json
    import sys
    import tempfile
    from pathlib import Path

    # ------------------------------------------------------------------
    # Make project root importable when this file is executed directly.
    #
    # Supports:
    #
    #     python src/reporting/report_generator.py
    #
    # and:
    #
    #     python -m src.reporting.report_generator
    # ------------------------------------------------------------------

    PROJECT_ROOT = Path(__file__).resolve().parents[2]

    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    try:

        # ------------------------------------------------------------------
        # Import Module 11 structures
        # ------------------------------------------------------------------

        from src.correlation.evidence import (
            EvidenceItem,
            EvidenceState,
        )

        from src.correlation.correlate import (
            correlate_evidence,
        )

        from src.correlation.decision import (
            decide_from_correlated_evidence,
        )

        from src.correlation.risk import (
            calculate_risk,
        )

        # ------------------------------------------------------------------
        # Verify ReportLab is available
        # ------------------------------------------------------------------

        try:
            import reportlab

        except ImportError as exc:
            raise RuntimeError(
                "ReportLab is required for the Module 12 PDF "
                f"self-test: {exc}"
            ) from exc

        # ------------------------------------------------------------------
        # Temporary self-test directory
        # ------------------------------------------------------------------

        test_dir = Path(
            tempfile.mkdtemp(
                prefix="module12_test_"
            )
        )

        text_report = (
            test_dir / "forensic_report.txt"
        )

        json_report = (
            test_dir / "forensic_report.json"
        )

        pdf_report = (
            test_dir / "forensic_report.pdf"
        )

        # ------------------------------------------------------------------
        # Synthetic forensic evidence
        # ------------------------------------------------------------------
        #
        # These findings simulate normalized evidence produced by
        # Modules 1–11.
        #
        # The test intentionally contains:
        #
        #   - observation
        #   - YARA indicator
        #   - verified extraction
        #   - second verified finding
        #   - inconclusive extraction
        #
        # This exercises correlation, decision, risk and reporting.
        # ------------------------------------------------------------------

        evidence = [

            EvidenceItem(
                finding_id="TEST-OBS-001",
                source_module="Module 9",
                source_tool="file",
                category="file_type",
                description=(
                    "Recovered payload identified as ASCII text."
                ),
                evidence_state=EvidenceState.OBSERVATION,
                target_artifact="test_image.png",
                rationale=(
                    "The recovered artifact was identified as "
                    "printable ASCII text."
                ),
            ),

            EvidenceItem(
                finding_id="TEST-IND-001",
                source_module="Module 10",
                source_tool="YARA",
                category="yara_match",
                description=(
                    "YARA rule matched an executable-content indicator."
                ),
                evidence_state=EvidenceState.INDICATOR,
                target_artifact="test_image.png",
                severity="medium",
                confidence=0.82,
                rationale=(
                    "The rule match is an investigative indicator "
                    "requiring contextual validation."
                ),
            ),

            EvidenceItem(
                finding_id="TEST-VER-001",
                source_module="Module 8",
                source_tool="steghide",
                category="extraction_attempt",
                description=(
                    "Hidden payload was successfully recovered."
                ),
                evidence_state=EvidenceState.VERIFIED,
                target_artifact="test_image.png",
                artifact=str(
                    test_dir / "recovered_payload.bin"
                ),
                confidence=0.98,
                corroboration_group="TEST-CORR-001",
                rationale=(
                    "The hidden payload was successfully extracted "
                    "and validated."
                ),
            ),

            EvidenceItem(
                finding_id="TEST-VER-002",
                source_module="Module 9",
                source_tool="payload_analysis",
                category="possible_embedded_file",
                description=(
                    "Recovered payload contains a structurally "
                    "consistent embedded file."
                ),
                evidence_state=EvidenceState.VERIFIED,
                target_artifact="test_image.png",
                artifact=str(
                    test_dir / "recovered_payload.bin"
                ),
                confidence=0.94,
                corroboration_group="TEST-CORR-001",
                rationale=(
                    "Independent payload analysis supports the "
                    "existence and structure of the recovered content."
                ),
            ),

            EvidenceItem(
                finding_id="TEST-INC-001",
                source_module="Module 8",
                source_tool="extraction",
                category="extraction_attempt",
                description=(
                    "An additional extraction technique produced "
                    "an inconclusive result."
                ),
                evidence_state=EvidenceState.INCONCLUSIVE,
                target_artifact="test_image.png",
                rationale=(
                    "The extraction attempt did not establish "
                    "whether additional hidden content exists."
                ),
            ),
        ]

        # ------------------------------------------------------------------
        # Create synthetic recovered payload file.
        # ------------------------------------------------------------------

        payload_file = (
            test_dir / "recovered_payload.bin"
        )

        payload_file.write_bytes(
            b"This is a synthetic recovered payload "
            b"used for Module 12 self-testing.\n"
        )

        # ------------------------------------------------------------------
        # Correlation
        # ------------------------------------------------------------------

        correlation_result = correlate_evidence(
            evidence
        )

        # ------------------------------------------------------------------
        # Decision
        # ------------------------------------------------------------------

        decision_result = decide_from_correlated_evidence(
            evidence=evidence,
            correlation_result=correlation_result,
        )

        # ------------------------------------------------------------------
        # Risk assessment
        # ------------------------------------------------------------------

        risk_result = calculate_risk(
            evidence=evidence,
            correlation_result=correlation_result,
        )

        # ------------------------------------------------------------------
        # Case information
        # ------------------------------------------------------------------

        case_info = {
            "case_id": "CASE-TEST-001",
            "original_filename": "test_image.png",
            "file_size": 12345,
            "sha256": (
                "0123456789abcdef"
                "0123456789abcdef"
                "0123456789abcdef"
                "0123456789abcdef"
            ),
            "file_type": "PNG image data",
        }

        # ------------------------------------------------------------------
        # Generate structured Module 12 report
        # ------------------------------------------------------------------

        report_result = generate_report(
            case_info=case_info,
            evidence=evidence,
            correlation_result=correlation_result,
            decision_result=decision_result,
            risk_result=risk_result,
            module_results={
                "Module 1": {
                    "status": "available",
                },
                "Module 2": {
                    "status": "available",
                },
                "Module 3": {
                    "status": "available",
                },
                "Module 4": {
                    "status": "available",
                },
                "Module 5": {
                    "status": "available",
                },
                "Module 6": {
                    "status": "available",
                },
                "Module 7": {
                    "status": "available",
                },
                "Module 8": {
                    "status": "available",
                },
                "Module 9": {
                    "status": "available",
                },
                "Module 10": {
                    "status": "available",
                },
                "Module 11": {
                    "status": "available",
                },
            },
        )

        # ------------------------------------------------------------------
        # Save JSON report
        # ------------------------------------------------------------------

        save_json_report(
            report_result,
            json_report,
        )

        # ------------------------------------------------------------------
        # Save text report
        # ------------------------------------------------------------------

        save_text_report(
            report_result,
            text_report,
        )

        # ------------------------------------------------------------------
        # Save PDF report
        #
        # IMPORTANT:
        # The self-test uses the actual Module 12 PDF renderer.
        # It does NOT create a separate PDF implementation.
        # ------------------------------------------------------------------

        save_pdf_report(
            report_result,
            pdf_report,
        )

        # ------------------------------------------------------------------
        # Locate generated files
        # ------------------------------------------------------------------

        generated_text = None
        generated_json = None
        generated_pdf = None

        possible_text_files = [
            test_dir / "forensic_report.txt",
            test_dir / "report.txt",
            test_dir / "forensic_report.md",
            test_dir / "report.md",
        ]

        possible_json_files = [
            test_dir / "forensic_report.json",
            test_dir / "report.json",
        ]

        possible_pdf_files = [
            test_dir / "forensic_report.pdf",
            test_dir / "report.pdf",
        ]

        for path in possible_text_files:

            if path.exists():
                generated_text = path
                break

        for path in possible_json_files:

            if path.exists():
                generated_json = path
                break

        for path in possible_pdf_files:

            if path.exists():
                generated_pdf = path
                break

        # ------------------------------------------------------------------
        # Require text report
        # ------------------------------------------------------------------

        if generated_text is None:

            raise RuntimeError(
                "Module 12 self-test completed the report-generation "
                "call but no text report was produced."
            )

        if generated_text.stat().st_size == 0:

            raise RuntimeError(
                f"Generated text report is empty: "
                f"{generated_text}"
            )

        # ------------------------------------------------------------------
        # Require JSON report
        # ------------------------------------------------------------------

        if generated_json is None:

            raise RuntimeError(
                "Module 12 self-test completed the report-generation "
                "call but no JSON report was produced."
            )

        if generated_json.stat().st_size == 0:

            raise RuntimeError(
                f"Generated JSON report is empty: "
                f"{generated_json}"
            )

        # ------------------------------------------------------------------
        # Validate JSON syntax
        # ------------------------------------------------------------------

        with generated_json.open(
            "r",
            encoding="utf-8",
        ) as file:

            parsed_json = json.load(file)

        if not isinstance(
            parsed_json,
            dict,
        ):

            raise RuntimeError(
                "Generated JSON report does not contain a "
                "top-level JSON object."
            )

        # ------------------------------------------------------------------
        # Require PDF report
        # ------------------------------------------------------------------

        if generated_pdf is None:

            raise RuntimeError(
                "Module 12 self-test completed the report-generation "
                "call but no PDF report was produced."
            )

        if generated_pdf.stat().st_size == 0:

            raise RuntimeError(
                f"Generated PDF report is empty: "
                f"{generated_pdf}"
            )

        # ------------------------------------------------------------------
        # Validate PDF file signature
        # ------------------------------------------------------------------

        with generated_pdf.open(
            "rb"
        ) as file:

            pdf_signature = file.read(5)

        if pdf_signature != b"%PDF-":

            raise RuntimeError(
                "Generated PDF does not have a valid PDF "
                "file signature."
            )

        # ------------------------------------------------------------------
        # Validate PDF is not suspiciously tiny
        # ------------------------------------------------------------------

        if generated_pdf.stat().st_size < 1000:

            raise RuntimeError(
                "Generated PDF is unexpectedly small and may "
                "not contain the expected report content."
            )

        # ------------------------------------------------------------------
        # Validate required JSON sections
        # ------------------------------------------------------------------

        required_json_keys = [
            "report_title",
            "module_name",
            "module_version",
            "case_information",
            "evidence_summary",
            "findings",
            "correlation",
            "decision",
            "risk_assessment",
            "limitations",
            "conclusion",
            "sections",
        ]

        for key in required_json_keys:

            if key not in parsed_json:

                raise RuntimeError(
                    "Generated JSON report is missing required "
                    f"section: {key}"
                )

        # ------------------------------------------------------------------
        # Validate evidence count
        # ------------------------------------------------------------------

        if len(
            parsed_json.get(
                "findings",
                [],
            )
        ) != len(evidence):

            raise RuntimeError(
                "Generated report finding count does not match "
                "the supplied evidence count."
            )

        # ------------------------------------------------------------------
        # Validate correlation
        # ------------------------------------------------------------------

        if parsed_json["correlation"].get(
            "correlation_count"
        ) != correlation_result.correlation_count:

            raise RuntimeError(
                "Generated report correlation count does not "
                "match Module 11 correlation output."
            )

        # ------------------------------------------------------------------
        # Validate decision
        # ------------------------------------------------------------------

        if parsed_json["decision"].get(
            "assessment"
        ) != str(
            decision_result.assessment
        ):

            raise RuntimeError(
                "Generated report decision assessment does not "
                "match Module 11 decision output."
            )

        # ------------------------------------------------------------------
        # Validate risk
        # ------------------------------------------------------------------

        if parsed_json["risk_assessment"].get(
            "score"
        ) != risk_result.score:

            raise RuntimeError(
                "Generated report risk score does not match "
                "Module 11 risk output."
            )

        # ------------------------------------------------------------------
        # Final successful self-test output
        # ------------------------------------------------------------------

        print(
            "Module 12 self-test passed."
        )

        print()

        print(
            f"Test directory: {test_dir}"
        )

        print(
            f"Text report:    {generated_text}"
        )

        print(
            f"JSON report:    {generated_json}"
        )

        print(
            f"PDF report:     {generated_pdf}"
        )

        print()

        print(
            f"Evidence items: {len(evidence)}"
        )

        print(
            f"Correlations:   "
            f"{correlation_result.correlation_count}"
        )

        print(
            f"Assessment:     "
            f"{decision_result.assessment}"
        )

        print(
            f"Risk score:     "
            f"{risk_result.score}"
        )

        print(
            f"Risk level:     "
            f"{risk_result.risk_level}"
        )

        print()

        print(
            "Generated files:"
        )

        for path in sorted(
            test_dir.iterdir()
        ):

            print(
                f"- {path.name} "
                f"({path.stat().st_size} bytes)"
            )

    except Exception as exc:

        print(
            "Module 12 self-test failed:"
        )

        print(
            f"{type(exc).__name__}: {exc}"
        )

        raise

