#!/usr/bin/env python3

from pathlib import Path
from typing import Any

from src.core.file_identifier import identify_file
from src.core.case_manager import create_case

from src.analysis.triage import triage_file
from src.analysis.metadata_forensics import build_metadata_result
from src.analysis.file_structure import build_structure_result
from src.analysis.visual_analysis import analyze_visual
from src.analysis.statistical_analysis import analyze_statistics
from src.analysis.zsteg_analysis import analyze_zsteg
from src.analysis.verify_extract import verify_and_extract
from src.analysis.payload_analysis import analyze_payload

from src.detection.yara_scan import analyze as yara_analyze

from src.correlation.normalize import (
    normalize_module2_result,
    normalize_module3_result,
    normalize_module4_result,
    normalize_module7_result,
    normalize_module8_result,
    normalize_module9_result,
    normalize_module10_result,
)
from src.correlation.correlate import correlate_evidence
from src.correlation.decision import decide_from_correlated_evidence
from src.correlation.risk import calculate_risk

from src.reporting.report_generator import generate_and_save_report


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent

DEFAULT_ANALYSIS_DIR = PROJECT_ROOT / "analysis"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"
DEFAULT_EXTRACTION_DIR = PROJECT_ROOT / "extracted"

DEFAULT_YARA_RULES = PROJECT_ROOT / "src" / "rules"


# ---------------------------------------------------------------------------
# PIPELINE
# ---------------------------------------------------------------------------

def run_pipeline(
    input_file: str,
    analysis_directory: str | Path = DEFAULT_ANALYSIS_DIR,
    report_directory: str | Path = DEFAULT_REPORT_DIR,
    extraction_directory: str | Path = DEFAULT_EXTRACTION_DIR,
    yara_rules_path: str | Path = DEFAULT_YARA_RULES,
    candidate_passphrases: list[str] | None = None,
) -> dict[str, Any]:

    input_path = Path(
        input_file
    ).expanduser().resolve()

    if not input_path.exists():
        raise FileNotFoundError(
            f"Input file does not exist: {input_path}"
        )

    if not input_path.is_file():
        raise ValueError(
            f"Input path is not a regular file: {input_path}"
        )

    yara_rules_path = Path(
        yara_rules_path
    ).expanduser().resolve()

    # ------------------------------------------------------------------
    # RESULT CONTAINER
    # ------------------------------------------------------------------

    module_results: dict[str, Any] = {}

    evidence = []

    # ------------------------------------------------------------------
    # MODULE 1 — FILE IDENTIFICATION
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 1 — FILE IDENTIFICATION")
    print("=" * 80)

    module1_result = identify_file(
        str(input_path)
    )

    module_results["Module 1"] = module1_result

    print("Module 1 complete.")

    # ------------------------------------------------------------------
    # CORE — CASE CREATION
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("CASE INITIALIZATION")
    print("=" * 80)

    case_info = create_case(
        str(input_path)
    )

    module_results["Case"] = case_info

    print("Case created.")

    # ------------------------------------------------------------------
    # CASE-SPECIFIC PATHS
    # ------------------------------------------------------------------

    evidence_path = Path(
        case_info["evidence_path"]
    ).resolve()

    case_directory = (
        evidence_path.parent.parent
    )

    analysis_directory = (
        case_directory / "analysis"
    )

    report_directory = (
        case_directory / "report"
    )

    extraction_directory = (
        case_directory / "extracted"
    )

    analysis_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    extraction_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(
        f"Case ID: {case_info['case_id']}"
    )

    print(
        f"Preserved evidence: {evidence_path}"
    )

    # ------------------------------------------------------------------
    # MODULE 2 — TRIAGE
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 2 — TRIAGE")
    print("=" * 80)

    module2_result = triage_file(
        str(evidence_path)
    )

    module_results["Module 2"] = module2_result

    # Module 2 evidence is normalized before entering the
    # correlation/decision/risk layer.
    evidence.append(
        normalize_module2_result(
            result=module2_result,
            finding_id="MOD2-TRIAGE",
            target_artifact=str(evidence_path),
        )
    )

    print("Module 2 complete.")

    # ------------------------------------------------------------------
    # MODULE 3 — METADATA FORENSICS
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 3 — METADATA FORENSICS")
    print("=" * 80)

    module3_result = build_metadata_result(
        str(evidence_path)
    )

    module_results["Module 3"] = module3_result

    # Module 3 evidence is normalized before entering the
    # correlation/decision/risk layer.
    evidence.append(
        normalize_module3_result(
            result=module3_result,
            finding_id="MOD3-METADATA",
            target_artifact=str(evidence_path),
        )
    )

    print("Module 3 complete.")

    # ------------------------------------------------------------------
    # MODULE 4 — STRUCTURE ANALYSIS
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 4 — STRUCTURE ANALYSIS")
    print("=" * 80)

    module4_result = build_structure_result(
        str(evidence_path)
    )

    module_results["Module 4"] = module4_result

    # Module 4 evidence is normalized before entering the
    # correlation/decision/risk layer.
    evidence.append(
        normalize_module4_result(
            result=module4_result,
            finding_id="MOD4-STRUCTURE",
            target_artifact=str(evidence_path),
        )
    )

    print("Module 4 complete.")

    # ------------------------------------------------------------------
    # MODULE 5 — VISUAL ANALYSIS
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 5 — VISUAL ANALYSIS")
    print("=" * 80)

    module5_result = analyze_visual(
        str(evidence_path)
    )

    module_results["Module 5"] = module5_result

    print("Module 5 complete.")

    # ------------------------------------------------------------------
    # MODULE 6 — STATISTICAL ANALYSIS
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 6 — STATISTICAL ANALYSIS")
    print("=" * 80)

    module6_output_directory = (
        analysis_directory / "statistical"
    )

    module6_output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    module6_result = analyze_statistics(
        str(evidence_path),
        str(module6_output_directory),
    )

    module_results["Module 6"] = module6_result

    print("Module 6 complete.")

    # ------------------------------------------------------------------
    # MODULE 7 — ZSTEG ANALYSIS
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 7 — ZSTEG ANALYSIS")
    print("=" * 80)

    module7_output_directory = (
        analysis_directory / "zsteg"
    )

    module7_output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    module7_result = analyze_zsteg(
        str(evidence_path),
        str(module7_output_directory),
    )

    module_results["Module 7"] = module7_result

    # zsteg findings are candidate/pre-verification evidence.
    # Module 8 remains authoritative for verification/extraction.
    evidence.append(
        normalize_module7_result(
            result=module7_result,
            finding_id="MOD7-ZSTEG",
            target_artifact=str(evidence_path),
        )
    )

    print("Module 7 complete.")

    # ------------------------------------------------------------------
    # MODULE 8 — VERIFICATION / EXTRACTION
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 8 — VERIFICATION / EXTRACTION")
    print("=" * 80)

    module8_result = verify_and_extract(
        str(evidence_path),
        candidate_passphrases=candidate_passphrases,
        output_dir=str(extraction_directory),
    )

    module_results["Module 8"] = module8_result

    print("Module 8 complete.")

    # ------------------------------------------------------------------
    # MODULE 8 → MODULE 11
    # NORMALIZE EXTRACTION RESULT
    # ------------------------------------------------------------------

    module8_evidence = normalize_module8_result(
        result=module8_result,
        finding_id="MOD8-001",
        target_artifact=str(evidence_path),
    )

    evidence.append(
        module8_evidence
    )

    # ------------------------------------------------------------------
    # MODULE 9 — PAYLOAD ANALYSIS
    # ------------------------------------------------------------------

    payload_result = None
    module9_evidence = []

    extracted_payload = None

    # Module 8 is the authoritative source for recovered payloads.
    # Do not fall back to technique-specific extraction paths because
    # those may represent candidate or non-verified results.
    if isinstance(module8_result, dict):

        if module8_result.get(
            "verified",
            False,
        ):
            extracted_payload = module8_result.get(
                "extracted_path"
            )

    print("\n" + "=" * 80)
    print("MODULE 9 — PAYLOAD ANALYSIS")
    print("=" * 80)

    if extracted_payload:

        payload_path = Path(
            extracted_payload
        ).expanduser().resolve()

        if payload_path.exists():

            print(
                f"Recovered payload found: {payload_path}"
            )

            module9_result = analyze_payload(
                str(payload_path),
                yara_rules_path=str(yara_rules_path),
            )

            payload_result = module9_result

            module_results["Module 9"] = (
                module9_result
            )

            module9_evidence = (
                normalize_module9_result(
                    result=module9_result,
                    finding_id="MOD9",
                    target_artifact=str(evidence_path),
                )
            )

            evidence.extend(
                module9_evidence
            )

        else:

            print(
                "Module 8 reported an extraction path, "
                "but the payload file does not exist."
            )

            module_results["Module 9"] = None

    else:

        print(
            "No recovered payload was available."
        )

        module_results["Module 9"] = None

    # ------------------------------------------------------------------
    # MODULE 10 — YARA DETECTION
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 10 — YARA DETECTION")
    print("=" * 80)

    module10_result = yara_analyze(
        target_path=str(evidence_path),
        rules_path=str(yara_rules_path),
    )

    module_results["Module 10"] = (
        module10_result
    )

    # Module 10 YARA findings are normalized before entering
    # correlation, decision, and risk assessment.
    evidence.extend(
        normalize_module10_result(
            result=module10_result,
            finding_id="MOD10-YARA",
            target_artifact=str(evidence_path),
        )
    )

    print("Module 10 complete.")

    # ------------------------------------------------------------------
    # MODULE 11 — CORRELATION
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 11 — CORRELATION")
    print("=" * 80)

    correlation_result = correlate_evidence(
        evidence
    )

    print("Correlation complete.")

    # ------------------------------------------------------------------
    # MODULE 11 — DECISION
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 11 — DECISION")
    print("=" * 80)

    decision_result = decide_from_correlated_evidence(
        evidence=evidence,
        correlation_result=correlation_result,
    )

    print("Decision complete.")

    # ------------------------------------------------------------------
    # MODULE 11 — RISK
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 11 — RISK ASSESSMENT")
    print("=" * 80)

    risk_result = calculate_risk(
        evidence=evidence,
        correlation_result=correlation_result,
    )

    print("Risk assessment complete.")

    # ------------------------------------------------------------------
    # MODULE 12 — REPORTING
    # ------------------------------------------------------------------

    print("\n" + "=" * 80)
    print("MODULE 12 — FORENSIC REPORTING")
    print("=" * 80)

    report_result = generate_and_save_report(
        case_info=case_info,
        evidence=evidence,
        correlation_result=correlation_result,
        decision_result=decision_result,
        risk_result=risk_result,
        module_results=module_results,
        output_directory=report_directory,
        report_name="forensic_report",
    )

    print("Reports generated.")

    print(
        f"Reports saved to: {report_directory}"
    )

    # ------------------------------------------------------------------
    # FINAL RESULT
    # ------------------------------------------------------------------

    return {
        "case": case_info,

        "module_results": module_results,

        "evidence": evidence,

        "correlation": correlation_result,

        "decision": decision_result,

        "risk": risk_result,

        "report": report_result,
    }


# ---------------------------------------------------------------------------
# COMMAND-LINE INTERFACE
# ---------------------------------------------------------------------------

def main() -> int:

    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Digital Media Forensics & "
            "Steganalysis Framework"
        )
    )

    parser.add_argument(
        "input_file",
        help="Path to the suspicious image/audio file",
    )

    parser.add_argument(
        "--analysis-dir",
        default=str(
            DEFAULT_ANALYSIS_DIR
        ),
        help="Directory for analysis artifacts",
    )

    parser.add_argument(
        "--report-dir",
        default=str(
            DEFAULT_REPORT_DIR
        ),
        help="Directory for forensic reports",
    )

    parser.add_argument(
        "--extraction-dir",
        default=str(
            DEFAULT_EXTRACTION_DIR
        ),
        help="Directory for recovered payloads",
    )

    parser.add_argument(
        "--yara-rules",
        default=str(
            DEFAULT_YARA_RULES
        ),
        help="Directory containing YARA rules",
    )

    parser.add_argument(
        "--passphrase",
        action="append",
        default=None,
        help=(
            "Candidate passphrase for Module 8. "
            "Can be supplied multiple times."
        ),
    )

    args = parser.parse_args()

    try:

        result = run_pipeline(
            input_file=args.input_file,
            analysis_directory=args.analysis_dir,
            report_directory=args.report_dir,
            extraction_directory=args.extraction_dir,
            yara_rules_path=args.yara_rules,
            candidate_passphrases=args.passphrase,
        )

        print("\n" + "=" * 80)
        print("INTEGRATED FORENSIC PIPELINE COMPLETE")
        print("=" * 80)

        decision = result.get(
            "decision"
        )

        risk = result.get(
            "risk"
        )

        if decision is not None:

            print(
                f"Final assessment: "
                f"{getattr(decision, 'assessment', 'N/A')}"
            )

        if risk is not None:

            print(
                f"Risk level: "
                f"{getattr(risk, 'risk_level', 'N/A')}"
            )

            print(
                f"Risk score: "
                f"{getattr(risk, 'score', 'N/A')}"
            )

        case_info = result.get(
            "case",
            {}
        )

        evidence_path = case_info.get(
            "evidence_path"
        )

        if evidence_path:

            case_directory = (
                Path(
                    evidence_path
                ).resolve().parent.parent
            )

            print(
                f"\nCase ID: "
                f"{case_info.get('case_id', 'N/A')}"
            )

            print(
                f"Case directory: "
                f"{case_directory}"
            )

            print(
                f"Reports saved to: "
                f"{case_directory / 'report'}"
            )

        return 0

    except Exception as exc:

        print(
            "\nPIPELINE ERROR:"
        )

        print(
            f"{type(exc).__name__}: {exc}"
        )

        return 1


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(
        main()
    )
