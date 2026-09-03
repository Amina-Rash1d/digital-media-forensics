#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------

SCRIPT_PATH = Path(__file__).resolve()
PROJECT_ROOT = SCRIPT_PATH.parents[2]

DEFAULT_RULES_PATH = PROJECT_ROOT / "src" / "rules"


# ---------------------------------------------------------------------------
# DATA STRUCTURES
# ---------------------------------------------------------------------------

@dataclass
class RuleMetadata:

    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[str] = None
    rule_file: Optional[str] = None

@dataclass
class YaraMatch:

    rule_name: str
    namespace: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    metadata: Optional[RuleMetadata] = None


@dataclass
class YaraResult:

    target: str
    target_exists: bool = False
    target_readable: bool = False

    yara_available: bool = False
    yara_path: Optional[str] = None
    yara_version: Optional[str] = None

    rules_path: Optional[str] = None
    rule_files: list[str] = field(default_factory=list)
    rule_count: int = 0

    scan_completed: bool = False
    matches: list[YaraMatch] = field(default_factory=list)

    findings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    assessment: str = "NOT ANALYZED"


# ---------------------------------------------------------------------------
# GENERAL HELPERS
# ---------------------------------------------------------------------------

def command_exists(command: str) -> Optional[str]:

    return shutil.which(command)


def run_command(
    command: list[str],
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:

    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )


# ---------------------------------------------------------------------------
# TARGET VALIDATION
# ---------------------------------------------------------------------------

def validate_target(target: Path, result: YaraResult) -> bool:

    if not target.exists():
        result.errors.append(
            f"Target does not exist: {target}"
        )
        return False

    result.target_exists = True

    if not os.access(target, os.R_OK):
        result.errors.append(
            f"Target is not readable: {target}"
        )
        return False

    result.target_readable = True

    return True


# ---------------------------------------------------------------------------
# YARA AVAILABILITY
# ---------------------------------------------------------------------------

def detect_yara(result: YaraResult) -> bool:

    yara_path = command_exists("yara")

    if yara_path is None:
        result.errors.append(
            "YARA is not installed or is not available in PATH."
        )
        return False

    result.yara_available = True
    result.yara_path = yara_path

    try:
        proc = run_command(
            [yara_path, "--version"],
            timeout=10,
        )

        version = proc.stdout.strip()

        if proc.returncode == 0 and version:
            result.yara_version = version
        else:
            result.errors.append(
                "YARA was found, but its version could not be determined."
            )

    except (OSError, subprocess.TimeoutExpired) as exc:
        result.errors.append(
            f"Unable to query YARA version: {exc}"
        )

    return True


# ---------------------------------------------------------------------------
# RULE DISCOVERY
# ---------------------------------------------------------------------------

def discover_rule_files(
    rules_path: Path,
    result: YaraResult,
) -> list[Path]:

    if not rules_path.exists():
        result.errors.append(
            f"YARA rules path does not exist: {rules_path}"
        )
        return []

    if rules_path.is_file():
        if rules_path.suffix.lower() not in {".yar", ".yara"}:
            result.errors.append(
                f"Rules file does not have a .yar or .yara extension: "
                f"{rules_path}"
            )
            return []

        return [rules_path]

    files = sorted(
        [
            path
            for path in rules_path.rglob("*")
            if path.is_file()
            and path.suffix.lower() in {".yar", ".yara"}
        ]
    )

    if not files:
        result.errors.append(
            f"No YARA rule files were found under: {rules_path}"
        )

    return files


# ---------------------------------------------------------------------------
# RULE METADATA PARSING
# ---------------------------------------------------------------------------

def _extract_quoted_value(
    text: str,
    key: str,
) -> Optional[str]:

    pattern = rf"{re.escape(key)}\s*=\s*\"([^\"]*)\""

    match = re.search(
        pattern,
        text,
        flags=re.IGNORECASE,
    )

    if match:
        return match.group(1)

    return None


def parse_rule_metadata(
    rule_file: Path,
) -> dict[str, RuleMetadata]:

    try:
        text = rule_file.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return {}

    metadata: dict[str, RuleMetadata] = {}

    rule_pattern = re.compile(
        r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)"
        r"(?:\s*:\s*([^{]+))?"
        r"\s*\{(.*?)\}",
        flags=re.IGNORECASE | re.DOTALL,
    )

    for match in rule_pattern.finditer(text):
        rule_name = match.group(1)
        tags_text = match.group(2) or ""
        body = match.group(3)

        description = _extract_quoted_value(
            body,
            "description",
        )

        category = _extract_quoted_value(
            body,
            "category",
        )

        severity = _extract_quoted_value(
            body,
            "severity",
        )

        confidence = _extract_quoted_value(
            body,
            "confidence",
        )

        metadata[rule_name] = RuleMetadata(
            name=rule_name,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            rule_file=str(rule_file),
        )

    return metadata

def load_rule_metadata(
    rule_files: list[Path],
) -> dict[str, RuleMetadata]:

    combined: dict[str, RuleMetadata] = {}

    for rule_file in rule_files:
        combined.update(
            parse_rule_metadata(rule_file)
        )

    return combined


# ---------------------------------------------------------------------------
# RULE COUNTING
# ---------------------------------------------------------------------------

def count_rules(
    rule_files: list[Path],
) -> int:

    count = 0

    pattern = re.compile(
        r"(?m)^\s*rule\s+"
        r"[A-Za-z_][A-Za-z0-9_]*"
        r"(?:\s*:\s*[^{]+)?\s*\{"
    )

    for rule_file in rule_files:

        try:
            text = rule_file.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            continue

        # Remove block comments before counting declarations.
        text = re.sub(
            r"/\*.*?\*/",
            "",
            text,
            flags=re.DOTALL,
        )

        # Remove single-line comments.
        text = re.sub(
            r"//.*?$",
            "",
            text,
            flags=re.MULTILINE,
        )

        count += len(
            pattern.findall(text)
        )

    return count

# ---------------------------------------------------------------------------
# RULE COMPILATION / VALIDATION
# ---------------------------------------------------------------------------

def validate_rules(
    yara_path: str,
    rules_path: Path,
    result: YaraResult,
) -> bool:

    rule_files = [
        Path(path)
        for path in result.rule_files
    ]

    if not rule_files:
        result.errors.append(
            "No YARA rule files are available for validation."
        )
        return False

    for rule_file in rule_files:

        try:
            proc = run_command(
                [
                    yara_path,
                    "-w",
                    str(rule_file),
                    "/dev/null",
                ],
                timeout=30,
            )

        except subprocess.TimeoutExpired:
            result.errors.append(
                f"YARA rule validation timed out: {rule_file}"
            )
            return False

        except OSError as exc:
            result.errors.append(
                f"Unable to validate YARA rules: {exc}"
            )
            return False

        if proc.returncode not in {0, 1}:

            error_text = (
                proc.stderr.strip()
                or proc.stdout.strip()
                or "Unknown YARA compilation error."
            )

            result.errors.append(
                f"YARA rule validation failed for "
                f"{rule_file}: {error_text}"
            )

            return False

    return True

# ---------------------------------------------------------------------------
# YARA OUTPUT PARSING
# ---------------------------------------------------------------------------

def parse_yara_output(
    output: str,
    metadata: dict[str, RuleMetadata],
) -> list[YaraMatch]:

    matches: list[YaraMatch] = []

    for raw_line in output.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        parts = line.split()

        if not parts:
            continue

        rule_token = parts[0]

        namespace = None
        rule_name = rule_token

        if "." in rule_token:
            namespace, rule_name = rule_token.rsplit(
                ".",
                1,
            )

        rule_metadata = metadata.get(rule_name)

        matches.append(
            YaraMatch(
                rule_name=rule_name,
                namespace=namespace,
                metadata=rule_metadata,
            )
        )

    return matches


# ---------------------------------------------------------------------------
# SCANNING
# ---------------------------------------------------------------------------

def scan_target(
    target: Path,
    yara_path: str,
    rules_path: Path,
    rule_metadata: dict[str, RuleMetadata],
    result: YaraResult,
    timeout: int = 60,
) -> bool:

    rule_files = [
        Path(path)
        for path in result.rule_files
    ]

    if not rule_files:
        result.errors.append(
            "No YARA rule files are available for scanning."
        )
        return False

    command = [
        yara_path,
        "-w",
    ]

    command.extend(
        str(rule_file)
        for rule_file in rule_files
    )

    command.append(
        str(target)
    )

    try:
        proc = run_command(
            command,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired:
        result.errors.append(
            f"YARA scan timed out after {timeout} seconds."
        )
        return False

    except OSError as exc:
        result.errors.append(
            f"YARA execution failed: {exc}"
        )
        return False

    # YARA return codes:
    #
    # 0 = one or more rules matched
    # 1 = no rules matched
    # 2+ = execution or rule error

    if proc.returncode not in {0, 1}:

        error_text = (
            proc.stderr.strip()
            or proc.stdout.strip()
            or "Unknown YARA scanning error."
        )

        result.errors.append(
            f"YARA returned exit code {proc.returncode}: "
            f"{error_text}"
        )

        return False

    result.scan_completed = True

    result.matches = parse_yara_output(
        proc.stdout,
        rule_metadata,
    )

    return True

# ---------------------------------------------------------------------------
# FINDINGS / ASSESSMENT
# ---------------------------------------------------------------------------

def build_findings(
    result: YaraResult,
) -> None:

    if not result.scan_completed:
        return

    if not result.matches:

        result.findings.append(
            "No custom YARA rule matched the target."
        )

        result.findings.append(
            "No known pattern represented by the loaded rule set "
            "was detected."
        )

        result.findings.append(
            "A YARA no-match result does not prove that the target "
            "is benign or free of concealed content."
        )

        result.assessment = (
            "NO KNOWN YARA INDICATORS DETECTED"
        )

        return

    informational = []
    low_medium = []
    anomalies = []

    for match in result.matches:

        metadata = match.metadata

        if metadata is None:
            low_medium.append(match)
            continue

        category = (
            metadata.category.lower()
            if metadata.category
            else ""
        )

        if category in {
            "file_identification",
            "container_identification",
            "executable_identification",
        }:
            informational.append(match)
        elif category == "forensic_anomaly":
            anomalies.append(match)
        else:
            low_medium.append(match)

    result.findings.append(
        f"{len(result.matches)} custom YARA rule match(es) "
        "were detected."
    )

    if informational:
        result.findings.append(
            f"{len(informational)} match(es) identify file, "
            "container, or executable characteristics."
        )

    if low_medium:
        result.findings.append(
            f"{len(low_medium)} match(es) identify scripting "
            "or executable-related indicators."
        )

    if anomalies:
        result.findings.append(
            f"{len(anomalies)} forensic anomaly rule(s) matched "
            "and warrant further investigation."
        )

    for match in result.matches:

        metadata = match.metadata

        if metadata is None:
            result.findings.append(
                f"Rule {match.rule_name} matched."
            )
            continue

        severity = (
            metadata.severity.upper()
            if metadata.severity
            else "UNSPECIFIED"
        )

        category = (
            metadata.category
            if metadata.category
            else "uncategorized"
        )

        description = (
            metadata.description
            if metadata.description
            else "No rule description provided."
        )

        result.findings.append(
            f"Rule {match.rule_name} matched "
            f"(severity={severity}, category={category}): "
            f"{description}"
        )

    if anomalies:
        result.assessment = (
            "FORENSIC YARA ANOMALY INDICATOR(S) DETECTED"
        )
    elif low_medium:
        result.assessment = (
            "YARA INDICATOR(S) DETECTED"
        )
    else:
        result.assessment = (
            "YARA FILE/CONTAINER INDICATOR(S) DETECTED"
        )


# ---------------------------------------------------------------------------
# MAIN ANALYSIS FUNCTION
# ---------------------------------------------------------------------------

def analyze(
    target_path: str,
    rules_path: Optional[str] = None,
    timeout: int = 60,
) -> YaraResult:

    target = Path(target_path).expanduser().resolve()

    if rules_path is None:
        rules = DEFAULT_RULES_PATH
    else:
        rules = Path(rules_path).expanduser()

        if not rules.is_absolute():
            rules = (
                PROJECT_ROOT / rules
            )

        rules = rules.resolve()

    result = YaraResult(
        target=str(target),
        rules_path=str(rules),
    )

    # Target
    if not validate_target(target, result):
        result.assessment = "TARGET INVALID"
        return result

    # YARA
    if not detect_yara(result):
        result.assessment = (
            "YARA ANALYSIS UNAVAILABLE"
        )
        return result

    # Rules
    rule_files = discover_rule_files(
        rules,
        result,
    )

    result.rule_files = [
        str(path)
        for path in rule_files
    ]

    result.rule_count = count_rules(
        rule_files
    )

    if not rule_files:
        result.assessment = (
            "YARA ANALYSIS UNAVAILABLE"
        )
        return result

    # Metadata
    metadata = load_rule_metadata(
        rule_files
    )

    # Validate rules
    if not validate_rules(
        result.yara_path,
        rules,
        result,
    ):
        result.assessment = (
            "YARA RULE VALIDATION FAILED"
        )
        return result

    # Scan
    if not scan_target(
        target=target,
        yara_path=result.yara_path,
        rules_path=rules,
        rule_metadata=metadata,
        result=result,
        timeout=timeout,
    ):
        result.assessment = (
            "YARA SCAN FAILED"
        )
        return result

    # Findings
    build_findings(result)

    return result


# ---------------------------------------------------------------------------
# REPORTING
# ---------------------------------------------------------------------------

def print_result(result: YaraResult) -> None:

    print()
    print("YARA ARTIFACT DETECTION")
    print("────────────────────────────────────────")
    print()

    print("Target:")
    print(result.target)
    print()

    print("Exists:")
    print("YES" if result.target_exists else "NO")
    print()

    print("Readable:")
    print("YES" if result.target_readable else "NO")
    print()

    print("YARA:")
    if result.yara_available:
        print("AVAILABLE")
    else:
        print("UNAVAILABLE")
    print()

    if result.yara_path:
        print("YARA binary:")
        print(result.yara_path)
        print()

    if result.yara_version:
        print("YARA version:")
        print(result.yara_version)
        print()

    print("Rules path:")
    print(result.rules_path or "NOT AVAILABLE")
    print()

    print("Rule files:")
    print(len(result.rule_files))
    print()

    print("Rules loaded:")
    print(result.rule_count)
    print()

    print("Scan:")
    if result.scan_completed:
        print("COMPLETED")
    else:
        print("NOT COMPLETED")
    print()

    print("Matches:")
    print(len(result.matches))
    print()

    if result.matches:

        for index, match in enumerate(
            result.matches,
            start=1,
        ):

            print(f"Match {index}:")
            print(f"  Rule: {match.rule_name}")

            if match.namespace:
                print(
                    f"  Namespace: {match.namespace}"
                )

            if match.metadata:

                metadata = match.metadata

                print(
                    "  Description: "
                    f"{metadata.description or 'N/A'}"
                )

                print(
                    "  Category: "
                    f"{metadata.category or 'N/A'}"
                )

                severity = (
                    metadata.severity.upper()
                    if metadata.severity
                    else "N/A"
                )

                print(
                    "  Severity: "
                    f"{severity}"
                )

            print()

    print("Findings:")

    if result.findings:
        for finding in result.findings:
            print(f"  - {finding}")
    else:
        print("  - None")

    print()

    print("Errors / limitations:")

    if result.errors:
        for error in result.errors:
            print(f"  - {error}")
    else:
        print("  - None")

    print()

    print("Assessment:")
    print(result.assessment)
    print()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "Module 10 — YARA Artifact Detection"
        )
    )

    parser.add_argument(
        "target",
        help="Evidence or recovered payload to scan.",
    )

    parser.add_argument(
        "--rules",
        default=str(DEFAULT_RULES_PATH),
        help=(
            "YARA rule file or directory. "
            "Default: project/src/rules"
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Maximum YARA scan time in seconds.",
    )

    return parser


def main() -> int:

    parser = build_argument_parser()
    args = parser.parse_args()

    result = analyze(
        target_path=args.target,
        rules_path=args.rules,
        timeout=args.timeout,
    )

    print_result(result)

    if result.assessment in {
        "YARA ANALYSIS UNAVAILABLE",
        "YARA RULE VALIDATION FAILED",
        "YARA SCAN FAILED",
        "TARGET INVALID",
    }:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
