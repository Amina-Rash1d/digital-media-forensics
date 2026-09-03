from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import zipfile

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_STRINGS_MIN_LENGTH = 4
DEFAULT_YARA_TIMEOUT = 30

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_YARA_RULES = PROJECT_ROOT / "src" / "rules"


# ---------------------------------------------------------------------------
# Common magic signatures
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
    b"BM": "BMP image",
    b"PK\x03\x04": "ZIP archive / ZIP-based container",
    b"%PDF": "PDF document",
    b"\x7fELF": "ELF executable",
    b"MZ": "PE/Windows executable",
    b"Rar!\x1a\x07\x00": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"\x1f\x8b": "GZIP compressed data",
    b"BZh": "BZIP2 compressed data",
    b"\xfd7zXZ\x00": "XZ compressed data",
}


# ---------------------------------------------------------------------------
# Nested signatures
# ---------------------------------------------------------------------------

INTERNAL_SIGNATURES = {
    b"PK\x03\x04": "ZIP",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"%PDF": "PDF",
    b"\x7fELF": "ELF",
    b"MZ": "PE",
    b"Rar!\x1a\x07\x00": "RAR",
    b"7z\xbc\xaf\x27\x1c": "7-Zip",
}


# ---------------------------------------------------------------------------
# Result data structures
# ---------------------------------------------------------------------------

@dataclass
class ArchiveEntry:
    """Information about one archive member."""

    name: str = ""
    size_bytes: int = 0
    compressed_size_bytes: int = 0
    is_directory: bool = False


@dataclass
class YaraMatch:
    """Structured YARA match."""

    rule: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class PayloadResult:

    payload_path: str = ""

    exists: bool = False
    readable: bool = False

    size_bytes: int = 0
    sha256: str = ""

    file_type: str = ""

    magic_signature: str = ""
    magic_match: bool = False

    classification: str = ""

    strings_count: int = 0
    strings: list[str] = field(default_factory=list)

    metadata_available: bool = False
    metadata_summary: list[str] = field(default_factory=list)

    yara_available: bool = False
    yara_rules_path: Optional[str] = None
    yara_matches: list[YaraMatch] = field(default_factory=list)

    archive_container: bool = False
    archive_type: str = ""
    archive_entries: list[ArchiveEntry] = field(default_factory=list)

    nested_content_suspected: bool = False

    further_analysis_required: bool = False

    assessment: str = ""

    findings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Basic payload validation
# ---------------------------------------------------------------------------

def validate_payload_path(payload_path: str) -> tuple[bool, str]:

    if not payload_path:
        return False, "No payload path supplied."

    path = Path(payload_path)

    if not path.exists():
        return False, "Payload file does not exist."

    if not path.is_file():
        return False, "Payload path is not a regular file."

    if not os.access(path, os.R_OK):
        return False, "Payload file is not readable."

    return True, ""


# ---------------------------------------------------------------------------
# SHA-256
# ---------------------------------------------------------------------------

def calculate_sha256(
    file_path: str,
    chunk_size: int = 1024 * 1024,
) -> str:

    digest = hashlib.sha256()

    with open(file_path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# ---------------------------------------------------------------------------
# File type identification
# ---------------------------------------------------------------------------

def identify_file_type(
    file_path: str,
    timeout: int = 10,
) -> str:

    file_binary = shutil.which("file")

    if file_binary is None:
        raise RuntimeError(
            "The 'file' command is not available."
        )

    proc = subprocess.run(
        [
            file_binary,
            "--brief",
            file_path,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    output = proc.stdout.strip()

    if proc.returncode != 0:
        error = proc.stderr.strip()

        raise RuntimeError(
            error or "file command failed."
        )

    return output


# ---------------------------------------------------------------------------
# Magic/signature analysis
# ---------------------------------------------------------------------------

def read_magic_bytes(
    file_path: str,
    length: int = 32,
) -> bytes:

    with open(file_path, "rb") as handle:
        return handle.read(length)


def identify_magic_signature(
    file_path: str,
) -> tuple[str, bool]:

    header = read_magic_bytes(file_path)

    for signature, description in MAGIC_SIGNATURES.items():
        if header.startswith(signature):
            return description, True

    return "Unknown / no known signature", False


# ---------------------------------------------------------------------------
# Printable strings
# ---------------------------------------------------------------------------

def extract_printable_strings(
    file_path: str,
    minimum_length: int = DEFAULT_STRINGS_MIN_LENGTH,
) -> list[str]:

    with open(file_path, "rb") as handle:
        data = handle.read()

    strings_found: list[str] = []
    current = bytearray()

    for byte in data:

        if 32 <= byte <= 126:
            current.append(byte)

        else:
            if len(current) >= minimum_length:
                strings_found.append(
                    current.decode(
                        "ascii",
                        errors="replace",
                    )
                )

            current = bytearray()

    if len(current) >= minimum_length:
        strings_found.append(
            current.decode(
                "ascii",
                errors="replace",
            )
        )

    return strings_found


# ---------------------------------------------------------------------------
# Payload classification
# ---------------------------------------------------------------------------

def classify_payload(
    file_type: str,
    magic_signature: str,
    strings_found: list[str],
) -> str:

    lowered = file_type.lower()

    if any(
        keyword in lowered
        for keyword in (
            "ascii text",
            "utf-8 unicode text",
            "unicode text",
            "text",
        )
    ):
        return "TEXT"

    if any(
        keyword in lowered
        for keyword in (
            "png",
            "jpeg",
            "jpg",
            "gif",
            "bmp",
            "image",
        )
    ):
        return "IMAGE"

    if any(
        keyword in lowered
        for keyword in (
            "zip",
            "rar",
            "7-zip",
            "archive",
            "gzip",
            "bzip",
            "xz",
            "compressed",
        )
    ):
        return "ARCHIVE"

    if any(
        keyword in lowered
        for keyword in (
            "elf",
            "executable",
            "pe32",
            "shared object",
        )
    ):
        return "EXECUTABLE"

    if any(
        keyword in lowered
        for keyword in (
            "pdf",
            "document",
            "microsoft",
            "office",
        )
    ):
        return "DOCUMENT"

    if magic_signature == "ELF executable":
        return "EXECUTABLE"

    if strings_found:
        return "BINARY_WITH_PRINTABLE_STRINGS"

    if file_type:
        return "BINARY"

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Metadata analysis
# ---------------------------------------------------------------------------

def analyze_metadata(
    file_path: str,
    file_type: str,
    timeout: int = 15,
) -> tuple[bool, list[str], Optional[str]]:
    """
    Perform lightweight metadata analysis where ExifTool is applicable.

    Returns:
        (available, summary, error)
    """

    exiftool = shutil.which("exiftool")

    if exiftool is None:
        return (
            False,
            [],
            "ExifTool is not installed.",
        )

    lowered = file_type.lower()

    applicable = any(
        keyword in lowered
        for keyword in (
            "image",
            "png",
            "jpeg",
            "jpg",
            "gif",
            "bmp",
            "pdf",
            "document",
            "microsoft",
            "office",
        )
    )

    if not applicable:
        return False, [], None

    try:
        proc = subprocess.run(
            [
                exiftool,
                "-s",
                "-G1",
                "-FileName",
                "-FileSize",
                "-FileType",
                "-MIMEType",
                "-Software",
                "-CreateDate",
                "-ModifyDate",
                "-Comment",
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    except (
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        return (
            False,
            [],
            f"Metadata analysis failed: {exc}",
        )

    if proc.returncode != 0:
        return (
            False,
            [],
            proc.stderr.strip()
            or "ExifTool metadata analysis failed.",
        )

    lines = [
        line.strip()
        for line in proc.stdout.splitlines()
        if line.strip()
    ]

    return True, lines, None


# ---------------------------------------------------------------------------
# Archive detection
# ---------------------------------------------------------------------------

def detect_archive(
    file_path: str,
    file_type: str,
) -> tuple[bool, str]:

    lowered = file_type.lower()

    if zipfile.is_zipfile(file_path):
        return True, "ZIP"

    if any(
        keyword in lowered
        for keyword in (
            "rar",
            "7-zip",
            "gzip",
            "bzip",
            "xz",
            "archive",
            "compressed",
        )
    ):
        if "rar" in lowered:
            return True, "RAR"

        if "7-zip" in lowered:
            return True, "7-ZIP"

        if "gzip" in lowered:
            return True, "GZIP"

        if "bzip" in lowered:
            return True, "BZIP2"

        if "xz" in lowered:
            return True, "XZ"

        return True, "ARCHIVE/CONTAINER"

    return False, ""


# ---------------------------------------------------------------------------
# ZIP enumeration
# ---------------------------------------------------------------------------

def enumerate_zip_contents(
    file_path: str,
) -> tuple[list[ArchiveEntry], Optional[str]]:

    entries: list[ArchiveEntry] = []

    try:
        with zipfile.ZipFile(file_path, "r") as archive:

            bad_member = archive.testzip()

            if bad_member is not None:
                return (
                    entries,
                    f"ZIP integrity test reported a problematic member: "
                    f"{bad_member}",
                )

            for info in archive.infolist():

                entries.append(
                    ArchiveEntry(
                        name=info.filename,
                        size_bytes=info.file_size,
                        compressed_size_bytes=info.compress_size,
                        is_directory=info.is_dir(),
                    )
                )

    except (
        OSError,
        zipfile.BadZipFile,
    ) as exc:
        return [], f"ZIP enumeration failed: {exc}"

    return entries, None


# ---------------------------------------------------------------------------
# Nested-content indicators
# ---------------------------------------------------------------------------

def detect_nested_content(
    file_path: str,
    file_type: str,
) -> tuple[bool, list[str]]:

    findings: list[str] = []

    lowered_type = file_type.lower()

    if any(
        keyword in lowered_type
        for keyword in (
            "zip",
            "rar",
            "7-zip",
            "archive",
            "compressed",
        )
    ):
        findings.append(
            "Payload is itself an archive/container and may contain "
            "additional artifacts."
        )

        return True, findings

    with open(file_path, "rb") as handle:
        data = handle.read()

    detected_internal: list[str] = []

    for signature, name in INTERNAL_SIGNATURES.items():

        offset = data.find(signature)

        if offset > 0:
            detected_internal.append(
                f"{name} signature at offset {offset}"
            )

    if detected_internal:

        findings.append(
            "Additional recognizable file signature(s) detected "
            "inside the payload: "
            + "; ".join(detected_internal)
        )

        return True, findings

    return False, findings


# ---------------------------------------------------------------------------
# YARA output parser
# ---------------------------------------------------------------------------

def parse_yara_output(
    output: str,
) -> list[YaraMatch]:

    matches: list[YaraMatch] = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        parts = line.split()

        if not parts:
            continue

        rule_name = parts[0]

        matches.append(
            YaraMatch(
                rule=rule_name,
                tags=[],
            )
        )

    return matches


# ---------------------------------------------------------------------------
# YARA scanning
# ---------------------------------------------------------------------------

def run_yara(
    payload_path: str,
    rules_path: Path,
    timeout: int = DEFAULT_YARA_TIMEOUT,
) -> tuple[bool, list[YaraMatch], list[str]]:

    errors: list[str] = []

    yara_binary = shutil.which("yara")

    if yara_binary is None:
        errors.append(
            "YARA is not installed; YARA scanning was skipped."
        )

        return False, [], errors

    rules_path = Path(rules_path)

    if not rules_path.exists():

        errors.append(
            f"YARA rules path not found: {rules_path}"
        )

        return True, [], errors

    if rules_path.is_dir():

        rule_files = sorted(
            [
                path
                for path in rules_path.iterdir()
                if path.is_file()
                and path.suffix.lower() in (
                    ".yar",
                    ".yara",
                )
            ]
        )

        if not rule_files:

            errors.append(
                f"No YARA rule files found in: {rules_path}"
            )

            return True, [], errors

        # Scan each rule file independently.
        all_matches: list[YaraMatch] = []

        for rule_file in rule_files:

            try:
                proc = subprocess.run(
                    [
                        yara_binary,
                        str(rule_file),
                        payload_path,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )

            except subprocess.TimeoutExpired:
                errors.append(
                    f"YARA scan timed out for {rule_file} "
                    f"after {timeout}s."
                )
                continue

            except (
                OSError,
                subprocess.SubprocessError,
            ) as exc:
                errors.append(
                    f"YARA execution failed for {rule_file}: {exc}"
                )
                continue

            if proc.returncode not in (0, 1):

                errors.append(
                    proc.stderr.strip()
                    or (
                        f"YARA returned unexpected exit code "
                        f"{proc.returncode}."
                    )
                )

                continue

            all_matches.extend(
                parse_yara_output(proc.stdout)
            )

        return True, all_matches, errors

    # Single rule file.
    try:
        proc = subprocess.run(
            [
                yara_binary,
                str(rules_path),
                payload_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired:

        errors.append(
            f"YARA scan timed out after {timeout}s."
        )

        return True, [], errors

    except (
        OSError,
        subprocess.SubprocessError,
    ) as exc:

        errors.append(
            f"YARA execution failed: {exc}"
        )

        return True, [], errors

    if proc.returncode not in (0, 1):

        errors.append(
            proc.stderr.strip()
            or (
                f"YARA returned unexpected exit code "
                f"{proc.returncode}."
            )
        )

        return True, [], errors

    matches = parse_yara_output(proc.stdout)

    return True, matches, errors


# ---------------------------------------------------------------------------
# Evidence interpretation
# ---------------------------------------------------------------------------

def generate_findings(
    result: PayloadResult,
) -> None:

    if result.magic_match:

        result.findings.append(
            f"Known file signature identified: "
            f"{result.magic_signature}."
        )

    else:

        result.findings.append(
            "No known magic-byte signature was identified."
        )

    if result.classification == "TEXT":

        result.findings.append(
            "Payload is classified as text based on file-type analysis."
        )

    elif result.classification == "BINARY_WITH_PRINTABLE_STRINGS":

        result.findings.append(
            "Payload is binary data containing printable strings."
        )

    elif result.classification == "IMAGE":

        result.findings.append(
            "Payload is classified as an image artifact."
        )

    elif result.classification == "DOCUMENT":

        result.findings.append(
            "Payload is classified as a document artifact."
        )

    elif result.classification == "ARCHIVE":

        result.findings.append(
            "Payload is an archive/container and requires "
            "content enumeration or further analysis."
        )

    elif result.classification == "EXECUTABLE":

        result.findings.append(
            "Payload is identified as executable content and "
            "requires further artifact analysis."
        )

    if result.strings_count:

        result.findings.append(
            f"{result.strings_count} printable string(s) "
            "were identified."
        )

    if result.metadata_available:

        result.findings.append(
            "Metadata analysis was performed because the payload "
            "type supports metadata inspection."
        )

    if result.yara_available:

        if result.yara_matches:

            result.findings.append(
                f"YARA identified {len(result.yara_matches)} "
                "matching rule(s). This is an indicator requiring "
                "further investigation and is not by itself proof "
                "of maliciousness."
            )

        else:

            result.findings.append(
                "YARA scan completed with no matching rules."
            )

    if result.archive_container:

        result.findings.append(
            f"Payload identified as {result.archive_type} "
            "container/archive."
        )

        if result.archive_entries:

            file_count = sum(
                1
                for entry in result.archive_entries
                if not entry.is_directory
            )

            directory_count = sum(
                1
                for entry in result.archive_entries
                if entry.is_directory
            )

            result.findings.append(
                f"Archive enumeration identified {file_count} "
                f"file(s) and {directory_count} director{'y' if directory_count == 1 else 'ies'}."
            )

    if result.nested_content_suspected:

        result.findings.append(
            "Nested or additional recognizable content is suspected; "
            "further artifact analysis is required."
        )


# ---------------------------------------------------------------------------
# Further-analysis decision
# ---------------------------------------------------------------------------

def determine_further_analysis(
    result: PayloadResult,
) -> bool:

    if result.archive_container:
        return True

    if result.nested_content_suspected:
        return True

    if result.yara_matches:
        return True

    if result.classification == "EXECUTABLE":
        return True

    if result.classification == "UNKNOWN":
        return True

    return False


# ---------------------------------------------------------------------------
# Final assessment
# ---------------------------------------------------------------------------

def determine_assessment(
    result: PayloadResult,
) -> str:

    if not result.exists:

        return "PAYLOAD ANALYSIS FAILED"

    if result.errors:

        # Missing YARA rules should be treated as an analysis
        # limitation only when YARA could not be completed.
        return "PAYLOAD IDENTIFIED WITH ANALYSIS LIMITATIONS"

    if result.further_analysis_required:

        return "PAYLOAD IDENTIFIED — FURTHER ANALYSIS REQUIRED"

    return "PAYLOAD IDENTIFIED"


# ---------------------------------------------------------------------------
# Main payload analysis
# ---------------------------------------------------------------------------

def analyze_payload(
    payload_path: str,
    strings_min_length: int = DEFAULT_STRINGS_MIN_LENGTH,
    yara_rules_path: Optional[str] = None,
) -> PayloadResult:

    result = PayloadResult(
        payload_path=os.path.abspath(payload_path)
    )

    valid, reason = validate_payload_path(payload_path)

    if not valid:

        result.errors.append(reason)

        result.assessment = "PAYLOAD ANALYSIS FAILED"

        return result

    result.exists = True
    result.readable = True

    # -----------------------------------------------------------------------
    # Size
    # -----------------------------------------------------------------------

    try:

        result.size_bytes = os.path.getsize(payload_path)

    except OSError as exc:

        result.errors.append(
            f"Unable to determine payload size: {exc}"
        )

    # -----------------------------------------------------------------------
    # SHA-256
    # -----------------------------------------------------------------------

    try:

        result.sha256 = calculate_sha256(payload_path)

    except (
        OSError,
        IOError,
    ) as exc:

        result.errors.append(
            f"Unable to calculate SHA-256: {exc}"
        )

    # -----------------------------------------------------------------------
    # File type
    # -----------------------------------------------------------------------

    try:

        result.file_type = identify_file_type(payload_path)

    except (
        OSError,
        subprocess.SubprocessError,
        RuntimeError,
    ) as exc:

        result.errors.append(
            f"File-type identification failed: {exc}"
        )

    # -----------------------------------------------------------------------
    # Magic bytes
    # -----------------------------------------------------------------------

    try:

        (
            result.magic_signature,
            result.magic_match,
        ) = identify_magic_signature(payload_path)

    except (
        OSError,
        IOError,
    ) as exc:

        result.errors.append(
            f"Magic-byte analysis failed: {exc}"
        )

    # -----------------------------------------------------------------------
    # Strings
    # -----------------------------------------------------------------------

    try:

        result.strings = extract_printable_strings(
            payload_path,
            minimum_length=strings_min_length,
        )

        result.strings_count = len(result.strings)

    except (
        OSError,
        IOError,
    ) as exc:

        result.errors.append(
            f"String extraction failed: {exc}"
        )

    # -----------------------------------------------------------------------
    # Classification
    # -----------------------------------------------------------------------

    result.classification = classify_payload(
        result.file_type,
        result.magic_signature,
        result.strings,
    )

    # -----------------------------------------------------------------------
    # Metadata
    # -----------------------------------------------------------------------

    try:

        (
            result.metadata_available,
            result.metadata_summary,
            metadata_error,
        ) = analyze_metadata(
            payload_path,
            result.file_type,
        )

        if metadata_error:
            result.errors.append(metadata_error)

    except (
        OSError,
        IOError,
    ) as exc:

        result.errors.append(
            f"Metadata analysis failed: {exc}"
        )

    # -----------------------------------------------------------------------
    # Archive/container
    # -----------------------------------------------------------------------

    try:

        (
            result.archive_container,
            result.archive_type,
        ) = detect_archive(
            payload_path,
            result.file_type,
        )

        if (
            result.archive_container
            and result.archive_type == "ZIP"
        ):

            (
                result.archive_entries,
                archive_error,
            ) = enumerate_zip_contents(
                payload_path
            )

            if archive_error:
                result.errors.append(archive_error)

    except (
        OSError,
        IOError,
    ) as exc:

        result.errors.append(
            f"Archive analysis failed: {exc}"
        )

    # -----------------------------------------------------------------------
    # Nested content
    # -----------------------------------------------------------------------

    try:

        (
            result.nested_content_suspected,
            nested_findings,
        ) = detect_nested_content(
            payload_path,
            result.file_type,
        )

        result.findings.extend(nested_findings)

    except (
        OSError,
        IOError,
    ) as exc:

        result.errors.append(
            f"Nested-content analysis failed: {exc}"
        )

    # -----------------------------------------------------------------------
    # YARA
    # -----------------------------------------------------------------------

    selected_yara_path = (
        Path(yara_rules_path)
        if yara_rules_path
        else DEFAULT_YARA_RULES
    )

    result.yara_rules_path = str(
        selected_yara_path.resolve()
        if selected_yara_path.exists()
        else selected_yara_path
    )

    (
        result.yara_available,
        result.yara_matches,
        yara_errors,
    ) = run_yara(
        payload_path,
        selected_yara_path,
    )

    result.errors.extend(yara_errors)

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------

    generate_findings(result)

    # -----------------------------------------------------------------------
    # Further-analysis decision
    # -----------------------------------------------------------------------

    result.further_analysis_required = (
        determine_further_analysis(result)
    )

    # -----------------------------------------------------------------------
    # Assessment
    # -----------------------------------------------------------------------

    result.assessment = determine_assessment(result)

    return result


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

def print_payload_report(
    result: PayloadResult,
) -> None:
    """
    Print a concise forensic report for terminal review.
    """

    print()
    print("PAYLOAD FORENSICS")
    print("────────────────────────────────────────")
    print()

    print("Payload:")
    print(result.payload_path)
    print()

    print("Exists:")
    print("YES" if result.exists else "NO")
    print()

    print("Readable:")
    print("YES" if result.readable else "NO")
    print()

    print("Size:")
    print(f"{result.size_bytes} bytes")
    print()

    if result.sha256:

        print("SHA-256:")
        print(result.sha256)
        print()

    if result.file_type:

        print("File type:")
        print(result.file_type)
        print()

    if result.magic_signature:

        print("Magic signature:")
        print(result.magic_signature)
        print()

    if result.classification:

        print("Classification:")
        print(result.classification)
        print()

    print("Printable strings:")
    print(result.strings_count)
    print()

    if result.strings:

        print("String preview:")

        for value in result.strings[:10]:

            print(f"  {value}")

        if len(result.strings) > 10:

            print(
                f"  ... {len(result.strings) - 10} more"
            )

        print()

    # -----------------------------------------------------------------------
    # Metadata
    # -----------------------------------------------------------------------

    print("Metadata analysis:")

    if result.metadata_available:

        print("AVAILABLE")

        for line in result.metadata_summary[:15]:

            print(f"  {line}")

    else:

        print("NOT AVAILABLE / NOT APPLICABLE")

    print()

    # -----------------------------------------------------------------------
    # YARA
    # -----------------------------------------------------------------------

    print("YARA:")

    if not result.yara_available:

        print("NOT AVAILABLE")

    elif result.yara_matches:

        print(
            f"MATCHES: {len(result.yara_matches)}"
        )

        for match in result.yara_matches:

            print(f"  - {match.rule}")

    else:

        print("AVAILABLE — NO MATCHES")

    print()

    if result.yara_rules_path:

        print("YARA rules path:")
        print(result.yara_rules_path)
        print()

    # -----------------------------------------------------------------------
    # Archive
    # -----------------------------------------------------------------------

    print("Archive/container:")

    print(
        "YES"
        if result.archive_container
        else "NO"
    )

    if result.archive_container:

        print(f"Type: {result.archive_type}")

        if result.archive_entries:

            print("Contents:")

            for entry in result.archive_entries:

                if entry.is_directory:

                    print(
                        f"  [DIR]  {entry.name}"
                    )

                else:

                    print(
                        f"  [FILE] {entry.name} "
                        f"({entry.size_bytes} bytes)"
                    )

    print()

    # -----------------------------------------------------------------------
    # Nested content
    # -----------------------------------------------------------------------

    print("Nested content suspected:")

    print(
        "YES"
        if result.nested_content_suspected
        else "NO"
    )

    print()

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------

    if result.findings:

        print("Findings:")

        for finding in result.findings:

            print(f"  - {finding}")

        print()

    # -----------------------------------------------------------------------
    # Further analysis
    # -----------------------------------------------------------------------

    print("Further analysis:")

    print(
        "REQUIRED"
        if result.further_analysis_required
        else "NOT CURRENTLY REQUIRED"
    )

    print()

    # -----------------------------------------------------------------------
    # Errors / limitations
    # -----------------------------------------------------------------------

    if result.errors:

        print("Errors / limitations:")

        for error in result.errors:

            print(f"  - {error}")

        print()

    # -----------------------------------------------------------------------
    # Assessment
    # -----------------------------------------------------------------------

    print("Assessment:")
    print(result.assessment)
    print()


# ---------------------------------------------------------------------------
# Optional structured dictionary
# ---------------------------------------------------------------------------

def result_to_dict(
    result: PayloadResult,
) -> dict:

    return asdict(result)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:

    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Module 9 — Extracted Payload Forensics"
        )
    )

    parser.add_argument(
        "payload",
        help="Path to the extracted payload.",
    )

    parser.add_argument(
        "--strings-min",
        type=int,
        default=DEFAULT_STRINGS_MIN_LENGTH,
        help=(
            "Minimum printable-string length "
            "(default: 4)."
        ),
    )

    parser.add_argument(
        "--yara-rules",
        default=None,
        help=(
            "YARA rules file or directory. "
            "Default: project src/rules directory."
        ),
    )

    args = parser.parse_args()

    if args.strings_min < 1:

        parser.error(
            "--strings-min must be at least 1."
        )

    result = analyze_payload(
        args.payload,
        strings_min_length=args.strings_min,
        yara_rules_path=args.yara_rules,
    )

    print_payload_report(result)

    # Non-zero status only when the payload itself could not be analyzed.
    if not result.exists:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
