from pathlib import Path
import struct
import subprocess
import re


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

def analyze_png_structure(file_path):

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    with open(path, "rb") as f:
        data = f.read()

    png_signature = PNG_SIGNATURE
    signature = data[:8]

    structure = {
        "signature": signature.hex(),
        "valid_signature": (
            signature == png_signature
        ),
        "format": "PNG",
        "chunk_count": 0,
        "chunk_types": [],
        "iend_offset": None,
        "end_offset": None,
        "trailing_bytes": 0,
    }

    # ---------------------------------------------------------
    # Invalid PNG signature
    # ---------------------------------------------------------

    if not structure["valid_signature"]:
        return structure

    # ---------------------------------------------------------
    # Parse PNG chunks
    # ---------------------------------------------------------

    offset = 8

    while offset < len(data):

        # A PNG chunk requires:
        #   4 bytes length
        #   4 bytes type
        if offset + 8 > len(data):
            break

        length = struct.unpack(
            ">I",
            data[offset:offset + 4]
        )[0]

        chunk_type_bytes = data[
            offset + 4:
            offset + 8
        ]

        chunk_type = chunk_type_bytes.decode(
            "ascii",
            errors="replace"
        )

        data_end = (
            offset
            + 8
            + length
        )

        # Chunk also requires a 4-byte CRC.
        chunk_end = data_end + 4

        # -----------------------------------------------------
        # Incomplete/truncated chunk
        # -----------------------------------------------------

        if chunk_end > len(data):
            break

        structure["chunk_count"] += 1

        structure["chunk_types"].append(
            chunk_type
        )

        # -----------------------------------------------------
        # IEND marks the logical end of the PNG.
        # -----------------------------------------------------

        if chunk_type == "IEND":

            structure["iend_offset"] = offset

            structure["end_offset"] = chunk_end

            structure["trailing_bytes"] = (
                len(data) - chunk_end
            )

            break

        offset = chunk_end

    return structure

def run_binwalk(file_path):

    try:
        result = subprocess.run(
            ["binwalk", str(file_path)],
            capture_output=True,
            text=True,
            check=False,
        )

        return {
            "available": True,
            "return_code": result.returncode,
            "output": result.stdout.strip(),
            "errors": result.stderr.strip(),
        }

    except FileNotFoundError:
        return {
            "available": False,
            "return_code": None,
            "output": "",
            "errors": "binwalk not installed",
        }


def run_strings(file_path):

    try:
        result = subprocess.run(
            ["strings", "-a", str(file_path)],
            capture_output=True,
            text=True,
            check=False,
        )

        strings = result.stdout.splitlines()

        return {
            "available": True,
            "count": len(strings),
            "strings": strings[:50],
        }

    except FileNotFoundError:
        return {
            "available": False,
            "count": 0,
            "strings": [],
        }


def find_embedded_signatures(file_path):

    path = Path(file_path)

    with open(path, "rb") as f:
        data = f.read()

    signatures = {
        "ZIP": b"PK\x03\x04",
        "PDF": b"%PDF",
        "RAR": b"Rar!\x1a\x07",
        "GZIP": b"\x1f\x8b\x08",
        "7ZIP": b"7z\xbc\xaf\x27\x1c",
        "JPEG": b"\xff\xd8\xff",
        "PNG": PNG_SIGNATURE,
    }

    findings = []

    for name, signature in signatures.items():

        start = 0

        while True:
            offset = data.find(signature, start)

            if offset == -1:
                break

            findings.append(
                {
                    "type": name,
                    "offset": offset,
                }
            )

            start = offset + 1

    return findings


def analyze_structure(file_path):

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    # ---------------------------------------------------------
    # Read initial bytes to identify the actual file format.
    # ---------------------------------------------------------

    with open(path, "rb") as f:
        header = f.read(16)

    is_png = header.startswith(PNG_SIGNATURE)
    is_bmp = header.startswith(b"BM")

    # ---------------------------------------------------------
    # Structure analysis
    # ---------------------------------------------------------

    if is_png:
        structure = analyze_png_structure(path)

        format_name = "PNG"

    elif is_bmp:
        # BMP does not use PNG-style chunks/IEND.
        # Do not manufacture PNG findings for a BMP file.
        structure = {
            "signature": header[:8].hex(),
            "valid_signature": header[:2] == b"BM",
            "format": "BMP",
            "chunk_count": 0,
            "chunk_types": [],
            "iend_offset": None,
            "end_offset": None,
            "trailing_bytes": 0,
        }

        format_name = "BMP"

    else:
        # Unknown/other format.
        structure = {
            "signature": header[:8].hex(),
            "valid_signature": None,
            "format": "UNKNOWN",
            "chunk_count": 0,
            "chunk_types": [],
            "iend_offset": None,
            "end_offset": None,
            "trailing_bytes": 0,
        }

        format_name = "UNKNOWN"

    # ---------------------------------------------------------
    # Run supporting tools
    # ---------------------------------------------------------

    binwalk = run_binwalk(path)
    strings = run_strings(path)

    embedded = find_embedded_signatures(path)

    findings = []

    # ---------------------------------------------------------
    # Format-specific structural findings
    # ---------------------------------------------------------

    if format_name == "PNG":

        if structure["valid_signature"]:
            findings.append(
                "Valid PNG file signature detected"
            )
        else:
            findings.append(
                "Invalid PNG file signature detected"
            )

        if structure["iend_offset"] is not None:
            findings.append(
                "PNG IEND chunk detected"
            )

        trailing = structure["trailing_bytes"]

        if trailing > 0:
            findings.append(
                f"Trailing data detected after IEND: {trailing} bytes"
            )

    elif format_name == "BMP":

        if structure["valid_signature"]:
            findings.append(
                "Valid BMP file signature detected"
            )

    # ---------------------------------------------------------
    # Embedded signatures
    #
    # Ignore the file's own signature at offset 0.
    # ---------------------------------------------------------

    non_native_signatures = []

    for item in embedded:

        item_type = item.get("type")
        item_offset = item.get("offset")

        native_signature = (
            (format_name == "PNG" and item_type == "PNG")
            or
            (format_name == "BMP" and item_type == "BMP")
        )

        if native_signature and item_offset == 0:
            continue

        non_native_signatures.append(item)

    if non_native_signatures:

        for item in non_native_signatures:

            findings.append(
                f"Embedded {item['type']} signature detected "
                f"at offset {item['offset']}"
            )

    # ---------------------------------------------------------
    # Binwalk results
    #
    # Binwalk commonly reports the target file itself at offset 0.
    # That is normal identification, not an embedded signature.
    # ---------------------------------------------------------

    binwalk_output = binwalk.get(
        "output",
        "",
    )

    if binwalk_output:

        lines = binwalk_output.splitlines()

        for line in lines:

            stripped = line.strip()

            if not stripped:
                continue

            if stripped.startswith("DECIMAL"):
                continue

            if stripped.startswith("-"):
                continue

            # -------------------------------------------------
            # Ignore the expected format identification for the
            # file itself at offset 0.
            # -------------------------------------------------

            if stripped.startswith("0 0x0"):

                normalized = stripped.lower()

                if format_name == "BMP" and (
                    "pc bitmap" in normalized
                    or "bitmap" in normalized
                ):
                    continue

                if format_name == "PNG" and (
                    "png image" in normalized
                ):
                    continue

            # -------------------------------------------------
            # Preserve genuine tool-reported signatures.
            # -------------------------------------------------

            if stripped:
                findings.append(
                    f"Binwalk additional signature: {stripped}"
                )

    # ---------------------------------------------------------
    # Final assessment
    # ---------------------------------------------------------

    suspicious = False

    if format_name == "PNG":
        trailing = structure["trailing_bytes"]

        if trailing > 0:
            suspicious = True

    else:
        trailing = 0

    if non_native_signatures:
        suspicious = True

    # Important:
    #
    # Binwalk findings alone do not automatically establish
    # structural anomaly because signatures can occur legitimately
    # inside file data.

    if suspicious:

        severity = "HIGH"
        assessment = "STRUCTURAL ANOMALY DETECTED"

    else:

        severity = "LOW"
        assessment = "NO IMMEDIATE ANOMALY"

        findings.append(
            "No immediate structural anomaly detected"
        )

    # ---------------------------------------------------------
    # Return raw structure-analysis result
    # ---------------------------------------------------------

    return {
        "structure": structure,

        "embedded_signatures": non_native_signatures,

        "tool_results": {
            "binwalk": binwalk,
            "strings": strings,
        },

        "findings": findings,

        "assessment": {
            "severity": severity,

            "findings": [
                finding
                for finding in findings
                if (
                    "anomaly" in finding.lower()
                    or "trailing" in finding.lower()
                    or "embedded" in finding.lower()
                    or "additional signature" in finding.lower()
                )
            ],

            "assessment": assessment,
        },
    }

def build_structure_result(file_path):

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    result = analyze_structure(path)

    structure = result.get(
        "structure",
        {},
    )

    format_name = structure.get(
        "format",
        "",
    )

    if not format_name:

        suffix = path.suffix.lower()

        if suffix == ".png":
            format_name = "PNG"

        elif suffix == ".bmp":
            format_name = "BMP"

        else:
            format_name = suffix.lstrip(".").upper()

    original_findings = list(
        result.get(
            "findings",
            [],
        )
    )

    # ---------------------------------------------------------
    # Normalize findings
    # ---------------------------------------------------------

    normalized_findings = []

    for finding in original_findings:

        lower = finding.lower()

        # Remove any stale PNG-specific finding that could
        # survive from an older implementation.
        if (
            format_name != "PNG"
            and "invalid png file signature" in lower
        ):
            continue

        # A normal Binwalk identification of the file at offset
        # 0 is not an embedded signature.
        if (
            format_name == "BMP"
            and "binwalk additional signature" in lower
            and (
                "pc bitmap" in lower
                or "windows 3.x" in lower
                or "bitmap" in lower
            )
        ):
            continue

        normalized_findings.append(
            finding
        )

    # ---------------------------------------------------------
    # Identify actual structural anomalies
    # ---------------------------------------------------------

    anomaly_findings = []

    for finding in normalized_findings:

        lower = finding.lower()

        # Normal format identification is NOT an anomaly.
        if lower.startswith(
            "valid bmp file signature detected"
        ):
            continue

        if lower.startswith(
            "valid png file signature detected"
        ):
            continue

        # Normal PNG IEND presence is NOT an anomaly.
        if lower == "png iend chunk detected":
            continue

        # The baseline message is not an anomaly.
        if "no immediate structural anomaly" in lower:
            continue

        # Actual structural indicators.
        if (
            "invalid" in lower
            or "trailing" in lower
            or "embedded" in lower
            or "additional signature" in lower
        ):
            anomaly_findings.append(
                finding
            )

    # ---------------------------------------------------------
    # Ensure baseline message
    # ---------------------------------------------------------

    if not anomaly_findings:

        normalized_findings = [
            finding
            for finding in normalized_findings
            if (
                "no immediate structural anomaly"
                not in finding.lower()
            )
        ]

        normalized_findings.append(
            "No immediate structural anomaly detected"
        )

    # ---------------------------------------------------------
    # Severity and assessment
    # ---------------------------------------------------------

    if anomaly_findings:

        severity = "MEDIUM"

        assessment_text = (
            "STRUCTURAL ANOMALY REQUIRES REVIEW"
        )

    else:

        severity = "LOW"

        assessment_text = (
            "NO IMMEDIATE ANOMALY"
        )

    # ---------------------------------------------------------
    # Assessment findings contain ONLY actual anomalies.
    # Normal observations such as valid signatures are excluded.
    # ---------------------------------------------------------

    assessment_findings = list(
        anomaly_findings
    )

    # ---------------------------------------------------------
    # Final normalized result
    # ---------------------------------------------------------

    normalized = {
        "module": (
            "File Structure & Embedded Data Analysis"
        ),

        "status": "completed",

        "target": {
            "file": path.name,

            "file_type": format_name,

            "file_size": path.stat().st_size,
        },

        "structure": structure,

        "embedded_signatures": result.get(
            "embedded_signatures",
            [],
        ),

        "tool_results": result.get(
            "tool_results",
            {},
        ),

        "findings": normalized_findings,

        "assessment": {
            "severity": severity,

            "findings": assessment_findings,

            "assessment": assessment_text,
        },

        "carving": result.get(
            "carving"
        ),
    }

    return normalized
