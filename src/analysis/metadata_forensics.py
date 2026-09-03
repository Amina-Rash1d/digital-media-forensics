from pathlib import Path
import subprocess
import json


def extract_metadata(file_path):
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    result = subprocess.run(
        ["exiftool", "-json", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )

    metadata = json.loads(result.stdout)

    if not metadata:
        raise ValueError("ExifTool returned no metadata")

    return metadata[0]


def analyze_metadata(file_path):
    metadata = extract_metadata(file_path)

    findings = {
        "filename": metadata.get("FileName"),
        "file_type": metadata.get("FileType"),
        "file_size": metadata.get("FileSize"),
        "timestamps": {
            "modified": metadata.get("FileModifyDate"),
            "accessed": metadata.get("FileAccessDate"),
            "inode_changed": metadata.get("FileInodeChangeDate"),
        },
        "image": {
            "width": metadata.get("ImageWidth"),
            "height": metadata.get("ImageHeight"),
            "color_type": metadata.get("ColorType"),
            "bit_depth": metadata.get("BitDepth"),
            "compression": metadata.get("Compression"),
        },
        "metadata": {
            "xmp_toolkit": metadata.get("XMPToolkit"),
            "orientation": metadata.get("Orientation"),
            "software": metadata.get("Software"),
            "artist": metadata.get("Artist"),
            "copyright": metadata.get("Copyright"),
            "comment": metadata.get("Comment"),
        },
        "gps": {
            "latitude": metadata.get("GPSLatitude"),
            "longitude": metadata.get("GPSLongitude"),
        },
    }

    return findings

def assess_metadata(findings):
    assessment = {
        "gps_present": False,
        "xmp_present": False,
        "editing_software_detected": False,
        "comments_present": False,
        "author_present": False,
        "notable_findings": [],
        "assessment": "NO IMMEDIATE ANOMALY",
    }

    metadata = findings["metadata"]
    gps = findings["gps"]

    if metadata.get("xmp_toolkit"):
        assessment["xmp_present"] = True
        assessment["notable_findings"].append(
            "XMP metadata is present"
        )

    if metadata.get("software"):
        assessment["editing_software_detected"] = True
        assessment["notable_findings"].append(
            f"Software reported: {metadata['software']}"
        )

    if metadata.get("comment"):
        assessment["comments_present"] = True
        assessment["notable_findings"].append(
            "Comment metadata is present"
        )

    if metadata.get("artist"):
        assessment["author_present"] = True
        assessment["notable_findings"].append(
            f"Author/artist metadata is present: {metadata['artist']}"
        )

    if gps.get("latitude") or gps.get("longitude"):
        assessment["gps_present"] = True
        assessment["notable_findings"].append(
            "GPS metadata is present"
        )

    if assessment["notable_findings"]:
        assessment["assessment"] = "NOTABLE METADATA PRESENT"

    return assessment

def compare_metadata(file_a, file_b):
    metadata_a = extract_metadata(file_a)
    metadata_b = extract_metadata(file_b)

    ignored_fields = {
        "SourceFile",
        "FileName",
        "FileSize",
        "FileModifyDate",
        "FileAccessDate",
        "FileInodeChangeDate",
    }

    all_keys = sorted(set(metadata_a) | set(metadata_b))

    embedded_changes = []
    filesystem_changes = []

    for key in all_keys:
        value_a = metadata_a.get(key)
        value_b = metadata_b.get(key)

        if value_a == value_b:
            continue

        change = {
            "field": key,
            "file_a": value_a,
            "file_b": value_b,
        }

        if key in ignored_fields:
            filesystem_changes.append(change)
        else:
            embedded_changes.append(change)

    if embedded_changes:
        assessment = "EMBEDDED METADATA CHANGES DETECTED"
    else:
        assessment = "NO EMBEDDED METADATA CHANGES"

    return {
        "file_a": str(file_a),
        "file_b": str(file_b),
        "filesystem_changes": filesystem_changes,
        "embedded_metadata_changes": embedded_changes,
        "filesystem_change_count": len(filesystem_changes),
        "embedded_metadata_change_count": len(embedded_changes),
        "assessment": assessment,
    }

def build_metadata_result(file_path, comparison=None):

    findings = analyze_metadata(file_path)
    assessment = assess_metadata(findings)

    normalized_findings = list(assessment["notable_findings"])

    if comparison:
        if comparison.get("embedded_metadata_changes"):
            normalized_findings.append(
                f"{comparison['embedded_metadata_change_count']} embedded metadata changes detected"
            )

        if comparison.get("filesystem_changes"):
            normalized_findings.append(
                f"{comparison['filesystem_change_count']} filesystem-level changes detected"
            )

    result = {
        "module": "Metadata Forensics",
        "status": "completed",

        "target": {
            "file": findings["filename"],
            "file_type": findings["file_type"],
            "file_size": findings["file_size"],
        },

        "timestamps": findings["timestamps"],

        "image": findings["image"],

        "metadata": findings["metadata"],

        "gps": findings["gps"],

        "findings": normalized_findings,

        "assessment": assessment,

        "comparison": comparison,
    }

    return result

if __name__ == "__main__":
    print("Metadata Forensics module loaded successfully.") 
