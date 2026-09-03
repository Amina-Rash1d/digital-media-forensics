from pathlib import Path
import shutil
import subprocess


SUPPORTED_EXTENSIONS = {
    ".png",
    ".bmp",
}


def validate_input_file(file_path):

    path = Path(file_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(
            f"Evidence file not found: {path}"
        )

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            "Unsupported file format for zsteg analysis: "
            f"{path.suffix or '[no extension]'}"
        )

    return path


def locate_zsteg():

    zsteg_path = shutil.which("zsteg")

    if not zsteg_path:
        raise FileNotFoundError(
            "zsteg executable was not found in PATH. "
            "Install zsteg and ensure its executable directory "
            "is available in PATH."
        )

    return zsteg_path


def run_zsteg(file_path):

    path = validate_input_file(file_path)
    zsteg_path = locate_zsteg()

    command = [
        zsteg_path,
        str(path),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(
            f"Unable to execute zsteg: {exc}"
        ) from exc

    return {
        "command": command,
        "return_code": int(result.returncode),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def parse_zsteg_output(stdout):

    findings = []

    for line in stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        findings.append(
            {
                "raw": line,
            }
        )

    return findings


def classify_zsteg_finding(finding_text):

    text = finding_text.lower()

    if "wbstego" in text:
        return "possible_steganography_indicator"

    if "file:" in text:
        return "possible_embedded_file_interpretation"

    if "text:" in text:
        return "possible_text_interpretation"

    if "meta " in text:
        return "metadata_interpretation"

    return "tool_reported_pattern"


def build_structured_findings(findings):

    structured = []

    for index, finding in enumerate(findings, start=1):
        raw_text = finding["raw"]

        structured.append(
            {
                "id": f"ZSTEG-{index:03d}",
                "raw": raw_text,
                "category": classify_zsteg_finding(
                    raw_text
                ),
            }
        )

    return structured


def generate_interpretation(findings):

    if not findings:
        return (
            "zsteg produced no non-empty findings for the "
            "analyzed file. This does not independently "
            "exclude steganography."
        )

    categories = {
        finding["category"]
        for finding in findings
    }

    if "possible_steganography_indicator" in categories:
        return (
            "zsteg reported a possible steganography-related "
            "indicator. This is an automated comparative "
            "finding and requires corroboration or verification "
            "before concealed data can be considered confirmed."
        )

    if (
        "possible_embedded_file_interpretation" in categories
        or "possible_text_interpretation" in categories
    ):
        return (
            "zsteg reported possible file or text "
            "interpretations within the analyzed image data. "
            "These are automated indicators only and do not "
            "independently establish the presence of hidden data."
        )

    return (
        "zsteg reported one or more automated patterns or "
        "interpretations. The results require contextual "
        "analysis and do not independently establish "
        "steganography."
    )


def save_raw_output(output_dir, filename, execution_result):

    output_path = Path(output_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    stdout_path = output_path / f"{filename}_zsteg_stdout.txt"
    stderr_path = output_path / f"{filename}_zsteg_stderr.txt"

    stdout_path.write_text(
        execution_result["stdout"],
        encoding="utf-8",
    )

    stderr_path.write_text(
        execution_result["stderr"],
        encoding="utf-8",
    )

    return {
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }


def analyze_zsteg(file_path, output_dir=None):

    path = validate_input_file(file_path)

    execution_result = run_zsteg(path)

    parsed_findings = parse_zsteg_output(
        execution_result["stdout"]
    )

    structured_findings = build_structured_findings(
        parsed_findings
    )

    interpretation = generate_interpretation(
        structured_findings
    )

    artifacts = {}

    if output_dir:
        artifacts = save_raw_output(
            output_dir,
            path.stem,
            execution_result,
        )

    return {
        "status": "analyzed",
        "tool": "zsteg",
        "file": str(path),
        "filename": path.name,
        "format": path.suffix.lower().lstrip("."),
        "return_code": execution_result["return_code"],
        "finding_count": len(structured_findings),
        "findings": structured_findings,
        "interpretation": interpretation,
        "artifacts": artifacts,
        "stderr": execution_result["stderr"],
    }


def print_analysis_report(result):

    print("Automated Steganalysis")
    print("======================")
    print(f"Status: {result['status']}")
    print(f"Tool: {result['tool']}")
    print(f"File: {result['filename']}")
    print(f"Format: {result['format']}")
    print(f"Findings: {result['finding_count']}")

    print()
    print("zsteg Findings")
    print("--------------")

    if not result["findings"]:
        print("No non-empty zsteg findings reported.")
    else:
        for finding in result["findings"]:
            print(
                f"{finding['id']}: "
                f"{finding['category']}"
            )
            print(
                f"  {finding['raw']}"
            )

    print()
    print("Interpretation")
    print("--------------")
    print(result["interpretation"])

    if result["artifacts"]:
        print()
        print("Raw Output Artifacts")
        print("--------------------")
        print(
            f"stdout: {result['artifacts']['stdout']}"
        )
        print(
            f"stderr: {result['artifacts']['stderr']}"
        )


def main():

    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Automated steganalysis using zsteg."
        )
    )

    parser.add_argument(
        "file",
        help="Path to the PNG or BMP evidence file.",
    )

    parser.add_argument(
        "--output-dir",
        help=(
            "Directory for preserved raw zsteg output."
        ),
    )

    args = parser.parse_args()

    try:
        result = analyze_zsteg(
            args.file,
            output_dir=args.output_dir,
        )

        print_analysis_report(result)

    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main() 
