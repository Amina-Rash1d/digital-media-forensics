from src.core.file_identifier import identify_file
from pathlib import Path
from datetime import datetime
import hashlib
import shutil
import uuid


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_case(input_file):
    input_path = Path(input_file).resolve()

    if not input_path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {input_path}")

    timestamp = datetime.now()
    case_id = f"CASE-{timestamp.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

    case_dir = Path("cases") / case_id

    evidence_dir = case_dir / "evidence"
    raw_results_dir = case_dir / "raw_results"
    analysis_dir = case_dir / "analysis"
    extracted_dir = case_dir / "extracted"
    report_dir = case_dir / "report"

    for directory in [
        evidence_dir,
        raw_results_dir,
        analysis_dir,
        extracted_dir,
        report_dir,
    ]:
        directory.mkdir(parents=True, exist_ok=True)

    preserved_file = evidence_dir / input_path.name
    shutil.copy2(input_path, preserved_file)

    sha256 = calculate_sha256(preserved_file)
    file_type = identify_file(preserved_file)

    case_info = {
        "case_id": case_id,
        "original_filename": input_path.name,
        "file_size": preserved_file.stat().st_size,
        "sha256": sha256,
        "file_type": file_type,
        "acquisition_timestamp": timestamp.isoformat(),
        "evidence_path": str(preserved_file),
    }

    return case_info


if __name__ == "__main__":
    print("Case Manager module loaded successfully.") 
