from pathlib import Path
import hashlib
import subprocess


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def get_file_type(file_path):
    result = subprocess.run(
        ["file", "-b", str(file_path)],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.strip()


def extract_strings(file_path):
    result = subprocess.run(
        ["strings", "-n", "4", str(file_path)],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.splitlines()


def triage_file(file_path):
    path = Path(file_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    strings = extract_strings(path)

    return {
        "filename": path.name,
        "file_size": path.stat().st_size,
        "sha256": calculate_sha256(path),
        "file_type": get_file_type(path),
        "string_count": len(strings),
        "strings": strings,
    }


if __name__ == "__main__":
    print("File Triage module loaded successfully.") 
