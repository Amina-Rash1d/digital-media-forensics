from pathlib import Path
import subprocess


def identify_file(file_path):
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    result = subprocess.run(
        ["file", "-b", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.strip()


if __name__ == "__main__":
    print("File Identifier module loaded successfully.")
