from __future__ import annotations

import os
import re
import shutil
import string
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COMMON_ENGLISH_WORDS = {
    "this",
    "is",
    "a",
    "very",
    "secret",
    "message",
    "the",
    "and",
    "to",
    "of",
    "in",
    "you",
    "that",
    "it",
    "for",
    "on",
    "with",
    "as",
    "was",
    "hidden",
    "data",
    "test",
    "flag",
    "password",
    "file",
    "here",
    "from",
    "hello",
    "important",
    "confidential",
    "document",
    "text",
}

_PRINTABLE_BYTES = set(range(32, 127))
_ALLOWED_TEXT_BYTES = _PRINTABLE_BYTES | {9, 10, 13}


# ---------------------------------------------------------------------------
# Text plausibility
# ---------------------------------------------------------------------------

def score_text_plausibility(candidate: str) -> float:

    if not candidate:
        return 0.0

    candidate = candidate.strip(
        "\x00\r\n\t "
    )

    if not candidate:
        return 0.0

    length = len(candidate)

    if length < 8:
        return 0.0

    # ---------------------------------------------------------------
    # Printable-character check
    # ---------------------------------------------------------------

    printable = sum(
        1
        for char in candidate
        if char in string.printable
    )

    printable_ratio = printable / length

    if printable_ratio < 0.90:
        return 0.0

    # ---------------------------------------------------------------
    # Character composition
    # ---------------------------------------------------------------

    alphabetic = sum(
        1
        for char in candidate
        if char.isalpha()
    )

    alphabetic_ratio = alphabetic / length

    if alphabetic_ratio < 0.25:
        return 0.0

    digits = sum(
        1
        for char in candidate
        if char.isdigit()
    )

    digit_ratio = digits / length

    punctuation = sum(
        1
        for char in candidate
        if char in string.punctuation
    )

    punctuation_ratio = punctuation / length

    spaces = sum(
        1
        for char in candidate
        if char == " "
    )

    space_ratio = spaces / length

    if (
        space_ratio == 0.0
        and digit_ratio > 0.0
        and punctuation_ratio > 0.0
    ):
        return 0.0

    if (
        space_ratio == 0.0
        and digit_ratio > 0.0
        and alphabetic_ratio < 0.75
    ):
        return 0.0

    # Excessive punctuation strongly indicates noise.
    if punctuation_ratio > 0.30:
        return 0.0

    # Excessive spaces are also suspicious.
    if space_ratio > 0.35:
        return 0.0

    # ---------------------------------------------------------------
    # Word extraction
    # ---------------------------------------------------------------

    words = re.findall(
        r"[a-zA-Z']+",
        candidate.lower(),
    )

    if not words:
        return 0.0

    # ---------------------------------------------------------------
    # Dictionary-word matching
    # ---------------------------------------------------------------

    word_hits = sum(
        1
        for word in words
        if word in _COMMON_ENGLISH_WORDS
    )


    # Require:
    #
    #   1. at least two recognizable words, OR
    #   2. one recognizable word plus actual whitespace.
    if word_hits == 0:
        return 0.0

    if word_hits < 2 and space_ratio == 0.0:
        return 0.0

    # ---------------------------------------------------------------
    # Reject tiny compact alphabetic noise
    # ---------------------------------------------------------------

    if (
        length <= 12
        and space_ratio == 0.0
        and word_hits < 2
    ):
        return 0.0

    # ---------------------------------------------------------------
    # Repetition checks
    # ---------------------------------------------------------------

    if len(set(candidate)) <= 2:
        return 0.0

    if length >= 12:

        unique_ratio = (
            len(set(candidate)) / length
        )

        if unique_ratio < 0.20:
            return 0.0

    # ---------------------------------------------------------------
    # Word score
    # ---------------------------------------------------------------

    word_score = min(
        word_hits / 3.0,
        1.0,
    )

    # ---------------------------------------------------------------
    # Final heuristic score
    # ---------------------------------------------------------------

    score = (
        0.30 * printable_ratio
        + 0.25 * min(
            alphabetic_ratio * 2.0,
            1.0,
        )
        + 0.15 * min(
            space_ratio * 4.0,
            1.0,
        )
        + 0.30 * word_score
    )

    return round(
        min(score, 1.0),
        3,
    )

# ---------------------------------------------------------------------------
# Leading text extraction from unbounded zsteg output
# ---------------------------------------------------------------------------

def extract_leading_text_segment(
    raw: bytes,
    minimum_length: int = 8,
) -> Optional[str]:

    if not raw:
        return None

    runs: list[bytes] = []
    current = bytearray()

    for byte in raw:

        if byte in _ALLOWED_TEXT_BYTES:
            current.append(byte)

        else:

            if len(current) >= minimum_length:
                runs.append(bytes(current))

            current = bytearray()

    if len(current) >= minimum_length:
        runs.append(bytes(current))

    if not runs:
        return None

    candidates: list[tuple[str, float, int]] = []

    for run in runs:

        try:
            text = run.decode("utf-8")

        except UnicodeDecodeError:
            continue

        text = text.strip(
            "\x00\r\n\t "
        )

        if len(text) < minimum_length:
            continue

        score = score_text_plausibility(
            text
        )

        # Do not retain zero-score printable noise.
        if score <= 0.0:
            continue

        candidates.append(
            (
                text,
                score,
                len(text),
            )
        )

    if not candidates:
        return None

    # Prefer the strongest text-quality score.
    # Length is only a secondary factor.
    candidates.sort(
        key=lambda item: (
            item[1],
            item[2],
        ),
        reverse=True,
    )

    return candidates[0][0]

# ---------------------------------------------------------------------------
# Steghide
# ---------------------------------------------------------------------------

@dataclass
class SteghideResult:
    attempted: bool = False
    extracted: bool = False
    plausible: Optional[bool] = None
    verified: bool = False
    confirmed: bool = False
    passphrase_used: Optional[str] = None
    extracted_path: Optional[str] = None
    raw_output: str = ""
    interpretation: str = ""


def try_steghide(
    file_path: str,
    candidate_passphrases: list[str],
    output_dir: str,
    timeout: int = 15,
) -> SteghideResult:

    result = SteghideResult(attempted=True)

    # Remove duplicates while preserving order.
    passphrases_to_try = []
    seen = set()

    for password in [""] + list(candidate_passphrases):
        if password not in seen:
            seen.add(password)
            passphrases_to_try.append(password)

    for password in passphrases_to_try:

        fd, probe_path = tempfile.mkstemp(
            prefix="steghide_probe_",
            suffix=".out",
        )
        os.close(fd)

        try:
            # Steghide expects to create the extraction file itself.
            try:
                os.remove(probe_path)
            except FileNotFoundError:
                pass

            proc = subprocess.run(
                [
                    "steghide",
                    "extract",
                    "-sf",
                    file_path,
                    "-p",
                    password,
                    "-f",
                    "-xf",
                    probe_path,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Keep only a bounded amount of command output.
            stdout = (proc.stdout or "").strip()
            stderr = (proc.stderr or "").strip()

            max_output = 2000

            if len(stdout) > max_output:
                stdout = stdout[:max_output] + "...[truncated]"

            if len(stderr) > max_output:
                stderr = stderr[:max_output] + "...[truncated]"

            result.raw_output += (
                f"\n--- passphrase={'(empty)' if not password else '[supplied]'} ---\n"
                f"{stdout}\n"
                f"{stderr}"
            )

            if (
                proc.returncode == 0
                and os.path.exists(probe_path)
                and os.path.getsize(probe_path) > 0
            ):
                os.makedirs(
                    output_dir,
                    exist_ok=True,
                )

                destination = os.path.join(
                    output_dir,
                    "steghide_payload.bin",
                )

                if os.path.exists(destination):
                    os.remove(destination)

                shutil.move(
                    probe_path,
                    destination,
                )

                result.extracted = True
                result.plausible = True
                result.verified = True
                result.confirmed = True

                result.passphrase_used = (
                    "(empty)"
                    if not password
                    else password
                )

                result.extracted_path = destination

                result.interpretation = (
                    "EXTRACTED: yes. "
                    "PLAUSIBLE: yes. "
                    "VERIFIED: yes. "
                    "Steghide successfully created a non-empty "
                    "extracted payload using one of the tested "
                    "passphrases."
                )

                return result

        except FileNotFoundError:
            result.interpretation = (
                "EXTRACTED: no. "
                "PLAUSIBLE: not applicable. "
                "VERIFIED: no. "
                "Steghide is not installed on this system."
            )
            return result

        except subprocess.TimeoutExpired:
            result.raw_output += (
                f"\n--- passphrase="
                f"{'(empty)' if not password else '[supplied]'} ---\n"
                "TIMEOUT"
            )

        finally:
            if os.path.exists(probe_path):
                try:
                    os.remove(probe_path)
                except OSError:
                    pass

    result.interpretation = (
        "EXTRACTED: no. "
        "PLAUSIBLE: not applicable. "
        "VERIFIED: no. "
        "Steghide extraction did not succeed with the tested "
        "passphrases. This is NOT proof that hidden data is absent; "
        "Steghide failure cannot reliably distinguish an incorrect "
        "passphrase from absence of a recoverable Steghide payload."
    )

    return result

# ---------------------------------------------------------------------------
# Stegseek
# ---------------------------------------------------------------------------

@dataclass
class StegseekResult:
    attempted: bool = False
    extracted: bool = False
    plausible: Optional[bool] = None
    verified: bool = False
    confirmed: bool = False
    passphrase_found: Optional[str] = None
    extracted_path: Optional[str] = None
    raw_output: str = ""
    interpretation: str = ""


def try_stegseek(
    file_path: str,
    wordlist_path: str,
    output_dir: str,
    timeout: int = 300,
) -> StegseekResult:

    result = StegseekResult(attempted=True)

    if not os.path.exists(wordlist_path):
        result.interpretation = (
            "EXTRACTED: no. "
            "PLAUSIBLE: not applicable. "
            "VERIFIED: no. "
            f"Wordlist not found at {wordlist_path}."
        )
        return result

    os.makedirs(
        output_dir,
        exist_ok=True,
    )

    destination = os.path.join(
        output_dir,
        "stegseek_payload",
    )

    if os.path.exists(destination):
        try:
            os.remove(destination)
        except OSError:
            pass

    try:
        proc = subprocess.run(
            [
                "stegseek",
                file_path,
                wordlist_path,
                "-xf",
                destination,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    except FileNotFoundError:
        result.interpretation = (
            "EXTRACTED: no. "
            "PLAUSIBLE: not applicable. "
            "VERIFIED: no. "
            "Stegseek is not installed on this system."
        )
        return result

    except subprocess.TimeoutExpired:
        result.interpretation = (
            "EXTRACTED: no. "
            "PLAUSIBLE: not applicable. "
            "VERIFIED: no. "
            f"Stegseek did not finish within {timeout}s."
        )
        return result

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    max_output = 3000

    if len(stdout) > max_output:
        stdout = stdout[:max_output] + "...[truncated]"

    if len(stderr) > max_output:
        stderr = stderr[:max_output] + "...[truncated]"

    result.raw_output = (
        stdout + "\n" + stderr
    ).strip()

    passphrase_match = re.search(
        r'passphrase:\s*"([^"]*)"',
        result.raw_output,
        re.IGNORECASE,
    )

    if (
        proc.returncode == 0
        and passphrase_match
        and os.path.exists(destination)
        and os.path.getsize(destination) > 0
    ):
        result.extracted = True
        result.plausible = True
        result.verified = True
        result.confirmed = True

        result.passphrase_found = (
            passphrase_match.group(1)
        )

        result.extracted_path = destination

        result.interpretation = (
            "EXTRACTED: yes. "
            "PLAUSIBLE: yes. "
            "VERIFIED: yes. "
            "Stegseek recovered a non-empty payload using "
            "the discovered passphrase."
        )

        return result

    result.interpretation = (
        "EXTRACTED: no. "
        "PLAUSIBLE: not applicable. "
        "VERIFIED: no. "
        "Stegseek did not find a working passphrase from "
        "the supplied wordlist. This is inconclusive, not "
        "a negative proof."
    )

    return result

# ---------------------------------------------------------------------------
# zsteg candidate parsing
# ---------------------------------------------------------------------------

@dataclass
class ZstegResult:
    attempted: bool = False

    extracted: bool = False
    plausible: bool = False
    verified: bool = False
    confirmed: bool = False

    best_candidate_preview: Optional[str] = None
    best_config: Optional[str] = None
    best_score: float = 0.0

    extracted_text: Optional[str] = None
    extracted_path: Optional[str] = None

    raw_extraction_size: int = 0
    validated_text_length: int = 0

    all_text_candidates: list[
        tuple[str, str, float]
    ] = field(default_factory=list)

    interpretation: str = ""


# zsteg -a commonly emits:
#
# b1,bgr,lsb,xy .. text: "This is ..."
#
# Keep this deliberately permissive.
_ZSTEG_LINE_RE = re.compile(
    r"^(\S+)\s+\.\.\s+text:\s+(.*)$"
)


def _rank_zsteg_candidates(
    scan_output: str,
    min_len: int,
) -> list[tuple[str, str, float]]:

    candidates = []

    for line in scan_output.splitlines():

        match = _ZSTEG_LINE_RE.match(
            line.strip()
        )

        if not match:
            continue

        config = match.group(1)
        raw_text = match.group(2)

        text = raw_text.strip()

        # Remove surrounding quotes when zsteg provides them.
        if (
            len(text) >= 2
            and text[0] == '"'
            and text[-1] == '"'
        ):
            text = text[1:-1]

        if len(text) < min_len:
            continue

        score = score_text_plausibility(text)

        candidates.append(
            (
                config,
                text,
                score,
            )
        )

    candidates.sort(
        key=lambda item: item[2],
        reverse=True,
    )

    return candidates


# ---------------------------------------------------------------------------
# zsteg explicit extraction
# ---------------------------------------------------------------------------

def _zsteg_explicit_extract(
    file_path: str,
    config: str,
    timeout: int = 30,
) -> Optional[bytes]:

    try:
        proc = subprocess.run(
            [
                "zsteg",
                "-E",
                config,
                file_path,
            ],
            capture_output=True,
            timeout=timeout,
        )

    except FileNotFoundError:
        return None

    except subprocess.TimeoutExpired:
        return None

    if proc.returncode != 0:
        return None

    if not proc.stdout:
        return None

    return proc.stdout


# ---------------------------------------------------------------------------
# zsteg verification
# ---------------------------------------------------------------------------

def try_zsteg(
    file_path: str,
    output_dir: str,
    timeout: int = 60,
    min_score: float = 0.5,
    min_len: int = 8,
    max_candidates_to_verify: int = 3,
) -> ZstegResult:

    result = ZstegResult(
        attempted=True
    )

    # ---------------------------------------------------------------
    # Step 1: detection
    # ---------------------------------------------------------------

    try:
        proc = subprocess.run(
            [
                "zsteg",
                "-a",
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    except FileNotFoundError:
        result.interpretation = (
            "EXTRACTED: no. "
            "PLAUSIBLE: no. "
            "VERIFIED: no. "
            "zsteg is not installed."
        )
        return result

    except subprocess.TimeoutExpired:
        result.interpretation = (
            "EXTRACTED: no. "
            "PLAUSIBLE: no. "
            "VERIFIED: no. "
            "zsteg timed out."
        )
        return result

    # ---------------------------------------------------------------
    # Preserve all detected text candidates.
    #
    # IMPORTANT:
    #     These remain candidates only.
    # ---------------------------------------------------------------

    result.all_text_candidates = (
        _rank_zsteg_candidates(
            proc.stdout,
            min_len,
        )
    )

    if not result.all_text_candidates:
        result.interpretation = (
            "EXTRACTED: no. "
            "PLAUSIBLE: no. "
            "VERIFIED: no. "
            "zsteg found no text-shaped candidates."
        )
        return result

    (
        result.best_config,
        result.best_candidate_preview,
        result.best_score,
    ) = result.all_text_candidates[0]

    # ---------------------------------------------------------------
    # Step 2: preview plausibility
    # ---------------------------------------------------------------

    if result.best_score < min_score:
        result.interpretation = (
            "EXTRACTED: no. "
            f"PLAUSIBLE: no — best zsteg -a preview "
            f"scored {result.best_score}, below threshold "
            f"{min_score}. "
            "VERIFIED: no."
        )
        return result

    result.plausible = True

    # ---------------------------------------------------------------
    # Step 3: identify candidates suitable for steganographic
    #         verification.
    #
    # zsteg can report "extradata" as text.
    #
    # Example:
    #
    #     extradata:0 .. text: "..."
    #
    # This means bytes outside the normal encoded image structure
    # may be interpretable as text.
    #
    # That is useful forensic evidence, but it is NOT equivalent
    # to an LSB payload.
    #
    # Therefore only explicit LSB configurations are eligible for
    # this LSB verification path.
    # ---------------------------------------------------------------

    verification_candidates = []

    excluded_non_stego_candidates = []

    for (
        config,
        preview,
        preview_score,
    ) in result.all_text_candidates:

        config_lower = config.lower().strip()

        # -----------------------------------------------------------
        # Explicitly reject appended/extradata interpretations.
        # -----------------------------------------------------------

        if (
            "extradata" in config_lower
            or "extra-data" in config_lower
            or "extra_data" in config_lower
        ):
            excluded_non_stego_candidates.append(
                (
                    config,
                    preview,
                    preview_score,
                    "extradata"
                )
            )
            continue

        # -----------------------------------------------------------
        # Metadata interpretations are not LSB payloads.
        # -----------------------------------------------------------

        if (
            "meta" in config_lower
            or "metadata" in config_lower
        ):
            excluded_non_stego_candidates.append(
                (
                    config,
                    preview,
                    preview_score,
                    "metadata"
                )
            )
            continue

        # -----------------------------------------------------------
        # File/container interpretations are not LSB payloads.
        # -----------------------------------------------------------

        if (
            "file" in config_lower
            or "zip" in config_lower
            or "gzip" in config_lower
            or "rar" in config_lower
        ):
            excluded_non_stego_candidates.append(
                (
                    config,
                    preview,
                    preview_score,
                    "embedded/container interpretation"
                )
            )
            continue

        # -----------------------------------------------------------
        # This verification function is specifically responsible
        # for the LSB steganography path.
        #
        # Require zsteg to explicitly identify an LSB configuration.
        #
        # A printable candidate without an LSB configuration is
        # insufficient evidence for an LSB verification claim.
        # -----------------------------------------------------------

        if "lsb" not in config_lower:
            excluded_non_stego_candidates.append(
                (
                    config,
                    preview,
                    preview_score,
                    "non-LSB interpretation"
                )
            )
            continue

        verification_candidates.append(
            (
                config,
                preview,
                preview_score,
            )
        )

    # ---------------------------------------------------------------
    # No suitable LSB candidate exists.
    #
    # This is especially important for TEST-04:
    #
    #     valid PNG
    #     +
    #     appended bytes after IEND
    #
    # If zsteg reports those bytes as extradata, they must remain
    # structural/appended-data evidence and must NOT become a
    # verified LSB payload.
    # ---------------------------------------------------------------

    if not verification_candidates:

        if excluded_non_stego_candidates:
            excluded_types = sorted(
                {
                    item[3]
                    for item in excluded_non_stego_candidates
                }
            )

            excluded_text = ", ".join(
                excluded_types
            )

            result.interpretation = (
                "EXTRACTED: no. "
                "PLAUSIBLE: yes — zsteg reported "
                "text-shaped candidate(s). "
                "VERIFIED: no — no eligible LSB "
                "steganographic configuration was identified. "
                f"Non-steganographic interpretations excluded: "
                f"{excluded_text}. "
                "Recoverable extradata is not treated as "
                "LSB steganography."
            )

        else:
            result.interpretation = (
                "EXTRACTED: no. "
                "PLAUSIBLE: yes. "
                "VERIFIED: no — no eligible LSB "
                "steganographic configuration was identified."
            )

        return result

    # ---------------------------------------------------------------
    # Step 4: verify only the strongest eligible LSB candidates.
    # ---------------------------------------------------------------

    for (
        config,
        preview,
        preview_score,
    ) in verification_candidates[
        :max_candidates_to_verify
    ]:

        if preview_score < min_score:
            break

        # -----------------------------------------------------------
        # Explicit extraction
        # -----------------------------------------------------------

        raw = _zsteg_explicit_extract(
            file_path,
            config,
        )

        if raw is None:
            continue

        # Record exactly how much zsteg returned.
        result.raw_extraction_size = len(raw)

        # -----------------------------------------------------------
        # IMPORTANT:
        #
        # zsteg -E returns raw bytes.
        #
        # Do not decode the entire buffer as UTF-8.
        #
        # The extracted bit-plane can contain:
        #
        #     binary bytes
        #     +
        #     printable text
        #     +
        #     unrelated data
        #
        # Therefore identify a meaningful printable segment first.
        # -----------------------------------------------------------

        extracted_text = extract_leading_text_segment(
            raw,
            minimum_length=min_len,
        )

        if extracted_text is None:
            continue

        extracted_text = extracted_text.strip(
            "\x00\r\n\t "
        )

        if len(extracted_text) < min_len:
            continue

        # -----------------------------------------------------------
        # Step 5: ensure the explicit extraction is consistent with
        #         the candidate reported by zsteg -a.
        #
        # A high-scoring extracted string by itself is not enough.
        #
        # The explicit extraction should correspond to the
        # candidate that caused us to attempt verification.
        # -----------------------------------------------------------

        preview_normalized = (
            preview
            .strip(
                "\x00\r\n\t "
            )
        )

        extracted_normalized = (
            extracted_text
            .strip(
                "\x00\r\n\t "
            )
        )

        preview_match = (
            extracted_normalized == preview_normalized
            or extracted_normalized in preview_normalized
            or preview_normalized in extracted_normalized
        )

        if not preview_match:
            continue

        # -----------------------------------------------------------
        # Step 6: independent plausibility scoring
        # -----------------------------------------------------------

        full_score = score_text_plausibility(
            extracted_text
        )

        if full_score < min_score:
            continue

        if len(extracted_text) < min_len:
            continue

        # -----------------------------------------------------------
        # Step 7: successful LSB validation
        #
        # IMPORTANT:
        #
        # We have already established:
        #
        #     1. Candidate came from zsteg.
        #     2. Candidate explicitly identifies LSB.
        #     3. Explicit -E extraction succeeded.
        #     4. Meaningful text was recovered.
        #     5. Recovered text corresponds to the zsteg candidate.
        #     6. Recovered text independently meets the
        #        plausibility threshold.
        #
        # Only now may this result become VERIFIED.
        # -----------------------------------------------------------

        os.makedirs(
            output_dir,
            exist_ok=True,
        )

        destination = os.path.join(
            output_dir,
            "zsteg_payload.txt",
        )

        with open(
            destination,
            "w",
            encoding="utf-8",
        ) as output_file:
            output_file.write(
                extracted_text
            )

        result.extracted = True
        result.plausible = True
        result.verified = True
        result.confirmed = True

        result.best_config = config
        result.best_score = full_score

        result.extracted_text = (
            extracted_text
        )

        result.extracted_path = (
            destination
        )

        result.validated_text_length = (
            len(extracted_text)
        )

        result.interpretation = (
            "EXTRACTED: yes. "
            "PLAUSIBLE: yes. "
            "VERIFIED: yes. "
            f"Eligible LSB configuration "
            f"'{config}' was explicitly extracted "
            f"with zsteg -E. "
            f"The extraction returned {len(raw)} bytes, "
            f"and a meaningful text segment of "
            f"{len(extracted_text)} characters was recovered. "
            f"The recovered text corresponds to the zsteg "
            f"candidate preview and independently scored "
            f"{full_score}, meeting the verification "
            f"threshold of {min_score}."
        )

        return result

    # ---------------------------------------------------------------
    # Explicit extraction was attempted but no eligible candidate
    # passed all validation requirements.
    # ---------------------------------------------------------------

    result.interpretation = (
        "EXTRACTED: no. "
        "PLAUSIBLE: yes — one or more eligible LSB "
        "zsteg candidates were identified, but explicit "
        "extraction did not produce a validated payload. "
        "VERIFIED: no."
    )

    return result

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def verify_and_extract(
    file_path: str,
    candidate_passphrases: Optional[list[str]] = None,
    steghide_shaped_suspicion: bool = False,
    wordlist_path: str = (
        "/usr/share/wordlists/rockyou.txt"
    ),
    output_dir: str = "extracted",
) -> dict:

    candidate_passphrases = (
        candidate_passphrases or []
    )

    extension = os.path.splitext(
        file_path
    )[1].lower()

    steghide_result = None
    stegseek_result = None
    zsteg_result = None

    # ---------------------------------------------------------------
    # Steghide-compatible formats
    # ---------------------------------------------------------------

    if extension in (
        ".jpg",
        ".jpeg",
        ".bmp",
        ".wav",
        ".au",
    ):

        steghide_result = try_steghide(
            file_path,
            candidate_passphrases,
            output_dir,
        )

        if (
            not steghide_result.confirmed
            and steghide_shaped_suspicion
        ):
            stegseek_result = try_stegseek(
                file_path,
                wordlist_path,
                output_dir,
            )

    # ---------------------------------------------------------------
    # zsteg-compatible formats
    # ---------------------------------------------------------------

    if extension in (
        ".png",
        ".bmp",
    ):

        zsteg_result = try_zsteg(
            file_path,
            output_dir,
        )

    # ---------------------------------------------------------------
    # Final verification state
    # ---------------------------------------------------------------

    verified = bool(
        (
            steghide_result
            and steghide_result.verified
        )
        or (
            stegseek_result
            and stegseek_result.verified
        )
        or (
            zsteg_result
            and zsteg_result.verified
        )
    )

    technique = None

    if (
        steghide_result
        and steghide_result.verified
    ):
        technique = "Steghide"

    elif (
        stegseek_result
        and stegseek_result.verified
    ):
        technique = (
            "Steghide "
            "(password recovered via Stegseek)"
        )

    elif (
        zsteg_result
        and zsteg_result.verified
    ):
        technique = (
            f"LSB steganography "
            f"({zsteg_result.best_config})"
        )

    # ---------------------------------------------------------------
    # Report
    # ---------------------------------------------------------------

    lines = [
        "HIDDEN DATA VERIFICATION",
        "=========================",
        f"File: {file_path}",
        "",
    ]

    # ---------------------------------------------------------------
    # Steghide report
    # ---------------------------------------------------------------

    if steghide_result:

        lines += [
            "STEGHIDE",
            "--------",
            "Attempted: YES",
            (
                "Confirmed: "
                + (
                    "YES"
                    if steghide_result.confirmed
                    else "NOT CONFIRMED"
                )
            ),
            (
                "EXTRACTED: "
                + (
                    "yes"
                    if steghide_result.extracted
                    else "no"
                )
            ),
            (
                "PLAUSIBLE: "
                + (
                    "yes"
                    if steghide_result.plausible
                    else "not applicable"
                )
            ),
            (
                "VERIFIED: "
                + (
                    "yes"
                    if steghide_result.verified
                    else "no"
                )
            ),
            (
                "Interpretation: "
                + steghide_result.interpretation
            ),
            "",
        ]

    # ---------------------------------------------------------------
    # Stegseek report
    # ---------------------------------------------------------------

    if stegseek_result:

        lines += [
            "STEGSEEK",
            "--------",
            "Attempted: YES",
            (
                "Confirmed: "
                + (
                    "YES"
                    if stegseek_result.confirmed
                    else "NOT CONFIRMED"
                )
            ),
            (
                "EXTRACTED: "
                + (
                    "yes"
                    if stegseek_result.extracted
                    else "no"
                )
            ),
            (
                "PLAUSIBLE: "
                + (
                    "yes"
                    if stegseek_result.plausible
                    else "not applicable"
                )
            ),
            (
                "VERIFIED: "
                + (
                    "yes"
                    if stegseek_result.verified
                    else "no"
                )
            ),
            (
                "Interpretation: "
                + stegseek_result.interpretation
            ),
            "",
        ]

    elif (
        steghide_result
        and not steghide_result.confirmed
    ):

        lines += [
            "STEGSEEK",
            "--------",
            "Attempted: NO",
            (
                "Reason: No independent Steghide-shaped "
                "suspicion was supplied."
            ),
            (
                "Steghide failure alone is insufficient "
                "to justify password cracking."
            ),
            "",
        ]

    # ---------------------------------------------------------------
    # zsteg report
    # ---------------------------------------------------------------

    if zsteg_result:

        lines += [
            "ZSTEG / LSB ANALYSIS",
            "--------------------",
            "Attempted: YES",
            (
                "Confirmed: "
                + (
                    "YES"
                    if zsteg_result.confirmed
                    else "NOT CONFIRMED"
                )
            ),
        ]

        if zsteg_result.best_config:

            lines += [
                (
                    "Candidate configuration: "
                    f"{zsteg_result.best_config}"
                ),
                (
                    "Plausibility score: "
                    f"{zsteg_result.best_score}"
                ),
                (
                    "EXTRACTED: "
                    + (
                        "YES"
                        if zsteg_result.extracted
                        else "NO"
                    )
                ),
                (
                    "PLAUSIBLE: "
                    + (
                        "YES"
                        if zsteg_result.plausible
                        else "NO"
                    )
                ),
                (
                    "VERIFIED: "
                    + (
                        "YES"
                        if zsteg_result.verified
                        else "NO"
                    )
                ),
            ]

            if zsteg_result.raw_extraction_size:

                lines.append(
                    "Raw zsteg -E extraction size: "
                    f"{zsteg_result.raw_extraction_size} bytes"
                )

            if zsteg_result.validated_text_length:

                lines.append(
                    "Validated text length: "
                    f"{zsteg_result.validated_text_length} "
                    "characters"
                )

            if zsteg_result.extracted:

                lines.append(
                    "Extraction method: "
                    "zsteg -E explicit extraction"
                )

                lines.append(
                    "Validated text segment: "
                    f"{zsteg_result.extracted_text!r}"
                )

            elif zsteg_result.best_candidate_preview:

                lines.append(
                    "zsteg -a preview: "
                    f"{zsteg_result.best_candidate_preview!r}"
                )

        lines += [
            (
                "Interpretation: "
                + zsteg_result.interpretation
            ),
            "",
        ]

    # ---------------------------------------------------------------
    # Final verdict
    # ---------------------------------------------------------------

    lines += [
        "VERDICT",
        "-------",
    ]

    if verified:

        lines.append(
            "Hidden data VERIFIED."
        )

        lines.append(
            f"Technique: {technique}"
        )

    else:

        lines.append(
            "Hidden data NOT VERIFIED using the "
            "tested techniques."
        )

    lines += [
        "",
        "Important limitation:",
        (
            "A NOT CONFIRMED result for one technique "
            "does not prove that the file contains no "
            "hidden data. It only means that extraction "
            "using that technique and the tested "
            "conditions did not succeed."
        ),
    ]

    summary = "\n".join(lines)

    # -----------------------------------------------------------------------
    # Canonical extraction identity
    # -----------------------------------------------------------------------
    #
    # Root-cause fix (see MASTER BUG REGISTER items M8-01/M8-02/M8-03):
    #
    # Previously, downstream code (normalize.py, report_generator.py) had
    # to guess which technique-specific sub-result was authoritative by
    # string-matching "technique" or by trying steghide/stegseek/zsteg in
    # a fixed order. That guessing is what produced:
    #
    #   - "Extraction successful: No" for a successful zsteg extraction
    #     (technique strings never literally equalled "zsteg")
    #   - "Verification score: 0.000" for a successful Steghide extraction
    #     (zsteg's default best_score=0.0 was picked up instead)
    #   - Empty/blank "validated recovered content" for a successful
    #     Steghide extraction (SteghideResult has no extracted_text field)
    #
    # This block computes ONE authoritative set of fields, directly from
    # whichever technique result actually verified, so every downstream
    # consumer reads the same, correct values instead of re-deriving them.
    # -----------------------------------------------------------------------

    verified_result = None
    verified_source_tool = None

    if steghide_result and steghide_result.verified:
        verified_result = steghide_result
        verified_source_tool = "steghide"

    elif stegseek_result and stegseek_result.verified:
        verified_result = stegseek_result
        verified_source_tool = "stegseek"

    elif zsteg_result and zsteg_result.verified:
        verified_result = zsteg_result
        verified_source_tool = "zsteg"

    canonical_extracted_path = None
    canonical_verification_score = None
    canonical_recovered_content = None

    if verified_result is not None:

        canonical_extracted_path = getattr(
            verified_result,
            "extracted_path",
            None,
        )

        # Only zsteg produces a graded plausibility score. Steghide and
        # Stegseek are binary pass/fail tools (a passphrase either
        # extracts a non-empty payload or it does not), so a fixed,
        # explicit confidence of 1.0 is reported instead of borrowing a
        # score field from an unrelated technique.
        canonical_verification_score = getattr(
            verified_result,
            "best_score",
            1.0,
        )

        if canonical_verification_score is None:
            canonical_verification_score = 1.0

        # Prefer text already validated inline (zsteg). Otherwise, read
        # the actual bytes of the verified extracted artifact from disk.
        # This is the single source of truth for "what was recovered" —
        # never a candidate preview, never a nonexistent field.
        extracted_text_field = getattr(
            verified_result,
            "extracted_text",
            None,
        )

        if extracted_text_field:
            canonical_recovered_content = extracted_text_field

        elif (
            canonical_extracted_path
            and os.path.exists(canonical_extracted_path)
        ):
            try:
                with open(
                    canonical_extracted_path,
                    "rb",
                ) as recovered_file:
                    raw_recovered_bytes = recovered_file.read()

                try:
                    canonical_recovered_content = (
                        raw_recovered_bytes.decode("utf-8")
                    )
                except UnicodeDecodeError:
                    canonical_recovered_content = (
                        f"<binary payload, "
                        f"{len(raw_recovered_bytes)} bytes; "
                        "not valid UTF-8 text>"
                    )

            except OSError:
                canonical_recovered_content = None

    return {
        "file": file_path,
        "verified": verified,
        "technique": technique,

        # Canonical fields (authoritative — use these, not the
        # technique-specific sub-dicts, when only one value is needed).
        "source_tool": verified_source_tool,
        "extracted_path": canonical_extracted_path,
        "verification_score": canonical_verification_score,
        "recovered_content": canonical_recovered_content,

        "steghide": (
            steghide_result.__dict__
            if steghide_result
            else None
        ),

        "stegseek": (
            stegseek_result.__dict__
            if stegseek_result
            else None
        ),

        "zsteg": (
            zsteg_result.__dict__
            if zsteg_result
            else None
        ),

        "summary": summary,
    }

# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print(
            "Usage: python3 verify_extract.py "
            "<file> [passphrase1 passphrase2 ...]"
        )

        print(
            "Stegseek is NOT run by default. "
            "Independent Steghide-shaped suspicion "
            "must be supplied by the framework."
        )

        sys.exit(1)

    target = sys.argv[1]

    passphrases = sys.argv[2:]

    result = verify_and_extract(
        target,
        candidate_passphrases=passphrases,
        output_dir="/tmp/module8_extracted",
    )

    print(
        result["summary"]
    ) 
