from pathlib import Path

from PIL import Image
import numpy as np


def load_and_validate_image(file_path):

    path = Path(file_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"Evidence image not found: {path}")

    try:
        with Image.open(path) as image:
            image_format = image.format
            mode = image.mode
            width, height = image.size

            # Force decoding while the file is open so that any
            # image-read error occurs during validation.
            image.load()

            image_array = np.array(image)

    except Exception as exc:
        raise ValueError(
            f"Unable to load or validate image: {path}"
        ) from exc

    return {
        "file": str(path),
        "filename": path.name,
        "format": image_format,
        "mode": mode,
        "width": width,
        "height": height,
        "file_size": path.stat().st_size,
        "array_shape": list(image_array.shape),
        "array_dtype": str(image_array.dtype),
    }

def extract_rgb_channels(file_path):

    path = Path(file_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"Evidence image not found: {path}")

    try:
        with Image.open(path) as image:
            original_mode = image.mode
            converted_to_rgb = original_mode != "RGB"

            image = image.convert("RGB")
            image.load()

            image_array = np.array(image)

    except Exception as exc:
        raise ValueError(
            f"Unable to extract RGB channels: {path}"
        ) from exc

    return {
        "original_mode": original_mode,
        "converted_to_rgb": converted_to_rgb,
        "red": image_array[:, :, 0],
        "green": image_array[:, :, 1],
        "blue": image_array[:, :, 2],
    }

def calculate_channel_statistics(channels):

    statistics = {}

    for channel_name in ("red", "green", "blue"):
        channel_array = channels[channel_name]

        statistics[channel_name] = {
            "min": int(np.min(channel_array)),
            "max": int(np.max(channel_array)),
            "mean": float(np.mean(channel_array)),
            "std_dev": float(np.std(channel_array)),
        }

    return statistics

def calculate_bit_plane_statistics(channels):

    statistics = {}

    for channel_name in ("red", "green", "blue"):
        channel_array = channels[channel_name]
        channel_statistics = {}

        total_pixels = channel_array.size

        for bit in range(8):
            bit_values = (channel_array >> bit) & 1

            ones = int(np.sum(bit_values))
            zeros = int(total_pixels - ones)

            one_ratio = float(ones / total_pixels)
            zero_ratio = float(zeros / total_pixels)

            if one_ratio in (0.0, 1.0):
                entropy = 0.0
            else:
                entropy = float(
                    -(
                        zero_ratio * np.log2(zero_ratio)
                        + one_ratio * np.log2(one_ratio)
                    )
                )

            channel_statistics[f"bit_{bit}"] = {
                "ones": ones,
                "zeros": zeros,
                "one_ratio": one_ratio,
                "zero_ratio": zero_ratio,
                "entropy": entropy,
            }

        statistics[channel_name] = channel_statistics

    return statistics

def generate_visual_findings(channel_statistics, bit_plane_statistics):

    findings = []

    # ---------------------------------------------------------
    # Finding 1 — Channel intensity distribution
    # ---------------------------------------------------------

    channel_means = {
        channel: channel_statistics[channel]["mean"]
        for channel in ("red", "green", "blue")
    }

    highest_mean_channel = max(
        channel_means,
        key=channel_means.get,
    )

    lowest_mean_channel = min(
        channel_means,
        key=channel_means.get,
    )

    findings.append(
        {
            "id": "VIS-OBS-001",
            "type": "observation",
            "severity": "info",
            "title": "RGB channel intensity distributions differ",
            "description": (
                f"The {highest_mean_channel} channel has the highest "
                f"mean intensity ({channel_means[highest_mean_channel]:.4f}), "
                f"while the {lowest_mean_channel} channel has the lowest "
                f"mean intensity ({channel_means[lowest_mean_channel]:.4f})."
            ),
            "evidence": {
                "channel_means": channel_means,
            },
        }
    )

    # ---------------------------------------------------------
    # Finding 2 — LSB distribution comparison
    # ---------------------------------------------------------

    lsb_ratios = {
        channel: bit_plane_statistics[channel]["bit_0"]["one_ratio"]
        for channel in ("red", "green", "blue")
    }

    highest_lsb_channel = max(
        lsb_ratios,
        key=lsb_ratios.get,
    )

    lowest_lsb_channel = min(
        lsb_ratios,
        key=lsb_ratios.get,
    )

    findings.append(
        {
            "id": "VIS-OBS-002",
            "type": "observation",
            "severity": "info",
            "title": "LSB distributions differ across RGB channels",
            "description": (
                f"The {highest_lsb_channel} channel has the highest "
                f"LSB one-ratio ({lsb_ratios[highest_lsb_channel]:.4f}), "
                f"while the {lowest_lsb_channel} channel has the lowest "
                f"LSB one-ratio ({lsb_ratios[lowest_lsb_channel]:.4f})."
            ),
            "evidence": {
                "lsb_one_ratios": lsb_ratios,
            },
        }
    )

    # ---------------------------------------------------------
    # Finding 3 — Bit-plane entropy variation
    # ---------------------------------------------------------

    entropy_values = {}

    for channel in ("red", "green", "blue"):
        entropy_values[channel] = {}

        for bit in range(8):
            bit_name = f"bit_{bit}"

            entropy_values[channel][bit_name] = (
                bit_plane_statistics[channel][bit_name]["entropy"]
            )

    findings.append(
        {
            "id": "VIS-OBS-003",
            "type": "observation",
            "severity": "info",
            "title": "Bit-plane entropy varies across channels and positions",
            "description": (
                "Measured bit-plane entropy varies across RGB channels "
                "and bit positions. These measurements describe the "
                "observed pixel distribution and are not, by themselves, "
                "evidence of hidden data."
            ),
            "evidence": {
                "entropy": entropy_values,
            },
        }
    )

    return findings

def generate_rgb_artifacts(channels, output_dir):

    output_path = Path(output_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    artifacts = {}

    for channel_name in ("red", "green", "blue"):
        channel_array = channels[channel_name]

        channel_image = Image.fromarray(
            channel_array,
            mode="L",
        )

        artifact_path = output_path / f"{channel_name}_channel.png"

        channel_image.save(
            artifact_path,
            format="PNG",
        )

        artifacts[channel_name] = str(artifact_path)

    return artifacts

def generate_grayscale_artifact(file_path, output_dir):

    path = Path(file_path).resolve()
    output_path = Path(output_dir).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"Evidence image not found: {path}")

    output_path.mkdir(parents=True, exist_ok=True)

    try:
        with Image.open(path) as image:
            image.load()
            grayscale_image = image.convert("L")

    except Exception as exc:
        raise ValueError(
            f"Unable to generate grayscale artifact: {path}"
        ) from exc

    artifact_path = output_path / "grayscale.png"

    grayscale_image.save(
        artifact_path,
        format="PNG",
    )

    return str(artifact_path)

def generate_bit_plane_artifacts(channels, output_dir):

    output_path = Path(output_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    artifacts = {}

    for channel_name in ("red", "green", "blue"):
        channel_array = channels[channel_name]

        artifacts[channel_name] = {}

        for bit in range(8):
            bit_plane = (
                ((channel_array >> bit) & 1) * 255
            ).astype(np.uint8)

            artifact_path = (
                output_path
                / f"{channel_name}_bit_{bit}.png"
            )

            bit_plane_image = Image.fromarray(
                bit_plane,
                mode="L",
            )

            bit_plane_image.save(
                artifact_path,
                format="PNG",
            )

            artifacts[channel_name][f"bit_{bit}"] = str(
                artifact_path
            )

    return artifacts

def analyze_visual(file_path):

    # ---------------------------------------------------------
    # Image validation
    # ---------------------------------------------------------

    image_info = load_and_validate_image(file_path)

    # ---------------------------------------------------------
    # RGB channel extraction
    # ---------------------------------------------------------

    channels = extract_rgb_channels(file_path)

    # ---------------------------------------------------------
    # Statistical analysis
    # ---------------------------------------------------------

    channel_statistics = calculate_channel_statistics(channels)

    bit_plane_statistics = calculate_bit_plane_statistics(
        channels
    )

    # ---------------------------------------------------------
    # Objective findings
    # ---------------------------------------------------------

    findings = generate_visual_findings(
        channel_statistics,
        bit_plane_statistics,
    )

    # ---------------------------------------------------------
    # Case analysis directories
    # ---------------------------------------------------------

    case_analysis_dir = (
        Path(file_path).resolve().parent.parent / "analysis"
    )

    visual_output_dir = case_analysis_dir / "visual"

    # ---------------------------------------------------------
    # Derived visual artifacts
    # ---------------------------------------------------------

    rgb_artifacts = generate_rgb_artifacts(
        channels,
        visual_output_dir,
    )

    grayscale_artifact = generate_grayscale_artifact(
        file_path,
        visual_output_dir,
    )

    bit_plane_artifacts = generate_bit_plane_artifacts(
        channels,
        visual_output_dir,
    )

    # ---------------------------------------------------------
    # Normalized structured result
    # ---------------------------------------------------------

    return {
        "module": "Visual & Bit-Plane Analysis",
        "status": "analyzed",

        "target": image_info,

        "channels": {
            "source_mode": channels["original_mode"],
            "converted_to_rgb": channels["converted_to_rgb"],

            "red": {
                "shape": list(channels["red"].shape),
                "dtype": str(channels["red"].dtype),
            },

            "green": {
                "shape": list(channels["green"].shape),
                "dtype": str(channels["green"].dtype),
            },

            "blue": {
                "shape": list(channels["blue"].shape),
                "dtype": str(channels["blue"].dtype),
            },
        },

        "statistics": {
            "channels": channel_statistics,
            "bit_planes": bit_plane_statistics,
        },

        "artifacts": {
            "channels": rgb_artifacts,
            "grayscale": grayscale_artifact,
            "bit_planes": bit_plane_artifacts,
        },

        "findings": findings,
    }

if __name__ == "__main__":
    evidence_file = (
        "cases/"
        "CASE-20260823-025653-EC010F/"
        "evidence/"
        "original_01.png"
    )

    result = analyze_visual(evidence_file)

    print("Visual & Bit-Plane Analysis")
    print("=" * 32)
    print(f"Status: {result['status']}")
    print(f"File: {result['target']['filename']}")
    print(f"Format: {result['target']['format']}")
    print(f"Mode: {result['target']['mode']}")
    print(
        f"Dimensions: "
        f"{result['target']['width']} x "
        f"{result['target']['height']}"
    )
    print(f"File size: {result['target']['file_size']} bytes")
    print(f"Array shape: {result['target']['array_shape']}")
    print(f"Array dtype: {result['target']['array_dtype']}")

    print()
    print("RGB Channels")
    print("------------")

    for channel in ("red", "green", "blue"):
        info = result["channels"][channel]
        print(
            f"{channel.capitalize()}: "
            f"shape={info['shape']}, "
            f"dtype={info['dtype']}"
        ) 
