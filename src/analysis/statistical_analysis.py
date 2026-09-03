from pathlib import Path

from PIL import Image
import numpy as np
import matplotlib.pyplot as plt


def load_rgb_channels(file_path):

    path = Path(file_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(
            f"Evidence image not found: {path}"
        )

    try:
        with Image.open(path) as image:
            image_format = image.format
            original_mode = image.mode

            image.load()

            rgb_image = image.convert("RGB")
            image_array = np.array(rgb_image)

    except Exception as exc:
        raise ValueError(
            f"Unable to load image for statistical analysis: {path}"
        ) from exc

    return {
        "file": str(path),
        "filename": path.name,
        "format": image_format,
        "original_mode": original_mode,
        "width": int(image_array.shape[1]),
        "height": int(image_array.shape[0]),
        "red": image_array[:, :, 0],
        "green": image_array[:, :, 1],
        "blue": image_array[:, :, 2],
    }


def calculate_lsb_statistics(channels):

    statistics = {}

    for channel_name in ("red", "green", "blue"):
        channel = channels[channel_name]

        lsb = channel & 1

        ones = int(np.sum(lsb))
        total = int(channel.size)
        zeros = int(total - ones)

        statistics[channel_name] = {
            "zeros": zeros,
            "ones": ones,
            "zero_ratio": float(zeros / total),
            "one_ratio": float(ones / total),
            "total_values": total,
        }

    return statistics


def calculate_pixel_value_distributions(channels):

    distributions = {}

    for channel_name in ("red", "green", "blue"):
        channel = channels[channel_name]

        counts = np.bincount(
            channel.flatten(),
            minlength=256,
        )

        distributions[channel_name] = {
            str(value): int(counts[value])
            for value in range(256)
        }

    return distributions


def calculate_shannon_entropy(values):

    values = np.asarray(values)

    counts = np.bincount(
        values.flatten(),
        minlength=256,
    )

    probabilities = counts[counts > 0] / values.size

    entropy = -np.sum(
        probabilities * np.log2(probabilities)
    )

    return float(entropy)


def calculate_channel_entropy(channels):

    return {
        channel_name: calculate_shannon_entropy(
            channels[channel_name]
        )
        for channel_name in ("red", "green", "blue")
    }


def generate_histogram_artifacts(channels, output_dir):

    output_path = Path(output_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    artifacts = {}

    for channel_name in ("red", "green", "blue"):
        channel = channels[channel_name]

        counts = np.bincount(
            channel.flatten(),
            minlength=256,
        )

        figure = plt.figure(figsize=(10, 5))

        plt.bar(
            range(256),
            counts,
            width=1.0,
        )

        plt.title(
            f"{channel_name.capitalize()} Channel "
            "Pixel-Value Distribution"
        )

        plt.xlabel("Pixel Value")
        plt.ylabel("Frequency")

        plt.xlim(0, 255)

        plt.tight_layout()

        artifact_path = (
            output_path
            / f"{channel_name}_histogram.png"
        )

        figure.savefig(
            artifact_path,
            dpi=150,
        )

        plt.close(figure)

        artifacts[channel_name] = str(
            artifact_path
        )

    return artifacts


def divide_into_regions(channels, rows=4, columns=4):

    regions = {}

    height, width = channels["red"].shape

    row_edges = np.linspace(
        0,
        height,
        rows + 1,
        dtype=int,
    )

    column_edges = np.linspace(
        0,
        width,
        columns + 1,
        dtype=int,
    )

    for region_row in range(rows):
        for region_column in range(columns):

            region_id = (
                f"region_{region_row + 1}_"
                f"{region_column + 1}"
            )

            y_start = row_edges[region_row]
            y_end = row_edges[region_row + 1]

            x_start = column_edges[region_column]
            x_end = column_edges[region_column + 1]

            regions[region_id] = {
                "row": region_row + 1,
                "column": region_column + 1,
                "red": channels["red"][
                    y_start:y_end,
                    x_start:x_end,
                ],
                "green": channels["green"][
                    y_start:y_end,
                    x_start:x_end,
                ],
                "blue": channels["blue"][
                    y_start:y_end,
                    x_start:x_end,
                ],
            }

    return regions


def calculate_regional_statistics(regions):

    statistics = {}

    for region_id, region in regions.items():

        statistics[region_id] = {
            "row": region["row"],
            "column": region["column"],
            "red": {
                "mean": float(np.mean(region["red"])),
                "std_dev": float(np.std(region["red"])),
            },
            "green": {
                "mean": float(np.mean(region["green"])),
                "std_dev": float(np.std(region["green"])),
            },
            "blue": {
                "mean": float(np.mean(region["blue"])),
                "std_dev": float(np.std(region["blue"])),
            },
        }

    return statistics


def calculate_regional_lsb_statistics(regions):

    statistics = {}

    for region_id, region in regions.items():

        statistics[region_id] = {
            "row": region["row"],
            "column": region["column"],
        }

        for channel_name in ("red", "green", "blue"):

            channel = region[channel_name]

            lsb = channel & 1

            ones = int(np.sum(lsb))
            total = int(channel.size)
            zeros = int(total - ones)

            statistics[region_id][channel_name] = {
                "zeros": zeros,
                "ones": ones,
                "zero_ratio": float(zeros / total),
                "one_ratio": float(ones / total),
            }

    return statistics


def calculate_regional_entropy(regions):

    entropy = {}

    for region_id, region in regions.items():

        entropy[region_id] = {
            "row": region["row"],
            "column": region["column"],
        }

        for channel_name in ("red", "green", "blue"):

            entropy[region_id][channel_name] = (
                calculate_shannon_entropy(
                    region[channel_name]
                )
            )

    return entropy


def calculate_regional_lsb_spread(regional_lsb_statistics):

    spread = {}

    for channel_name in ("red", "green", "blue"):

        ratios = [
            region[channel_name]["one_ratio"]
            for region in regional_lsb_statistics.values()
        ]

        ratios = np.asarray(ratios)

        spread[channel_name] = {
            "minimum": float(np.min(ratios)),
            "maximum": float(np.max(ratios)),
            "mean": float(np.mean(ratios)),
            "std_dev": float(np.std(ratios)),
        }

    return spread


def compare_lsb_statistics(
    reference_lsb,
    target_lsb,
):

    comparison = {}

    for channel_name in ("red", "green", "blue"):

        reference_ratio = reference_lsb[
            channel_name
        ]["one_ratio"]

        target_ratio = target_lsb[
            channel_name
        ]["one_ratio"]

        comparison[channel_name] = {
            "reference_one_ratio": float(
                reference_ratio
            ),
            "target_one_ratio": float(
                target_ratio
            ),
            "absolute_difference": float(
                abs(
                    target_ratio
                    - reference_ratio
                )
            ),
        }

    return comparison


def compare_entropy(
    reference_entropy,
    target_entropy,
):

    comparison = {}

    for channel_name in ("red", "green", "blue"):

        reference_value = reference_entropy[
            channel_name
        ]

        target_value = target_entropy[
            channel_name
        ]

        comparison[channel_name] = {
            "reference_entropy": float(
                reference_value
            ),
            "target_entropy": float(
                target_value
            ),
            "absolute_difference": float(
                abs(
                    target_value
                    - reference_value
                )
            ),
        }

    return comparison

def compare_statistical_profiles(
    reference_lsb,
    target_lsb,
    reference_pixel_distributions,
    target_pixel_distributions,
    reference_entropy,
    target_entropy,
    reference_regional_statistics,
    target_regional_statistics,
    reference_regional_lsb_spread,
    target_regional_lsb_spread,
):

    comparison = {
        "lsb": compare_lsb_statistics(
            reference_lsb,
            target_lsb,
        ),
        "entropy": compare_entropy(
            reference_entropy,
            target_entropy,
        ),
        "pixel_value_distribution": {},
        "regional_statistics": {},
        "regional_lsb_spread": {},
    }

    for channel_name in (
        "red",
        "green",
        "blue",
    ):
        reference_distribution = np.asarray(
            [
                reference_pixel_distributions[
                    channel_name
                ][str(value)]
                for value in range(256)
            ],
            dtype=np.float64,
        )

        target_distribution = np.asarray(
            [
                target_pixel_distributions[
                    channel_name
                ][str(value)]
                for value in range(256)
            ],
            dtype=np.float64,
        )

        absolute_difference = np.abs(
            target_distribution
            - reference_distribution
        )

        comparison[
            "pixel_value_distribution"
        ][channel_name] = {
            "reference_total": int(
                np.sum(reference_distribution)
            ),
            "target_total": int(
                np.sum(target_distribution)
            ),
            "total_absolute_difference": float(
                np.sum(absolute_difference)
            ),
            "maximum_value_difference": int(
                np.max(absolute_difference)
            ),
            "different_value_bins": int(
                np.count_nonzero(
                    absolute_difference
                )
            ),
        }

    for region_id in reference_regional_statistics:
        if region_id not in target_regional_statistics:
            continue

        reference_region = (
            reference_regional_statistics[
                region_id
            ]
        )

        target_region = (
            target_regional_statistics[
                region_id
            ]
        )

        comparison[
            "regional_statistics"
        ][region_id] = {
            "row": reference_region["row"],
            "column": reference_region["column"],
            "red": {
                "mean_absolute_difference": float(
                    abs(
                        target_region["red"]["mean"]
                        - reference_region["red"]["mean"]
                    )
                ),
                "std_dev_absolute_difference": float(
                    abs(
                        target_region["red"]["std_dev"]
                        - reference_region["red"]["std_dev"]
                    )
                ),
            },
            "green": {
                "mean_absolute_difference": float(
                    abs(
                        target_region["green"]["mean"]
                        - reference_region["green"]["mean"]
                    )
                ),
                "std_dev_absolute_difference": float(
                    abs(
                        target_region["green"]["std_dev"]
                        - reference_region["green"]["std_dev"]
                    )
                ),
            },
            "blue": {
                "mean_absolute_difference": float(
                    abs(
                        target_region["blue"]["mean"]
                        - reference_region["blue"]["mean"]
                    )
                ),
                "std_dev_absolute_difference": float(
                    abs(
                        target_region["blue"]["std_dev"]
                        - reference_region["blue"]["std_dev"]
                    )
                ),
            },
        }

    for channel_name in (
        "red",
        "green",
        "blue",
    ):
        reference_spread = (
            reference_regional_lsb_spread[
                channel_name
            ]
        )

        target_spread = (
            target_regional_lsb_spread[
                channel_name
            ]
        )

        comparison[
            "regional_lsb_spread"
        ][channel_name] = {
            "minimum_absolute_difference": float(
                abs(
                    target_spread["minimum"]
                    - reference_spread["minimum"]
                )
            ),
            "maximum_absolute_difference": float(
                abs(
                    target_spread["maximum"]
                    - reference_spread["maximum"]
                )
            ),
            "mean_absolute_difference": float(
                abs(
                    target_spread["mean"]
                    - reference_spread["mean"]
                )
            ),
            "std_dev_absolute_difference": float(
                abs(
                    target_spread["std_dev"]
                    - reference_spread["std_dev"]
                )
            ),
        }

    return comparison 

def generate_statistical_findings(
    lsb_statistics,
    channel_entropy,
    regional_lsb_spread,
):

    findings = []

    lsb_ratios = {
        channel: lsb_statistics[channel]["one_ratio"]
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
            "id": "STAT-OBS-001",
            "type": "observation",
            "severity": "info",
            "title": "LSB distributions differ across RGB channels",
            "description": (
                f"The {highest_lsb_channel} channel has the highest "
                f"LSB one-ratio ({lsb_ratios[highest_lsb_channel]:.6f}), "
                f"while the {lowest_lsb_channel} channel has the lowest "
                f"LSB one-ratio ({lsb_ratios[lowest_lsb_channel]:.6f})."
            ),
            "evidence": {
                "lsb_one_ratios": lsb_ratios,
            },
        }
    )

    highest_entropy_channel = max(
        channel_entropy,
        key=channel_entropy.get,
    )

    lowest_entropy_channel = min(
        channel_entropy,
        key=channel_entropy.get,
    )

    findings.append(
        {
            "id": "STAT-OBS-002",
            "type": "observation",
            "severity": "info",
            "title": "Shannon entropy differs across RGB channels",
            "description": (
                f"The {highest_entropy_channel} channel has the highest "
                f"measured entropy "
                f"({channel_entropy[highest_entropy_channel]:.6f}), "
                f"while the {lowest_entropy_channel} channel has the lowest "
                f"measured entropy "
                f"({channel_entropy[lowest_entropy_channel]:.6f})."
            ),
            "evidence": {
                "shannon_entropy": channel_entropy,
            },
        }
    )

    findings.append(
        {
            "id": "STAT-OBS-003",
            "type": "observation",
            "severity": "info",
            "title": "Regional LSB variation is measurable",
            "description": (
                "LSB one-ratios vary across image regions. "
                "The regional spread describes spatial variation "
                "in the measured LSB distribution and does not "
                "independently establish steganography."
            ),
            "evidence": {
                "regional_lsb_spread": regional_lsb_spread,
            },
        }
    )

    return findings 

def analyze_statistics(
    file_path,
    output_dir,
    reference_file=None,
    rows=4,
    columns=4,
):

    if rows < 1:
        raise ValueError(
            "Rows must be at least 1."
        )

    if columns < 1:
        raise ValueError(
            "Columns must be at least 1."
        )

    channels = load_rgb_channels(
        file_path
    )

    lsb_statistics = calculate_lsb_statistics(
        channels
    )

    pixel_value_distributions = (
        calculate_pixel_value_distributions(
            channels
        )
    )

    channel_entropy = calculate_channel_entropy(
        channels
    )

    histogram_artifacts = generate_histogram_artifacts(
        channels,
        output_dir,
    )

    regions = divide_into_regions(
        channels,
        rows=rows,
        columns=columns,
    )

    regional_statistics = calculate_regional_statistics(
        regions
    )

    regional_lsb_statistics = (
        calculate_regional_lsb_statistics(
            regions
        )
    )

    regional_entropy = calculate_regional_entropy(
        regions
    )

    regional_lsb_spread = calculate_regional_lsb_spread(
        regional_lsb_statistics
    )

    findings = generate_statistical_findings(
        lsb_statistics,
        channel_entropy,
        regional_lsb_spread,
    )

    comparison = None

    if reference_file is not None:

        reference_channels = load_rgb_channels(
            reference_file
        )

        if (
            reference_channels["width"]
            != channels["width"]
            or
            reference_channels["height"]
            != channels["height"]
        ):
            raise ValueError(
                "Reference image dimensions do not match "
                "the target image. Controlled statistical "
                "comparison requires matching dimensions."
            )

        reference_lsb = calculate_lsb_statistics(
            reference_channels
        )

        reference_pixel_value_distributions = (
            calculate_pixel_value_distributions(
                reference_channels
            )
        )

        reference_entropy = calculate_channel_entropy(
            reference_channels
        )

        reference_regions = divide_into_regions(
            reference_channels,
            rows=rows,
            columns=columns,
        )

        reference_regional_statistics = (
            calculate_regional_statistics(
                reference_regions
            )
        )

        reference_regional_lsb_statistics = (
            calculate_regional_lsb_statistics(
                reference_regions
            )
        )

        reference_regional_lsb_spread = (
            calculate_regional_lsb_spread(
                reference_regional_lsb_statistics
            )
        )

        comparison = (
            compare_statistical_profiles(
                reference_lsb=reference_lsb,
                target_lsb=lsb_statistics,
                reference_pixel_distributions=(
                    reference_pixel_value_distributions
                ),
                target_pixel_distributions=(
                    pixel_value_distributions
                ),
                reference_entropy=reference_entropy,
                target_entropy=channel_entropy,
                reference_regional_statistics=(
                    reference_regional_statistics
                ),
                target_regional_statistics=(
                    regional_statistics
                ),
                reference_regional_lsb_spread=(
                    reference_regional_lsb_spread
                ),
                target_regional_lsb_spread=(
                    regional_lsb_spread
                ),
            )
        )

        comparison["reference_file"] = str(
            Path(reference_file).resolve()
        )

        comparison["target_file"] = str(
            Path(file_path).resolve()
        )

        comparison["reference_dimensions"] = {
            "width": reference_channels["width"],
            "height": reference_channels["height"],
        }

        comparison["target_dimensions"] = {
            "width": channels["width"],
            "height": channels["height"],
        }

    results = {
        "analysis": {
            "module": "statistical_steganalysis",
            "status": "analyzed",
        },
        "file": {
            "path": channels["file"],
            "filename": channels["filename"],
            "format": channels["format"],
            "original_mode": channels["original_mode"],
            "width": channels["width"],
            "height": channels["height"],
            "pixel_count": (
                channels["width"]
                * channels["height"]
            ),
        },
        "lsb_statistics": lsb_statistics,
        "pixel_value_distributions": (
            pixel_value_distributions
        ),
        "channel_entropy": channel_entropy,
        "histogram_artifacts": histogram_artifacts,
        "regional_analysis": {
            "rows": rows,
            "columns": columns,
            "region_count": len(regions),
            "statistics": regional_statistics,
            "lsb_statistics": regional_lsb_statistics,
            "entropy": regional_entropy,
            "lsb_spread": regional_lsb_spread,
        },
        "comparison": comparison,
        "findings": findings,
    }

    return results

def print_statistical_summary(results):

    file_info = results["file"]

    print("Statistical Steganalysis")
    print("=" * 32)

    print(
        f"Status: "
        f"{results['analysis']['status']}"
    )

    print(
        f"File: "
        f"{file_info['filename']}"
    )

    print(
        f"Format: "
        f"{file_info['format']}"
    )

    print(
        f"Dimensions: "
        f"{file_info['width']} x "
        f"{file_info['height']}"
    )

    print(
        f"Pixel Count: "
        f"{file_info['pixel_count']}"
    )

    print()
    print("LSB Statistics")
    print("-" * 16)

    for channel_name in (
        "red",
        "green",
        "blue",
    ):
        statistics = results[
            "lsb_statistics"
        ][channel_name]

        print(
            f"{channel_name.capitalize()}: "
            f"zeros={statistics['zeros']}, "
            f"ones={statistics['ones']}, "
            f"zero_ratio={statistics['zero_ratio']:.6f}, "
            f"one_ratio={statistics['one_ratio']:.6f}"
        )

    print()
    print("Shannon Entropy")
    print("-" * 16)

    for channel_name in (
        "red",
        "green",
        "blue",
    ):
        entropy = results[
            "channel_entropy"
        ][channel_name]

        print(
            f"{channel_name.capitalize()}: "
            f"{entropy:.6f} bits"
        )

    print()
    print("Regional Analysis")
    print("-" * 18)

    regional = results[
        "regional_analysis"
    ]

    print(
        f"Grid: "
        f"{regional['rows']} x "
        f"{regional['columns']}"
    )

    print(
        f"Regions analyzed: "
        f"{regional['region_count']}"
    )

    print()
    print("Histogram Artifacts")
    print("-" * 19)

    for channel_name, path in results[
        "histogram_artifacts"
    ].items():

        print(
            f"{channel_name.capitalize()}: "
            f"{path}"
        )

    print()
    print("Statistical Findings")
    print("-" * 21)

    for finding in results["findings"]:

        print(
            f"{finding['id']}: "
            f"{finding['title']}"
        )

    comparison = results.get(
        "comparison"
    )

    if comparison is not None:

        print()
        print("Controlled Comparison")
        print("-" * 21)

        print(
            f"Reference: "
            f"{Path(comparison['reference_file']).name}"
        )

        print(
            f"Target: "
            f"{Path(comparison['target_file']).name}"
        )

        print()
        print("LSB Differences")
        print("-" * 16)

        for channel_name, values in comparison[
            "lsb"
        ].items():

            print(
                f"{channel_name.capitalize()}: "
                f"{values['absolute_difference']:.6f}"
            )

        print()
        print("Entropy Differences")
        print("-" * 19)

        for channel_name, values in comparison[
            "entropy"
        ].items():

            print(
                f"{channel_name.capitalize()}: "
                f"{values['absolute_difference']:.6f}"
            )

        print()
        print("Pixel-Value Distribution Differences")
        print("-" * 37)

        for channel_name, values in comparison[
            "pixel_value_distribution"
        ].items():

            print(
                f"{channel_name.capitalize()}: "
                f"different_bins="
                f"{values['different_value_bins']}, "
                f"total_absolute_difference="
                f"{values['total_absolute_difference']:.0f}, "
                f"maximum_bin_difference="
                f"{values['maximum_value_difference']}"
            )

        print()
        print("Regional Channel Differences")
        print("-" * 29)

        regional_comparison = comparison[
            "regional_statistics"
        ]

        channel_totals = {
            "red": {
                "mean": 0.0,
                "std_dev": 0.0,
            },
            "green": {
                "mean": 0.0,
                "std_dev": 0.0,
            },
            "blue": {
                "mean": 0.0,
                "std_dev": 0.0,
            },
        }

        for region in regional_comparison.values():

            for channel_name in (
                "red",
                "green",
                "blue",
            ):
                channel_totals[
                    channel_name
                ]["mean"] += (
                    region[channel_name][
                        "mean_absolute_difference"
                    ]
                )

                channel_totals[
                    channel_name
                ]["std_dev"] += (
                    region[channel_name][
                        "std_dev_absolute_difference"
                    ]
                )

        region_count = len(
            regional_comparison
        )

        if region_count > 0:

            for channel_name in (
                "red",
                "green",
                "blue",
            ):
                average_mean_difference = (
                    channel_totals[
                        channel_name
                    ]["mean"]
                    / region_count
                )

                average_std_difference = (
                    channel_totals[
                        channel_name
                    ]["std_dev"]
                    / region_count
                )

                print(
                    f"{channel_name.capitalize()}: "
                    f"avg_mean_difference="
                    f"{average_mean_difference:.6f}, "
                    f"avg_std_difference="
                    f"{average_std_difference:.6f}"
                )

        print()
        print("Regional LSB Spread Differences")
        print("-" * 32)

        for channel_name, values in comparison[
            "regional_lsb_spread"
        ].items():

            print(
                f"{channel_name.capitalize()}: "
                f"mean="
                f"{values['mean_absolute_difference']:.6f}, "
                f"std_dev="
                f"{values['std_dev_absolute_difference']:.6f}, "
                f"min="
                f"{values['minimum_absolute_difference']:.6f}, "
                f"max="
                f"{values['maximum_absolute_difference']:.6f}"
            )

        print()
        print(
            "Interpretation: "
            "Measured statistical differences are "
            "comparative indicators only and do not "
            "independently establish steganography."
        )

def main():

    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Statistical steganalysis for "
            "digital-media forensic evidence."
        )
    )

    parser.add_argument(
        "file",
        help="Path to the evidence image.",
    )

    parser.add_argument(
        "--output-dir",
        default=None,
        help=(
            "Directory for statistical artifacts. "
            "Defaults to <evidence_case>/analysis/statistical."
        ),
    )

    parser.add_argument(
        "--reference",
        default=None,
        help=(
            "Optional clean/reference image "
            "for statistical comparison."
        ),
    )

    parser.add_argument(
        "--rows",
        type=int,
        default=4,
        help="Number of regional rows.",
    )

    parser.add_argument(
        "--columns",
        type=int,
        default=4,
        help="Number of regional columns.",
    )

    args = parser.parse_args()

    evidence_path = Path(
        args.file
    ).resolve()

    if not evidence_path.is_file():
        raise FileNotFoundError(
            f"Evidence image not found: {evidence_path}"
        )

    if args.rows < 1:
        raise ValueError(
            "Rows must be at least 1."
        )

    if args.columns < 1:
        raise ValueError(
            "Columns must be at least 1."
        )

    if args.output_dir is None:
        case_directory = evidence_path.parent.parent

        output_directory = (
            case_directory
            / "analysis"
            / "statistical"
        )
    else:
        output_directory = Path(
            args.output_dir
        ).resolve()

    results = analyze_statistics(
        file_path=evidence_path,
        output_dir=output_directory,
        reference_file=args.reference,
        rows=args.rows,
        columns=args.columns,
    )

    print_statistical_summary(
        results
    )


if __name__ == "__main__":
    main()
