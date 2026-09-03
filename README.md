<p align="center">
  <img src="assets/banner.svg" alt="Digital Media Forensics & Steganalysis Framework" width="100%">
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10+-3776AB?logo=python&logoColor=white">
  <img alt="Status" src="https://img.shields.io/badge/status-active-39d98a">
</p>

A modular framework for examining suspicious image files — triage, metadata, statistics, steganalysis, verification, and reporting in one pipeline.

**Core idea:** a single suspicious finding is never a conclusion by itself. Every result is a candidate until it's verified and correlated with the rest of the evidence.

```
Image → Triage → Metadata / Structure / Visual / Statistical / Steganalysis
      → Verification & Extraction → Correlation → Risk Score → Report
```

## Quick start

```bash
git clone https://github.com/Amina-Rash1d/digital-media-forensics.git
cd digital-media-forensics
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python3 pipeline.py --input path/to/image.png
```

Reports land in `case_reports/<CASE-ID>/`.

## What it covers

Metadata forensics · file structure & carving · RGB/bit-plane visual analysis · LSB & entropy statistics · `zsteg` steganalysis · Steghide/zsteg verification & extraction · YARA scanning · evidence correlation & risk scoring · JSON/TXT/PDF reporting

## Validation dataset

Six controlled test cases (`data/test_dataset/`) covering a clean image, a stego sample, a metadata anomaly, appended data, a resaved image, and a hidden payload requiring full extraction — with ground truth included for each.

## Structure

```
src/            analysis, correlation, detection, reporting modules
data/           test dataset + ground truth
case_reports/   generated output
pipeline.py     entry point
```

## Status

Student / learning project, actively developed. Not for production evidentiary use.

---

<p align="center"><sub>Amina Rashid — Cybersecurity Student · Digital Forensics · Steganalysis</sub></p>
