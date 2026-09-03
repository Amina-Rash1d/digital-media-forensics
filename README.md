<h1 align="center">Digital Media Forensics</h1>
<h3 align="center"><sub>& Steganalysis Framework</sub></h3> 

A modular framework for examining suspicious image files — triage, metadata, statistics, steganalysis, verification, and reporting in one pipeline.

**Core idea:** a single suspicious finding is never a conclusion by itself. Every result is a candidate until it's verified and correlated with the rest of the evidence.

```text
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
