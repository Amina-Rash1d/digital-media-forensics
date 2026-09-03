/*
    Module 10 — Archive Indicators

    Purpose:
    Identify common archive/container formats that may be
    recovered as hidden payloads during forensic extraction.

    Important:
    A match identifies a container format.
    It does NOT establish that the archive is malicious.
*/


rule Archive_ZIP
{
    meta:
        description = "Identifies a ZIP archive using its local file header signature"
        category = "container_identification"
        severity = "informational"
        confidence = "high"

    condition:
        uint32(0) == 0x04034B50
}


rule Archive_ZIP_Empty
{
    meta:
        description = "Identifies a ZIP end-of-central-directory signature"
        category = "container_identification"
        severity = "informational"
        confidence = "medium"

    condition:
        uint32(0) == 0x06054B50
}


rule Archive_GZIP
{
    meta:
        description = "Identifies a GZIP compressed data stream"
        category = "container_identification"
        severity = "informational"
        confidence = "high"

    condition:
        uint16(0) == 0x8B1F
}


rule Archive_RAR
{
    meta:
        description = "Identifies a RAR archive"
        category = "container_identification"
        severity = "informational"
        confidence = "high"

    strings:
        $rar4 = "Rar!" ascii
        $rar5 = { 52 61 72 21 1A 07 01 00 }

    condition:
        $rar5 at 0 or $rar4 at 0
}
