/*
    Module 10 — File Signature Detection

    Purpose:
    Identify common executable and container file formats
    using their expected magic signatures.

    Important:
    These rules identify file formats.
    A match does NOT mean the file is malicious.
*/


rule FileSignature_PE
{
    meta:
        description = "Identifies a valid Windows Portable Executable (PE) file"
        category = "file_identification"
        severity = "informational"
        confidence = "high"

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}


rule FileSignature_ELF
{
    meta:
        description = "Identifies an ELF executable or shared object"
        category = "file_identification"
        severity = "informational"
        confidence = "high"

    condition:
        uint32(0) == 0x464C457F
}


rule FileSignature_ZIP
{
    meta:
        description = "Identifies a ZIP archive using its local file header signature"
        category = "container_identification"
        severity = "informational"
        confidence = "high"

    condition:
        uint32(0) == 0x04034B50
}
