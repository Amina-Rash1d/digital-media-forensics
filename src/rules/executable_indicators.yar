/*
    Module 10 — Executable Indicators

    Purpose:
    Identify executable-related characteristics in recovered
    forensic payloads.

    Important:
    A match identifies an executable or an executable-related
    indicator. It does NOT establish that the artifact is malicious.
*/


rule Executable_PE_Architecture
{
    meta:
        description = "Identifies a Windows PE executable and reports its architecture"
        category = "executable_identification"
        severity = "informational"
        confidence = "high"

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}


rule Executable_ELF_Architecture
{
    meta:
        description = "Identifies an ELF executable or shared object"
        category = "executable_identification"
        severity = "informational"
        confidence = "high"

    condition:
        uint32(0) == 0x464C457F
}


rule Executable_PE_Strings
{
    meta:
        description = "Detects common Windows executable-related strings"
        category = "executable_indicator"
        severity = "low"
        confidence = "medium"

    strings:
        $pe1 = "kernel32.dll" nocase ascii
        $pe2 = "ntdll.dll" nocase ascii
        $pe3 = "user32.dll" nocase ascii
        $pe4 = "advapi32.dll" nocase ascii

    condition:
        2 of them
} 
