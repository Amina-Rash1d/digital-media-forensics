/*
    Module 10 — Forensic Anomaly Detection

    Purpose:
    Detect combinations of indicators that may warrant further
    forensic investigation of a recovered payload.

    Important:
    These rules identify suspicious combinations of artifacts.
    A match does NOT prove maliciousness, steganography, or compromise.
*/


rule Forensic_Suspicious_PowerShell_Command
{
    meta:
        description = "Detects a combination of PowerShell and command-execution indicators"
        category = "forensic_anomaly"
        severity = "medium"
        confidence = "medium"

    strings:
        $powershell = "powershell" nocase ascii
        $powershell_exe = "powershell.exe" nocase ascii
        $encoded = "-encodedcommand" nocase ascii
        $cmd = "cmd.exe" nocase ascii
        $execute = "start-process" nocase ascii

    condition:
        1 of ($powershell, $powershell_exe) and
        1 of ($encoded, $cmd, $execute)
}


rule Forensic_Executable_And_Script_Indicators
{
    meta:
        description = "Detects executable signatures combined with scripting indicators"
        category = "forensic_anomaly"
        severity = "medium"
        confidence = "medium"

    strings:
        $mz = { 4D 5A }
        $elf = { 7F 45 4C 46 }
        $powershell = "powershell" nocase ascii
        $cmd = "cmd.exe" nocase ascii
        $python = "python" nocase ascii

    condition:
        1 of ($mz, $elf) and
        1 of ($powershell, $cmd, $python)
}


rule Forensic_Archive_And_Executable_Indicators
{
    meta:
        description = "Detects an archive signature combined with an executable signature"
        category = "forensic_anomaly"
        severity = "medium"
        confidence = "medium"

    strings:
        $zip = { 50 4B 03 04 }
        $mz = { 4D 5A }
        $elf = { 7F 45 4C 46 }

    condition:
        $zip and
        1 of ($mz, $elf)
} 
