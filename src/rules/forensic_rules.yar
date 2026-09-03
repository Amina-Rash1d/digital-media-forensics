rule Suspicious_Executable_PE
{
    meta:
        description = "Detects a Windows PE executable by its MZ and PE signatures"
        category = "file_identification"
        severity = "medium"

    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00" ascii

    condition:
        $mz at 0 and $pe
}


rule ELF_Executable
{
    meta:
        description = "Detects an ELF executable"
        category = "file_identification"
        severity = "medium"

    strings:
        $elf = { 7F 45 4C 46 }

    condition:
        $elf at 0
}


rule Embedded_PowerShell_Indicator
{
    meta:
        description = "Detects common PowerShell execution indicators"
        category = "behavioral_indicator"
        severity = "medium"

    strings:
        $ps1 = "powershell" nocase ascii
        $ps2 = "powershell.exe" nocase ascii
        $ps3 = "-encodedcommand" nocase ascii
        $ps4 = "-executionpolicy" nocase ascii

    condition:
        2 of them
}


rule Suspicious_Command_Execution_Indicators
{
    meta:
        description = "Detects common command execution indicators"
        category = "behavioral_indicator"
        severity = "low"

    strings:
        $cmd = "cmd.exe" nocase ascii
        $shell = "shell" nocase ascii
        $exec = "execute" nocase ascii
        $system = "system(" ascii

    condition:
        2 of them
}


rule Archive_Signature
{
    meta:
        description = "Detects a ZIP archive signature"
        category = "container_identification"
        severity = "low"

    strings:
        $zip = { 50 4B 03 04 }

    condition:
        $zip at 0
}
