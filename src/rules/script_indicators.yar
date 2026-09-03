/*
    Module 10 — Script Indicators

    Purpose:
    Detect common scripting and command-execution indicators
    that may be encountered inside recovered forensic payloads.

    Important:
    These are behavioral indicators, not malware verdicts.
    A single scripting string is not considered sufficient evidence.
*/


rule Script_PowerShell_Execution
{
    meta:
        description = "Detects multiple PowerShell execution indicators"
        category = "script_indicator"
        severity = "medium"
        confidence = "medium"

    strings:
        $ps1 = "powershell" nocase ascii
        $ps2 = "powershell.exe" nocase ascii
        $ps3 = "-encodedcommand" nocase ascii
        $ps4 = "-executionpolicy" nocase ascii

    condition:
        2 of them
}


rule Script_Windows_Command_Execution
{
    meta:
        description = "Detects multiple Windows command execution indicators"
        category = "script_indicator"
        severity = "low"
        confidence = "medium"

    strings:
        $cmd1 = "cmd.exe" nocase ascii
        $cmd2 = "/c" ascii
        $cmd3 = "command.com" nocase ascii
        $cmd4 = "start-process" nocase ascii

    condition:
        2 of them
}


rule Script_Common_Scripting_Indicators
{
    meta:
        description = "Detects multiple common scripting-language indicators"
        category = "script_indicator"
        severity = "low"
        confidence = "low"

    strings:
        $python = "python" nocase ascii
        $python_exec = "python.exe" nocase ascii
        $bash = "/bin/bash" ascii
        $sh = "/bin/sh" ascii
        $javascript = "javascript" nocase ascii

    condition:
        2 of them
}
