/* Starter YARA ruleset for the Agent Garrett broker.
   Replace with YARA-Forge / your own rules; point YARA_RULES env at another file. */

rule Embedded_PE {
  meta: description = "Embedded PE / DOS stub string"
  strings: $mz = "This program cannot be run in DOS mode"
  condition: $mz
}

rule Suspicious_PowerShell {
  meta: description = "PowerShell download/exec cradle indicators"
  strings:
    $a = "powershell" nocase
    $b = "-enc" nocase
    $c = "FromBase64String" nocase
    $d = "DownloadString" nocase
    $e = "IEX(" nocase
  condition: $a and 2 of ($b, $c, $d, $e)
}

rule Process_Injection_APIs {
  meta: description = "Classic process-injection Win32 API set"
  strings:
    $a = "VirtualAllocEx"
    $b = "WriteProcessMemory"
    $c = "CreateRemoteThread"
  condition: all of them
}

rule UPX_Packed {
  meta: description = "UPX packer section markers"
  strings: $u1 = "UPX0" $u2 = "UPX1"
  condition: $u1 and $u2
}

rule Long_Base64_Blob {
  meta: description = "Long base64 blob (possible embedded payload)"
  strings: $b = /[A-Za-z0-9+\/]{200,}={0,2}/
  condition: $b
}

rule Defense_Evasion_Cmds {
  meta: description = "Shadow-copy deletion / recovery tampering (ransomware)"
  strings:
    $a = "vssadmin" nocase
    $b = "delete shadows" nocase
    $c = "bcdedit" nocase
    $d = "wbadmin delete" nocase
  condition: 2 of them
}
