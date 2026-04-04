rule Obfuscation_Encoded_Execution
{
    meta:
        description = "Detects encoded command execution in code files (PowerShell/Python)"
        category    = "Obfuscation"
        severity    = "Critical"

    strings:
        // PowerShell indicators
        $ps_exec1 = "powershell" nocase ascii wide
        $ps_exec2 = "pwsh"       nocase ascii wide
        $ps_flag  = /-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s/i

        // Python base64 decode with execution
        $py_b64_decode  = "base64.b64decode"  nocase ascii wide
        $py_exec1       = "exec("             nocase ascii wide
        $py_exec2       = "eval("             nocase ascii wide
        $py_exec3       = "__import__"        nocase ascii wide
        $py_compile     = "compile("          nocase ascii wide

        // Base64 blob: minimum 100 chars (25 groups of 4), NOT preceded by common cert headers
        $b64_blob = /([A-Za-z0-9+\/]{4}){25,}(==|=)?/ ascii wide

        // Exclusion: PEM/certificate markers → high-confidence benign base64
        $cert_header1 = "-----BEGIN CERTIFICATE-----"    ascii
        $cert_header2 = "-----BEGIN PUBLIC KEY-----"     ascii
        $cert_header3 = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $cert_header4 = "-----BEGIN PRIVATE KEY-----"    ascii

    condition:
        not any of ($cert_header*) and
        $b64_blob and
        (
            // PowerShell: encoded command flag present
            (any of ($ps_exec*) and $ps_flag)
            or
            // Python: base64 decode combined with code execution
            ($py_b64_decode and any of ($py_exec*, $py_compile))
        )
}
