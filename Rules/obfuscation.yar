rule Obfuscation_Encoded_Execution
{
    meta:
        description = "Detects encoded command execution (PowerShell/Linux)"
        category = "Obfuscation"
        severity = "Critical"

    strings:
	
        // PowerShell indicators
        $ps_exec1 = "powershell" nocase ascii wide
        $ps_exec2 = "pwsh" nocase ascii wide
        $ps_flag = /-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s/i
		$py_b64 = "base64.b64decode" nocase ascii wide
		
        // Base64 blob, minimum 200 chars
        $b64 = /([A-Za-z0-9+\/]{4}){50,}(==|=)?/ ascii wide

    condition:
        (
            (any of ($ps_exec*) and $ps_flag) or
			$py_b64
        )
        and $b64
}
