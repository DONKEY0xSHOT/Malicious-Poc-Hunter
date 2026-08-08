rule Obfuscation_Encoded_Execution
{
    meta:
        description = "Detects encoded command execution (PowerShell/Linux)"
        category = "Obfuscation"
        severity = "Critical"

    strings:

        // Decoding
        $dec_1 = "base64.b64decode" nocase ascii wide
        $dec_2 = "binascii.unhexlify" nocase ascii wide
        $dec_3 = "bytes.fromhex" nocase ascii wide
        $dec_4 = "zlib.decompress" nocase ascii wide
        $dec_5 = "marshal.loads" nocase ascii wide
        $dec_6 = "FromBase64String" nocase ascii wide

        // Base64 blob, minimum 200 chars
        $b64 = /[A-Za-z0-9+\/]{200}/ ascii wide

        // Mixed case, since digit runs and hex digests shouldn't match : )
        $b64_lower = /[A-Za-z0-9+\/]{20}[a-z][A-Za-z0-9+\/]{20}/ ascii wide
        $b64_upper = /[A-Za-z0-9+\/]{20}[A-Z][A-Za-z0-9+\/]{20}/ ascii wide

        // Repositories embed screenshots this way & shoudln't match
        $img_1 = "iVBORw0KGgo" ascii wide
        $img_2 = "/9j/4AAQ" ascii wide
        $img_3 = "R0lGODlh" ascii wide

        // Something able to run the decoded result
        $run_1 = /[\s(,\[{](exec|eval)\s*\(/
        $run_2 = /subprocess\.(run|call|Popen|check_output|check_call)\s*\(/
        $run_3 = /os\.(system|startfile|popen|execv|execvp)\s*\(/
        $run_4 = /ctypes\.(windll|CDLL|cdll)/
        $run_5 = /VirtualAlloc|CreateThread|CreateRemoteThread/ nocase

        // Code execution
        $exec_1 = /[\s(,\[{](exec|eval)\s*\(\s*(base64|codecs|zlib|gzip|bz2|lzma|binascii|marshal|pickle)\./
        $exec_2 = /[\s(,\[{](exec|eval)\s*\([^\r\n)]{0,100}(b64decode|b32decode|a85decode|decompress|fromhex|unhexlify|rot_13|rot13)/
        $exec_3 = /[\s(,\[{]compile\s*\(\s*(base64|codecs|zlib)\./
		
        // Require a real argument
        $exec_4 = /[\s(,\[{](eval|Function)\s*\(\s*(atob|Buffer\.from)\s*\(\s*["'\w]/

        // Encoded PowerShell
        $ps_enc = /(powershell|pwsh)[^\r\n]{0,120}\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+["']?[A-Za-z0-9+\/]{40,}={0,2}/ nocase
        $ps_iex = /(IEX|Invoke-Expression)[^\r\n]{0,140}FromBase64String/ nocase

        // Proof that the file runs the command
        $script_1 = /#![^\r\n]{0,60}\b(sh|bash|zsh|ksh|dash)\b/
        $script_2 = "@echo off" nocase
        $execcall = /(os\.system|subprocess\.(run|call|Popen|check_output|check_call)|popen|child_process\.exec\w{0,8}|WScript\.Shell|Start-Process)\s*\([^\r\n]{0,120}(powershell|pwsh|IEX|Invoke-Expression)/ nocase

    condition:

        // An embedded payload that this file decodes and runs
        (any of ($dec_*) and $b64 and $b64_lower and $b64_upper and any of ($run_*) and not any of ($img_*))
        or any of ($exec_*)
        or (any of ($ps_enc, $ps_iex) and ($script_1 at 0 or $script_2 at 0 or $execcall))
}
