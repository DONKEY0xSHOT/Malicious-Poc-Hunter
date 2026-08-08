rule Package_Install_Hook_Code_Execution
{
    meta:
        description = "Detects code that runs automatically while a dependency is installed"
        category = "Supply Chain"
        severity = "Critical"

    strings:

        // setuptools hooks that run on install
        $py_hook_1 = /class\s+\w{1,40}\s*\(\s*(install|develop|egg_info)\s*\)/
        $py_hook_2 = /from\s+setuptools\.command\.(install|develop|egg_info)\s+import/
        $py_hook_3 = /import\s+setuptools\.command\.(install|develop|egg_info)/
        $py_run    = /def\s+run\s*\(\s*self/

        // npm hooks
        $js_hook = /"((pre|post)install|prepare)"\s*:\s*"[^"\r\n]{0,200}(curl|wget|node\s+-e|powershell|child_process|\.sh\b)/ nocase

        $manifest_1 = /"name"\s*:\s*"/
        $manifest_2 = /"version"\s*:\s*"/

        // Required half, so regular build hooks stay clean : )
        $payload_1  = /(urlopen|urlretrieve|requests\.(get|post))\s*\(/
        $payload_2  = /[\s(,\[{](exec|eval)\s*\(/
        $payload_3  = /base64\.b64decode\s*\(/
        $payload_4  = /marshal\.loads\s*\(/
        $payload_5  = /os\.system\s*\(/
        $payload_6  = /subprocess\.(run|call|Popen|check_output|check_call)\s*\(/
        $payload_7  = /curl[^\r\n]{0,120}https?:\/\// nocase
        $payload_8  = /wget[^\r\n]{0,120}https?:\/\// nocase
        $payload_9  = /node\s+-e\s+["']/ nocase
        $payload_10 = /powershell[^\r\n]{0,60}-(enc|encodedcommand|w\s+hidden|windowstyle\s+hidden|nop|noprofile)/ nocase
        $payload_11 = /child_process/
        $payload_12 = /socket\.socket\s*\(/

    condition:
        (any of ($py_hook_*) and $py_run and any of ($payload_*))
        or ($js_hook and all of ($manifest_*))
}
