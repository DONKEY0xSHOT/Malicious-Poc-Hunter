rule Python_RAT_Indicators
{
    meta:
        description = "Detects Python Remote Access Trojan patterns: C2 socket + keylogging/screenshot + exfiltration"
        category    = "RAT"
        severity    = "Critical"

    strings:
        // C2 communication
        $socket     = "socket.socket"      ascii
        $connect    = ".connect(("         ascii

        // Surveillance capabilities
        $screenshot = "ImageGrab"          ascii
        $keylog1    = "pynput"             ascii
        $keylog2    = "keyboard.on_press"  ascii
        $keylog3    = "on_press"           ascii
        $webcam     = "VideoCapture"       ascii
        $clipboard  = "pyperclip"          ascii

        // Persistence (Windows)
        $reg1       = "winreg"             ascii
        $reg2       = "RegSetValueEx"      ascii
        $reg3       = "HKEY_CURRENT_USER"  ascii
        $startup    = "\\Startup\\"        ascii wide

        // Command execution
        $cmd1       = "subprocess.Popen"   ascii
        $cmd2       = "os.system("         ascii
        $cmd3       = "os.popen("          ascii

        // Exfiltration channels
        $exfil1     = "discord.com/api/webhooks" ascii
        $exfil2     = "api.telegram.org"         ascii
        $exfil3     = "smtp"               nocase ascii
        $exfil4     = "smtplib"                  ascii

        // Obfuscation often present
        $b64        = "base64"             nocase ascii

    condition:
        $socket and $connect and
        any of ($cmd*) and
        (
            any of ($screenshot, $webcam, $clipboard) or
            2 of ($keylog*) or
            (any of ($reg*, $startup) and any of ($exfil*)) or
            (any of ($exfil*) and $b64)
        )
}


rule Python_Dropper
{
    meta:
        description = "Detects Python dropper patterns: download + write + execute"
        category    = "Dropper"
        severity    = "Critical"

    strings:
        // Download methods
        $dl1        = "urllib.request"     ascii
        $dl2        = "requests.get"       ascii
        $dl3        = "requests.post"      ascii
        $dl4        = "urlretrieve"        ascii
        $dl5        = "httpx.get"          ascii

        // Write to disk
        $write1     = /open\s*\([^)]+,\s*["']wb["']\)/ ascii
        $write2     = "os.write("          ascii

        // Execute the payload
        $exec1      = "subprocess.Popen"   ascii
        $exec2      = "subprocess.call"    ascii
        $exec3      = "os.system("         ascii
        $exec4      = "os.execv("          ascii
        $exec5      = "os.execve("         ascii

        // Make executable
        $chmod      = "os.chmod("          ascii
        $chmod2     = "stat.S_IXUSR"       ascii

        // Temporary / hidden paths often used
        $tmp1       = "tempfile"           ascii
        $tmp2       = "/tmp/"              ascii
        $tmp3       = "os.getenv(\"TEMP\")" ascii
        $hidden     = "/."                 ascii

    condition:
        any of ($dl*) and
        any of ($write*) and
        any of ($exec*) and
        (any of ($chmod, $chmod2) or any of ($tmp*) or $hidden)
}
