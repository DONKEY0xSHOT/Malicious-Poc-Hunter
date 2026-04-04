rule Windows_Persistence
{
    meta:
        description = "Detects Windows persistence via registry Run keys, scheduled tasks, or startup folder"
        category    = "Persistence"
        severity    = "High"

    strings:
        // Registry Run keys
        $reg_run1   = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"  nocase ascii wide
        $reg_run2   = "HKCU\\Software\\Microsoft\\Windows"                  nocase ascii wide
        $reg_run3   = "HKLM\\Software\\Microsoft\\Windows"                  nocase ascii wide
        $reg_api1   = "RegSetValueEx"      ascii wide
        $reg_api2   = "winreg"             ascii
        $reg_api3   = "reg add"            nocase ascii wide

        // Scheduled tasks
        $schtask1   = "schtasks"           nocase ascii wide
        $schtask2   = "SchTasks.exe"       nocase ascii wide
        $schtask3   = "Register-ScheduledTask" nocase ascii wide
        $schtask4   = "New-ScheduledTask"  nocase ascii wide

        // Startup folder
        $startup1   = "\\Start Menu\\Programs\\Startup" nocase ascii wide
        $startup2   = "shell:startup"     nocase ascii wide

        // Windows service
        $svc1       = "sc create"         nocase ascii wide
        $svc2       = "New-Service"        nocase ascii wide

        // Execution context (confirms it's code, not documentation)
        $exec1      = "subprocess"         ascii
        $exec2      = "os.system("         ascii
        $exec3      = "Invoke-Expression"  nocase ascii wide
        $exec4      = "Start-Process"      nocase ascii wide
        $exec5      = "shell32"            nocase ascii wide

    condition:
        any of ($exec*) and
        (
            (any of ($reg_run*, $reg_api*)) or
            (any of ($schtask*)) or
            (any of ($startup*)) or
            (any of ($svc*))
        )
}


rule Linux_Persistence
{
    meta:
        description = "Detects Linux persistence via cron, systemd, or shell profile modification"
        category    = "Persistence"
        severity    = "High"

    strings:
        // Cron
        $cron1      = "crontab"            ascii
        $cron2      = "/etc/cron"          ascii
        $cron3      = "/var/spool/cron"    ascii
        $cron4      = "@reboot"            ascii

        // Systemd service creation
        $systemd1   = "/etc/systemd/system" ascii
        $systemd2   = "systemctl enable"   ascii
        $systemd3   = "[Unit]"             ascii
        $systemd4   = "ExecStart="         ascii

        // Shell profile modification
        $profile1   = ".bashrc"            ascii
        $profile2   = ".profile"           ascii
        $profile3   = ".bash_profile"      ascii
        $profile4   = "/etc/profile"       ascii
        $profile5   = "/etc/rc.local"      ascii

        // SSH authorized_keys backdoor
        $ssh_auth   = "authorized_keys"    ascii

        // Execution context
        $exec1      = "subprocess"         ascii
        $exec2      = "os.system("         ascii
        $exec3      = "os.popen("          ascii
        $exec4      = "open("              ascii

    condition:
        any of ($exec*) and
        (
            2 of ($cron*) or
            (2 of ($systemd*) and $systemd3 and $systemd4) or
            (any of ($profile*) and any of ($exec*)) or
            $ssh_auth
        )
}
