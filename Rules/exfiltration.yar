rule Data_Exfiltration_Python
{
    meta:
        description = "Detects Python data exfiltration: sensitive file collection + upload channel"
        category    = "Exfiltration"
        severity    = "High"

    strings:
        // File discovery
        $glob       = "glob.glob"          ascii
        $walk       = "os.walk"            ascii
        $listdir    = "os.listdir"         ascii

        // Sensitive file targets
        $tgt_ssh1   = ".ssh"               ascii
        $tgt_ssh2   = "id_rsa"             ascii
        $tgt_passwd = "/etc/passwd"        ascii
        $tgt_shadow = "/etc/shadow"        ascii
        $tgt_creds  = "credentials"  nocase ascii
        $tgt_aws    = ".aws"               ascii
        $tgt_env    = ".env"               ascii
        $tgt_wallet = "wallet"       nocase ascii
        $tgt_chrome = "chrome"       nocase ascii
        $tgt_cookie = "cookies"      nocase ascii
        $tgt_key    = "private_key"  nocase ascii

        // Exfiltration channels
        $exfil_post  = "requests.post"     ascii
        $exfil_smtp  = "smtplib"           ascii
        $exfil_ftp   = "ftplib"            ascii
        $exfil_disc  = "discord.com/api/webhooks" ascii
        $exfil_tg    = "api.telegram.org"  ascii
        $exfil_dns   = "dns.resolver"      ascii

        // Archive before sending
        $zip        = "zipfile"            ascii
        $tar        = "tarfile"            ascii

    condition:
        any of ($glob, $walk, $listdir) and
        3 of ($tgt_*) and
        any of ($exfil_*) and
        any of ($zip, $tar)
}


rule Credential_Harvesting
{
    meta:
        description = "Detects credential harvesting from browsers, SSH keys, and system stores"
        category    = "Exfiltration"
        severity    = "High"

    strings:
        // Browser credential paths
        $chrome_path  = "Google/Chrome"         nocase ascii wide
        $firefox_path = "Mozilla/Firefox"        nocase ascii wide
        $edge_path    = "Microsoft/Edge"         nocase ascii wide
        $login_data   = "Login Data"                   ascii wide
        $cookies_db   = "Cookies"                      ascii wide

        // SSH key harvesting
        $ssh_dir      = ".ssh/"                        ascii
        $id_rsa       = "id_rsa"                       ascii
        $id_ed        = "id_ed25519"                   ascii

        // Windows credential APIs
        $cred_api1    = "CryptUnprotectData"           ascii wide
        $cred_api2    = "DPAPI"                        ascii wide
        $cred_api3    = "win32crypt"                   ascii

        // SQLite-based credential reading
        $sqlite_conn  = "sqlite3.connect"              ascii
        $select_creds = /SELECT.*password.*FROM/       nocase ascii

        // Exfiltration
        $send1        = "requests.post"                ascii
        $send2        = "smtplib"                      ascii
        $send3        = "discord.com/api/webhooks"     ascii

    condition:
        (
            (any of ($chrome_path, $firefox_path, $edge_path) and any of ($login_data, $cookies_db)) or
            (any of ($ssh_dir, $id_rsa, $id_ed)) or
            (any of ($cred_api*)) or
            ($sqlite_conn and $select_creds)
        ) and
        any of ($send*)
}
