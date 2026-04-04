rule Ransomware
{
    meta:
        description = "Detects ransomware: VSS deletion combined with execution, or extortion keywords alongside encryption code"
        category    = "Ransomware"
        severity    = "Critical"

    strings:
        // VSS deletion commands (both parts needed together)
        $vss_admin   = "vssadmin"       nocase ascii wide
        $vss_delete  = "delete shadows" nocase ascii wide

        // Extortion / ransom terminology
        $ext_bitcoin   = "bitcoin"    nocase ascii wide
        $ext_btc       = "BTC"              ascii wide
        $ext_ransom    = "ransom"      nocase ascii wide
        $ext_decrypt   = "decrypt"    nocase ascii wide
        $ext_wallet    = "wallet"     nocase ascii wide

        // Actual crypto/file operations that distinguish code from docs
        $crypto_aes   = "AES"         nocase ascii wide
        $crypto_rsa   = "RSA"         nocase ascii wide
        $crypto_fernet = "Fernet"           ascii wide
        $crypto_enc   = /encrypt\s*\(/ nocase ascii wide
        $file_walk    = "os.walk"           ascii
        $file_glob    = "glob.glob"         ascii
        $file_open    = /open\s*\(\s*[^,)]+,\s*["']wb["']/ ascii

        // Exclusion: documentation / research context markers
        $doc_readme   = "README"       nocase ascii wide
        $doc_abstract = "abstract"     nocase ascii wide
        $doc_markdown = /^#{1,3}\s/         ascii  // markdown headings

    condition:
        not (2 of ($doc_*)) and
        (
            // Confirmed ransomware action: VSS deletion with execution context
            ($vss_admin and $vss_delete)
            or
            // Extortion keywords accompanied by real encryption + file iteration
            (
                3 of ($ext_*) and
                any of ($crypto_*) and
                any of ($file_walk, $file_glob, $file_open)
            )
        )
}
