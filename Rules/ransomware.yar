rule Ransomware {
    meta:
        description = "Detects attempts to delete volume shadow copies & ransom notes"
        category = "Ransomware"
        severity = "Critical"
    strings:
	
        // VSS Deletion
        $vss_1 = "vssadmin" nocase ascii wide
        $vss_2 = "delete shadows" nocase ascii wide
        
        // Extortion keywords
        $ext_1 = "bitcoin" nocase ascii wide
		$ext_2 = "BTC" nocase ascii wide
		$ext_3 = "ransom" nocase ascii wide
        $ext_4 = "ransomware" nocase ascii wide
		
    condition:
	    1 of ($vss_*) or 
        3 of ($ext_*)
}