rule Exfiltration_To_Messaging_Webhook
{
    meta:
        description = "Detects data sent out to a hardcoded chat webhook or bot API"
        category = "Exfiltration"
        severity = "Critical"

    strings:

        // Live credentials, matched at full width : )
        $cred_1 = /discord(app)?\.com\/api\/(v\d{1,2}\/)?webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,72}/ nocase
        $cred_2 = /api\.telegram\.org\/bot[0-9]{8,12}:[A-Za-z0-9_-]{35}\// nocase
        $cred_3 = /["'][0-9]{8,12}:[A-Za-z0-9_-]{35}["']/
        $cred_4 = /hooks\.slack\.com\/services\/T[A-Za-z0-9]{7,12}\/B[A-Za-z0-9]{7,12}\/[A-Za-z0-9]{20,28}/

        // Transmission
        $send_1  = /requests\.(post|put)\s*\(/
        $send_2  = /httpx\.(post|put)\s*\(/
        $send_3  = /session\.(post|put)\s*\(/
        $send_4  = /urlopen\s*\(/
        $send_5  = /Invoke-RestMethod/ nocase
        $send_6  = /Invoke-WebRequest[^\r\n]{0,120}-Method\s+P(ost|ut)/ nocase
        $send_7  = /curl[^\r\n]{0,120}-X\s+POST/ nocase
        $send_8  = /curl[^\r\n]{0,120}(-d|--data|--data-binary|-F|--form)\s/
        $send_9  = /fetch\s*\([^\r\n]{0,160}method\s*:\s*["']POST["']/ nocase
        $send_10 = /Upload(String|File|Data|Values)\s*\(/ nocase
        $send_11 = /webhook\.send\s*\(/ nocase
        $send_12 = /DiscordWebhook\s*\(/ nocase
        $send_13 = /http\.client\.HTTPSConnection\s*\(/

    condition:
        any of ($cred_*) and any of ($send_*)
}
