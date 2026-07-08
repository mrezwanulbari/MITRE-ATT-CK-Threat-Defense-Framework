rule Ransomware_Generic_Activity
{
    meta:
        description = "Generic ransomware behavior detection"
        author = "Shakil Md. Rezwanul Bari"
        reference = "MITRE ATT&CK T1486"

    strings:
        $encrypt1 = "AES" nocase
        $encrypt2 = "RSA" nocase
        $shadow = "vssadmin delete shadows" nocase
        $ext = ".locked" nocase

    condition:
        any of ($encrypt*) or $shadow or $ext
}
