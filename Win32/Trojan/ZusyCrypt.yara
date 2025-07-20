rule Trojan_Win32_ZusyCrypt_LKA_2147896774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZusyCrypt.LKA!MTB"
        threat_id = "2147896774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZusyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "windows\\cache\\mgr.vbs" ascii //weight: 1
        $x_1_2 = "ftp.forest-fire.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

