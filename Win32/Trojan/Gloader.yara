rule Trojan_Win32_Gloader_2147814299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gloader"
        threat_id = "2147814299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_2 = "report_error.php?key=" ascii //weight: 1
        $x_1_3 = "621234491d587.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (2 of ($x*))
}

