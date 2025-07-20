rule Trojan_Win32_Maganpy_A_2147709394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maganpy.A!bit"
        threat_id = "2147709394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maganpy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.dll" ascii //weight: 1
        $x_1_2 = "taskkill /F /IM %s /T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

