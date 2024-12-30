rule Trojan_Win32_KillWin_ARAZ_2147928399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillWin.ARAZ!MTB"
        threat_id = "2147928399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 f0 8b 04 b2 46 89 04 24 e8 81 4a 00 00 01 c7 39 de 7c eb}  //weight: 2, accuracy: High
        $x_2_2 = "\\B2E.tmp" ascii //weight: 2
        $x_1_3 = "AddAtomA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillWin_NH_2147929306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillWin.NH!MTB"
        threat_id = "2147929306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c7 04 24 88 13 00 00 a1 dc 62 48 00 ff d0 83 ec 04 c7 04 24 d4 da 47 00 e8 c3 f9 00 00 b8 00 00 00 00 8b 4d fc}  //weight: 3, accuracy: High
        $x_1_2 = "vssadmin delete Shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "del %homedrive%\\NTDETECT.COM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

