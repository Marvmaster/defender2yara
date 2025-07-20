rule VirTool_Win64_Explinjesz_A_2147922945_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Explinjesz.A!MTB"
        threat_id = "2147922945"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Explinjesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 70 c7 45 dc 00 00 00 00 ?? ?? ?? ?? ?? 89 45 fc 83 7d fc 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 0d 46 2d 00 00 ?? ?? ?? ?? ?? b8 01 00 00 00 ?? ?? ?? ?? ?? 8b 45 fc 41 89 c0 ba 00 00 00 00 b9 ff 0f 1f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 f0 48 83 7d f0 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 0d 05 2d 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c1 e8 ?? ?? ?? ?? b8 01 00 00 00 ?? ?? ?? ?? ?? 8b 05 58 19 00 00 89 c2 48 8b 45 f0 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 49 89 d0 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 e8 8b 05 26 19 00 00 89 c1 48 8b 55 e8 48 8b 45 f0 48 c7 44 24 20 00 00 00 00 49 89 c9 ?? ?? ?? ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 55 e8 48 8b 4d f0 ?? ?? ?? ?? 48 89 44 24 38 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 49 89 d1 41 b8 00 00 00 00 ba 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 e0 48 83 7d e0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

