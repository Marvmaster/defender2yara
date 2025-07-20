rule VirTool_Win64_Shelentesz_A_2147912784_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelentesz.A!MTB"
        threat_id = "2147912784"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelentesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 30 00 00 00 ?? ?? ?? ?? ?? 48 8b 54 24 40 48 8b 8c 24 80 15 00 00 ?? ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 48 8b 44 24 78 48 8b 4c 24 60 48 03 c8 48 8b c1 48 89 44 24 40 83 bc 24 84 00 00 00 40 ?? ?? ?? ?? ?? ?? 81 bc 24 80 00 00 00 00 10 00 00 ?? ?? ?? ?? ?? ?? 81 bc 24 88 00 00 00 00 00 02 00 ?? ?? ?? ?? ?? ?? 4c 8b 44 24 78 48 8b 54 24 60}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 20 4c 8b 4c 24 58 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 54 24 60 48 8b 8c 24 80 15 00 00 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 48 8b 54 24 60 [0-25] 48 8b 0d e2 3f 00 00 ?? ?? ?? ?? ?? ?? 48 89 44 24 48 48 83 7c 24 48 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 94 24 a0 00 00 00 48 8b c8 [0-19] 48 8b c8 ?? ?? ?? ?? ?? ?? 44 8b 44 24 34 33 d2 b9 01 00 00 00 ?? ?? ?? ?? ?? ?? 48 89 44 24 50 48 83 7c 24 50 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

