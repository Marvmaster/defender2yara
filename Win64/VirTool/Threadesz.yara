rule VirTool_Win64_Threadesz_A_2147853080_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Threadesz.A!MTB"
        threat_id = "2147853080"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Threadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d5 e8 ?? ?? ?? ?? 4d 8b cc 66 0f 7f 74 24 40 4c ?? ?? ?? ?? 4c ?? ?? ?? ?? 48 8b d3 48 8b ce e8 ?? ?? ?? ?? 48 8b d5 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b f1 66 0f 6f 05 a6 2f 00 00 48 c7 c3 ff ff ff ff f3 0f 7f 45 bf c7 45 d9 48 89 08 48 c7 45 dd 83 ec 40 e8 c7 45 e1 11 00 00 00 c6 45 e5 48 c7 45 ea 5b 41 5a 41 c7 45 ee 59 41 58 5a c7 45 f2 59 58 ff e0 c6 45 f6 90}  //weight: 1, accuracy: High
        $x_1_3 = {4c 8b 45 8f 48 ?? ?? ?? 48 ?? ?? ?? 48 89 44 24 20 4d 8b ce 48 8b ce ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b e8 48 85 c0 0f 84 16 01 00 00 48 89 5c 24 30 89 5c 24 28 89 5c 24 20 45 33 c9 45 33 c0 33 d2 48 8b c8 ff 15 ?? ?? ?? ?? 44 8b f8 85 c0 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

