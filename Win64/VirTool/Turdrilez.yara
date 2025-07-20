rule VirTool_Win64_Turdrilez_A_2147846429_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Turdrilez.A!MTB"
        threat_id = "2147846429"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Turdrilez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 7c 24 28 45 8b 48 08 4c 89 44 24 20 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d0 8b ce e8 18 ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 ?? ?? ?? e8 ?? ?? ?? ?? 48 ?? ?? ?? e8 ?? ?? ?? ?? 48 8b d0 4b ?? ?? ?? e8 ?? ?? ?? ?? 8b d3 48}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d6 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 8d d0 01 00 00 41 8d ?? ?? ?? ?? ?? ?? 45 8b c6 e8 ?? ?? ?? ?? 45}  //weight: 1, accuracy: Low
        $x_1_4 = {44 8b 85 60 03 00 00 48 ?? ?? ?? ?? 83 64 24 20 00 45 33 c9 48 8b d6 e8 ?? ?? ?? ?? 3b 85 60 03 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

