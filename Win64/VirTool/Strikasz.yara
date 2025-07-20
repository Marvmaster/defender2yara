rule VirTool_Win64_Strikasz_A_2147904475_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Strikasz.A!MTB"
        threat_id = "2147904475"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Strikasz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 95 80 0b 00 00 48 8b 85 78 0b 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 40 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 38 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 30 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 28 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 20 48 89 c1 ?? ?? ?? ?? ?? 48 8b 85 78 0b 00 00 48 89 c1 ?? ?? ?? ?? ?? 89 c2 48 8b 85 78 0b 00 00 48 89 c1 ?? ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 e0 48 89 c3 48 8b 85 a8 0b 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 c6 dc 00 00 ?? ?? 48 89 85 68 0b 00 00 8b 85 94 0b 00 00 0f b7 c8 48 8b 95 a0 0b 00 00 48 8b 85 68 0b 00 00 48 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 e0 04 00 00 89 c2 48 8b 85 38 0b 00 00 48 89 c1 ?? ?? ?? ?? ?? c7 85 d8 04 00 00 04 00 00 00 8b 85 e0 04 00 00 89 c0 41 b9 40 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 2b d7 00 00 ?? ?? 48 89 85 20 0b 00 00 48 8b 85 20 0b 00 00 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 8b 85 e0 04 00 00 89 c1 48 8b 95 38 0b 00 00 48 8b 85 20 0b 00 00 49 89 c8 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

rule VirTool_Win64_Strikasz_B_2147919482_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Strikasz.B!MTB"
        threat_id = "2147919482"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Strikasz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 95 80 0b 00 00 48 8b 85 78 0b 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 40 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 38 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 30 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 28 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 20 48 89 c1 ?? ?? ?? ?? ?? 48 8b 85 78 0b 00 00 48 89 c1 ?? ?? ?? ?? ?? 89 c2 48 8b 85 78 0b 00 00 48 89 c1 ?? ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 e0 48 89 c3 48 8b 85 a8 0b 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 68 0b 00 00 8b 85 94 0b 00 00 0f b7 c8 48 8b 95 a0 0b 00 00 48 8b 85 68 0b 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 e0 04 00 00 89 c2 48 8b 85 38 0b 00 00 48 89 c1 ?? ?? ?? ?? ?? c7 85 d8 04 00 00 04 00 00 00 8b 85 e0 04 00 00 89 c0 41 b9 40 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 20 0b 00 00 48 8b 85 20 0b 00 00 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 8b 85 e0 04 00 00 89 c1 48 8b 95 38 0b 00 00 48 8b 85 20 0b 00 00 49 89 c8 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 85 e0 04 00 00 89 c1 ?? ?? ?? ?? ?? ?? ?? 48 8b 85 20 0b 00 00 49 89 d1 41 b8 20 00 00 00 48 89 ca 48 89 c1 [0-23] 48 89 c1 ?? ?? ?? ?? ?? 48 8b 95 20 0b 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 28 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 49 89 d0 ba 00 00 00 00 b9 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

