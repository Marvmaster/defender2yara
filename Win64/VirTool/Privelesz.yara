rule VirTool_Win64_Privelesz_A_2147921773_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Privelesz.A!MTB"
        threat_id = "2147921773"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Privelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 57 48 83 ec 70 [0-37] 48 89 44 24 30 ?? ?? ?? ?? ?? ?? ?? 48 8b 4c 24 30 ?? ?? ?? ?? ?? ?? 48 89 05 23 f9 08 00 [0-19] ba ff 01 0f 00 48 8b c8 ?? ?? ?? ?? ?? ?? 48 8b 0d 89 19 09 00 ?? ?? ?? ?? ?? 48 89 05 1d f9 08 00 8b 05 4f e7 08 00 41 b9 04 00 00 00 41 b8 00 10 00 00 8b d0 33 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c1 48 89 05 2d f8 08 00 48 c7 44 24 50 ff ff ff ff [0-18] 89 44 24 58 ?? ?? ?? ?? ?? ?? 89 44 24 5c 33 c0 83 f8 01 ?? ?? ?? ?? ?? ?? 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 ?? ?? ?? ?? ?? ?? ?? 33 d2 33 c9 ?? ?? ?? ?? ?? ?? 48 89 44 24 60 ba 0f 00 00 00 48 8b 4c 24 60 ?? ?? ?? ?? ?? ?? c7 44 24 68 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b c0 33 d2 b9 40 00 10 00 ?? ?? ?? ?? ?? ?? 48 89 44 24 40 48 83 7c 24 40 00 ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 41 b9 ff ff ff ff 4c 8b 44 24 40 48 8b 15 76 82 09 00 48 8b 4c 24 38 ?? ?? ?? ?? 4c 8b 44 24 40 48 8b 54 24 38 48 8b 0d a4 82 09 00 ?? ?? ?? ?? ?? ?? 48 c7 44 24 20 00 80 00 00 45 33 c9 4c 8b 44 24 60 ?? ?? ?? ?? ?? ?? ?? 48 8b 4c 24 38 ?? ?? ?? ?? 48 8b 4c 24 38}  //weight: 1, accuracy: Low
        $x_1_4 = {ba ff ff ff ff 48 8b 4c 24 60 ?? ?? ?? ?? ?? ?? 44 8b 44 24 58 33 d2 b9 ff ff 1f 00 ?? ?? ?? ?? ?? ?? 48 89 44 24 50 48 83 7c 24 50 00 [0-16] 89 44 24 6c 8b 44 24 5c 8b 4c 24 6c 2b c8 8b c1 3d e0 93 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

