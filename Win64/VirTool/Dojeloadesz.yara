rule VirTool_Win64_Dojeloadesz_A_2147917408_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dojeloadesz.A!MTB"
        threat_id = "2147917408"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dojeloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b f1 8b d1 [0-18] 8b 15 13 69 00 00 ?? ?? ?? ?? ?? ?? ?? 4c 8b 0d 0d 69 00 00 44 8b c2 ?? ?? ?? ?? ?? 8b 3d f7 68 00 00 48 8b 15 f8 68 00 00 44 8b c7 48 8b 0d fe 68 00 00 ?? ?? ?? ?? ?? 48 8b 15 f2 68 00 00 ?? ?? ?? ?? ?? ?? ?? 44 8b c7 ?? ?? ?? ?? ?? 8b 05 c5 68 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {40 56 48 83 ec 40 48 8b 05 63 5a 00 00 48 33 c4 48 89 44 24 28 8b f1 8b d1 [0-18] 44 8b 05 24 64 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 15 0e 64 00 00 ?? ?? ?? ?? ?? 8b 15 0b 64 00 00 ?? ?? ?? ?? ?? 48 8b 0d f7 63 00 00 41 b8 04 00 00 00 ?? ?? ?? ?? ?? ?? 85 c0 [0-33] 44 8b 05 d6 63 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {57 48 83 ec 20 8b f1 8b d1 [0-18] 48 8b 7c 24 28 ?? ?? ?? ?? ?? ?? ?? 48 8b d7 ?? ?? ?? ?? ?? 4c 8b 0d 0b 66 00 00 ?? ?? ?? ?? ?? ?? ?? 8b 15 26 66 00 00 44 8b c2 4d 8b 09 ?? ?? ?? ?? ?? 48 8b 0d 2c 66 00 00 48 85 c9}  //weight: 1, accuracy: Low
        $x_1_4 = {33 d2 8b ce [0-24] 48 8b 05 31 65 00 00 48 8b 08 48 89 0d 2f 65 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b d3 [0-18] 8b 15 33 65 00 00 41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b cb ?? ?? ?? ?? ?? ?? 48 8b 0d ef 64 00 00 48 89 01 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

