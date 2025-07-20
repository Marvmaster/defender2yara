rule VirTool_Win64_Rempatch_A_2147912620_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rempatch.A!MTB"
        threat_id = "2147912620"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rempatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 0d 03 19 00 00 ?? ?? ?? ?? ?? 40 84 ff [0-25] 48 8b c8 [0-19] 48 8b d8 c7 45 1f ?? ?? ?? ?? c7 45 23 ?? ?? ?? ?? c7 45 27 ?? ?? ?? ?? c6 45 2b ?? 89 75 e7 48 c7 45 f7 ?? ?? ?? ?? 48 89 45 df}  //weight: 1, accuracy: Low
        $x_1_2 = {80 7d d8 00 [0-19] 48 8b c8 [0-19] 48 8b d8 66 c7 45 e7 ?? ?? c6 45 e9 ?? 89 75 df 48 c7 45 f7 ?? ?? ?? ?? 48 89 45 1f ?? ?? ?? ?? 48 89 44 24 20 41 b9 04 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 49 8b cf ?? ?? ?? ?? ?? 48 89 74 24 20 41 b9 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {80 7d ef 00 [0-25] 48 8b c8 [0-19] 48 8b d8 c6 45 ef ?? 89 75 e7 48 c7 45 df ?? ?? ?? ?? 48 89 45 f7 ?? ?? ?? ?? 48 89 44 24 20 41 b9 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b d8 c7 44 24 28 ?? ?? ?? ?? c7 44 24 20 ?? ?? ?? ?? ?? ?? ?? ?? 45 33 c0 ?? ?? ?? ?? 49 8b cf ?? ?? ?? ?? ?? 48 89 74 24 20 [0-17] 48 8b 55 df 49 8b cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

