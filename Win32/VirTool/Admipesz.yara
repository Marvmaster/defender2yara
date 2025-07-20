rule VirTool_Win32_Admipesz_A_2147907212_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Admipesz.A!MTB"
        threat_id = "2147907212"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Admipesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 51 83 ec 44 [0-41] 89 44 24 10 c7 44 24 0c 02 00 00 00 c7 44 24 08 00 00 00 00 8b 45 f4 89 44 24 04 c7 04 24 02 00 00 80 ?? ?? ?? ?? ?? 83 ec 14 89 45 e8 83 7d e8 00 ?? ?? 8b 45 e8 89 44 24 04 c7 04 24 bc 50 40 00 ?? ?? ?? ?? ?? b8 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 ec 89 04 24 ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 e0 89 54 24 14 8b 55 ec 89 54 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 8b 55 f0 89 54 24 04 89 04 24 ?? ?? ?? ?? ?? 83 ec 18 89 45 e4 83 7d e4 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

