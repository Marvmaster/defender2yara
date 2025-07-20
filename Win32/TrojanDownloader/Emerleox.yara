rule TrojanDownloader_Win32_Emerleox_A_2147597610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Emerleox.gen!A"
        threat_id = "2147597610"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Emerleox"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "endEmail Unit By Anskya" ascii //weight: 2
        $x_1_2 = "#32770" ascii //weight: 1
        $x_2_3 = {20 20 a6 a6 2d 2b 51 51}  //weight: 2, accuracy: High
        $x_2_4 = "SetWindowsHookExA" ascii //weight: 2
        $x_2_5 = "MsHx.dll" ascii //weight: 2
        $x_9_6 = {64 ff 30 64 89 20 a1 ?? ?? ?? 00 c6 00 00 8d 85 ?? ?? ff ff e8 ?? ?? ?? 00 8d 85 ?? ?? ff ff ba ?? ?? ?? 00 e8 ?? ?? ff ff 8b 95 ?? ?? ff ff 8d 85 ?? ?? ff ff e8 ?? ?? ff ff ba 01 00 00 00 8d 85 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff 8d 85 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff 8b d0 83 ea 13 8d 85 ?? ?? ff ff}  //weight: 9, accuracy: Low
        $x_4_7 = {50 6a 02 e8 ?? ?? ff ff 8b 15 ?? ?? ?? 00 89 02 6a 00 a1 ?? ?? ?? 00 50 b8 ?? ?? ?? 00 50 6a 07 e8 ?? ?? ff ff 8b 15 ?? ?? ?? 00 89 02 6a 00 a1 ?? ?? ?? 00 50 b8 ?? ?? ?? 00 50 6a 04 e8 ?? ?? ff ff 8b 15 ?? ?? ?? 00 89 02}  //weight: 4, accuracy: Low
        $x_5_8 = {53 56 33 db 6a 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff 8b f0 68 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 00 56 e8 ?? ?? ff ff 85 c0 74 2e 68 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 00 56 e8 ?? ?? ff ff 85 c0 74 18 68 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 00 56 e8 ?? ?? ff ff 85 c0 74 02 b3 01 8b c3 5e 5b}  //weight: 5, accuracy: Low
        $x_5_9 = {83 fe 0d 0f 85 ?? ?? 00 00 8b c3 c1 e8 1f a8 01 0f 85 ?? ?? 00 00 e8 ?? ?? ff ff 84 c0 0f 84 ?? ?? 00 00 b8 ?? ?? ?? 00 e8 ?? ?? ff ff b8 ?? ?? ?? 00 e8 ?? ?? ff ff b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8d 45 f8 e8 ?? ?? ff ff 8b 55 f8 b8 ?? ?? ?? 00 e8 ?? ?? ff ff b8 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 e8 f2 d2 ff ff 8b 15 ?? ?? ?? 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((2 of ($x_5_*))) or
            ((1 of ($x_9_*))) or
            (all of ($x*))
        )
}

