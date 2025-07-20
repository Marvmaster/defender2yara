rule TrojanDownloader_Win32_Zlug_A_2147620378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlug.A"
        threat_id = "2147620378"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 5b be ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 75 16 6a 63 56 68 85 19 00 00 e8 ?? ?? ?? ?? 83 c4 0c 89 1d ?? ?? ?? ?? 56 8d 4d d4 e8 ?? ?? ?? ?? 6a 07 89 7d fc 8b 3d ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 ff d7 83 c4 0c 85 c0 74 26 6a 06 68 ?? ?? ?? ?? 56 ff d7 83 c4 0c 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 8d d0 fe ff ff 51 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 84 c0 74 34 8d 85 d0 fe ff ff 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 59 85 c0 59 74 1c 66 a1 ?? ?? ?? ?? 50 8d 85 d0 fe ff ff 50 e8 ?? ?? ?? ?? 59 3b c6 59 89 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

