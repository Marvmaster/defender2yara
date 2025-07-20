rule TrojanDownloader_Win32_Secdow_A_2147600888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Secdow.A"
        threat_id = "2147600888"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Secdow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SEC Downloader" ascii //weight: 10
        $x_2_2 = "svchost.exe" ascii //weight: 2
        $x_2_3 = "c:\\sec.exe" ascii //weight: 2
        $x_2_4 = "URLDownloadToFileA" ascii //weight: 2
        $x_2_5 = "virus.scr" ascii //weight: 2
        $x_2_6 = "c:\\virus.exe" ascii //weight: 2
        $x_5_7 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? 00 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

