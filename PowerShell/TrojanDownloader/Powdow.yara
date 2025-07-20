rule TrojanDownloader_PowerShell_Powdow_AR_2147753661_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Powdow.AR!MTB"
        threat_id = "2147753661"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 6c 00 69 00 63 00 79 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00 20 00 28 00 4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 27 00 68 00 74 74 00 70 00 3a 00 2f 00 2f 00 32 00 31 00 37 00 2e 00 38 00 2e 00 31 00 31 00 37 00 2e 00 36 00 33 00 2f 00 [0-10] 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 50 6f 77 65 72 53 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 32 31 37 2e 38 2e 31 31 37 2e 36 33 2f [0-10] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_3 = {68 00 74 00 74 70 00 3a 00 2f 00 2f 00 32 00 31 00 37 00 2e 00 38 00 2e 00 31 00 31 00 37 00 2e 00 36 00 33 00 2f 00 [0-10] 2e 00 65 00 78 00 65 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 [0-15] 2e 00 65 00 78 00 65 00 26 00 73 00 74 00 61 00 72 00 74 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 01 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_4 = {68 74 74 70 3a 2f 2f 32 31 37 2e 38 2e 31 31 37 2e 36 33 2f [0-10] 2e 65 78 65 20 25 74 65 6d 70 25 5c [0-15] 2e 65 78 65 26 73 74 61 72 74 20 25 74 65 6d 70 25 5c 01 2e 65 78 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (2 of ($x*))
}

