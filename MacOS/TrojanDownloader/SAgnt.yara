rule TrojanDownloader_MacOS_SAgnt_B_2147840760_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/SAgnt.B!MTB"
        threat_id = "2147840760"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 cc 48 89 55 98 48 89 4d ?? e8 ?? ?? ff ff 41 b8 ?? 00 00 00 44 89 c6 48 89 05 ?? ?? 00 00 48 89 15 ?? ?? 00 00 48 8d 3d ?? ?? 00 00 ba 01 00 00 00 e8 ?? ?? 00 00 41 b8 0c 00 00 00 44 89 c6 48 8d 3d ?? ?? 00 00 41 b8 01 00 00 00 48 89 55 88 44 89 c2 48 89 45 80 e8 ?? ?? 00 00 48 89 45 d8 48 89 55 e0 48 8d 45 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "=u?naidraug/" ascii //weight: 1
        $x_1_3 = "hsab/nib/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        ((uint32(0) == 0xfeedfacf) or (uint32(0) == 0xcffaedfe) or (uint32(0) == 0xfeedface) or (uint32(0) == 0xcefaedfe)) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_SAgnt_C_2147852953_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/SAgnt.C!MTB"
        threat_id = "2147852953"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 60 30 50 10 50 20 10 20 20 10 40 20 30 20 10 50 20 20 30 30 20 10 40 20 30 50 40 30 40 d0 07 b0 03 d0 03 70 80 04 d0 07 80 04 c0 03 d0 03 c0 03 b0 03 d0 03 b0 03 c0 03 c0 03 e0 3a a0 03 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        ((uint32(0) == 0xfeedfacf) or (uint32(0) == 0xcffaedfe) or (uint32(0) == 0xfeedface) or (uint32(0) == 0xcefaedfe)) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_SAgnt_AK_2147899666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/SAgnt.AK!MTB"
        threat_id = "2147899666"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 05 0b 54 00 00 48 89 e1 48 89 01 c7 41 20 01 00 00 00 48 c7 41 18 e6 33 00 00 c7 41 10 02 00 00 00 48 c7 41 08 a9 00 00 00 48 8d 3d da 52 00 00 48 8d 0d 99 53 00 00 ba 0b 00 00 00 89 d6 ba 36 00 00 00 41 89 d0 ba 02 00 00 00 89 95 34 fe ff ff 44 8b 8d 34 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 05 a7 54 00 00 48 89 e1 48 89 01 c7 41 20 01 00 00 00 48 c7 41 18 e1 33 00 00 c7 41 10 02 00 00 00 48 c7 41 08 a9 00 00 00 48 8d 3d 76 53 00 00 48 8d 0d 25 55 00 00 ba 0b 00 00 00 89 d6 ba 27 00 00 00 41 89 d0 ba 02 00 00 00 89 95 44 fe ff ff 44 8b 8d 44 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        ((uint32(0) == 0xfeedfacf) or (uint32(0) == 0xcffaedfe) or (uint32(0) == 0xfeedface) or (uint32(0) == 0xcefaedfe)) and
        (1 of ($x*))
}

