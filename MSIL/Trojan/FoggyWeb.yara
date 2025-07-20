rule Trojan_MSIL_FoggyWeb_A_2147794647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FoggyWeb.A!dha"
        threat_id = "2147794647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FoggyWeb"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 47 06 07 06 8e 69 5d 91 61 d2 52 06 07 06 8e 69 5d 06 07 06 8e 69 ?? 91 17 62 06 07 06 8e 69 5d 91 1d 63 60 d2 9c 07 17 58 0b 07 02 8e 69}  //weight: 2, accuracy: Low
        $x_2_2 = {25 16 05 a2 2b 01 14 0a 02 17 91 1f 5a 33 12 02 16 91 1f 4d 33 0b 02 03 04 06 28 12 ?? ?? ?? 2b 13 28 27 ?? ?? ?? 02 6f 28 ?? ?? ?? 03 04 06 28 11 ?? ?? ?? de 03}  //weight: 2, accuracy: Low
        $x_2_3 = {19 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 77 00 65 00 62 00 70 00 00 1f ?? 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2e 00 77 00 65 00 62 00 70 00 00 13 ?? 00 6f 00 67 00 6f 00 2e 00 77 00 65 00 62 00 70 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {07 47 00 45 00 54 00 00 45 2f 00 61 00 64 00 66 00 73 00 2f 00 70 00 6f 00 72 00 ?? 00 61 00 6c 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 74 00 68 00 65 00 6d 00 65 00 2f 00 6c 00 69 00 ?? 00 68 00 74 00 30 00 31 00 2f 00 00}  //weight: 2, accuracy: Low
        $x_2_5 = {09 50 00 4f 00 53 00 54 00 00 55 2f 00 61 00 64 00 66 00 73 00 2f 00 73 00 ?? 00 72 00 76 00 69 00 63 00 65 00 73 00 2f 00 74 00 72 00 75 00 73 00 74 00 2f 00 32 00 30 00 30 00 35 00 ?? 00 73 00 61 00 6d 00 6c 00 6d 00 69 00 78 00 65 00 64 00 2f 00 75 ?? 70 00 6c 00 6f 00 61 00 64 00 00}  //weight: 2, accuracy: Low
        $x_2_6 = {47 65 74 41 73 73 65 6d 62 6c 79 42 79 4e 61 6d 65 00 41 73 73 65 6d 62 6c 79 4e 61 ?? 65 00 6e 61 6d 65 00 47 65 74 46 72 61 6d 65 00 45 78 65 63 75 74 65 41 73 73 65 6d 62 6c 79 52 6f 75 74 69 6e ?? 00 63 65 72 74 69 66 69 63 61 74 65 54 79 70 65}  //weight: 2, accuracy: Low
        $x_1_7 = {4f 3c 00 58 00 35 00 30 00 39 00 43 00 65 00 72 00 74 00 ?? 00 66 00 69 00 63 00 61 00 74 00 65 00 3e 00 28 00 2e 00 2a 00 29 00 ?? 00 2f 00 58 00 35 00 30 00 39 00 43 00 65 00 72 00 74 00 69 00 66 00 69 ?? 63 00 61 00 74 00 65 00 3e 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {4b 3c 00 53 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 ?? 00 56 00 61 00 6c 00 75 00 65 00 3e 00 28 00 2e 00 2a 00 29 00 3c 00 2f 00 53 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 56 00 ?? 00 6c 00 75 00 65 00 3e 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

