rule Trojan_MSIL_OceanMap_A_2147767197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OceanMap.A!dha"
        threat_id = "2147767197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OceanMap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 ?? 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 69 00 6d 00 61 00 70 00 5f 00 63 00 68 00 61 00 6e 00 65 00 6c 00 2e 00 65 00 ?? 00 65 00 00 00 2a 00 05 00 01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 ?? 00 00 00 00 00 69 00 6d 00 61 00 70 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 57 4f ?? 4b 5c 53 6f 75 72 63 65 5c 69 6d 61 70 ?? 63 68 61 6e 65 6c 5c 69 6d 61 70 5f 63 68 61 6e 65 6c 5c 6f 62 6a 5c 52 65 6c 65 ?? 73 65 5c 69 6d 61 70 5f 63 68 61 6e 65 6c ?? 70 64 62 00}  //weight: 1, accuracy: Low
        $x_1_3 = {df 6d 00 6f 00 76 00 65 00 20 00 2f 00 59 00 20 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 22 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 25 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 25 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 65 00 78 00 65 00 22 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {24 00 20 00 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 00 2d 24 00 20 00 ?? 00 49 00 44 00 20 00 53 00 45 00 41 00 52 00 43 00 48 00 20 00 73 00 75 00 ?? 00 6a 00 65 00 63 00 74 00 20 00 22 00 00 07 22 00 0d 00 0a 00 00 1b 28 00 6e 00 ?? 00 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 73 00 29}  //weight: 1, accuracy: Low
        $x_1_5 = {24 00 20 00 55 00 49 00 ?? 00 20 00 46 00 45 00 54 00 43 00 48 00 20 00 00 25 20 00 42 00 4f 00 44 00 ?? 00 2e 00 50 00 45 00 45 00 4b 00 5b 00 74 00 65 00 78 00 74 00 5d 00 0d 00 0a 00 00 0d 46 00 72 00 6f 00 6d 00 ?? 00 20 00 00 17 0d 00 0a 00 53 00 75 00 62 00 6a 00 65 00 63 00 74 00 3a 00 20 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5f 00 72 00 65 00 70 00 6f 00 72 00 74 00 ?? 00 00 09 0d 00 0a 00 0d 00 0a 00 00 21 24 00 20 00 41 00 50 00 ?? 00 45 00 4e 00 44 00 20 00 49 00 6e 00 62 00 6f 00 78 00 20 00 7b 00 00 07 7d 00 0d 00 0a 00 00 0f ?? 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 0f 20 00 20 00 45 00 72 00 72 00 6f 00 72 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {8c 18 63 4c 63 ?? ce 4e 75 f1 55 f8 06 80 8f 05 32 fe f8 a8 47 2d b2 54 33 ?? ?? a4 8c b6 9b 7c b1 43 bc e1 39 ?? 9d 33 c2 09 22 01 70 f0 d9 8f de}  //weight: 1, accuracy: Low
        $x_1_8 = {4f 00 4b 00 00 19 ?? 00 20 00 55 00 49 00 44 00 20 00 53 00 54 00 4f 00 52 00 45 00 20 00 00 29 20 00 2b 00 ?? 00 4c 00 41 00 47 00 53 00 20 00 28 00 5c 00 44 00 65 00 6c 00 65 00 74 00 65 00 64 00 29 00 0d 00 0a 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (1 of ($x*))
}

rule Trojan_MSIL_OceanMap_B_2147767954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OceanMap.B!dha"
        threat_id = "2147767954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OceanMap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 ?? 00 61 00 6d 00 65 00 00 00 69 00 67 00 6d 00 74 00 53 00 58 00 2e 00 65 00 78 00 65 00 00 00 50 00 72 00 6f 00 64 00 75 00 ?? 00 74 00 4e 00 61 00 6d 00 65 00 00 00 69 00 67 00 6d 00 74 00 53 00 58 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 44 65 63 72 79 ?? 74 6f 72 00 43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 00 53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 00 72 5f ?? 72 65 64 73 00 63 6f 6d 6d 61 6e 64 73}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6f 6d 70 5f 69 64 20 ?? 6d 64 20 52 65 61 64 54 6f 45 6e 64 20 63 6f 6d 6d 61 6e 64 20 70 61 ?? 73 77 6f 72 64 20 73 78 64}  //weight: 1, accuracy: Low
        $x_1_4 = {24 34 61 30 33 32 62 30 64 2d 37 31 31 62 2d 34 66 61 36 2d ?? 35 37 64 2d 37 35 35 30 32 63 37 66 63 64 66 35 00}  //weight: 1, accuracy: Low
        $x_1_5 = {0f 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 0f 20 00 20 00 45 00 ?? 00 72 00 6f 00 72 00 00 0d 44 00 72 00 61 00 66 00 74 00 73 00 00 19 49 00 4e 00 42 00 4f 00 58 00 2e 00 44 00 ?? 00 61 00 66 00 74 00 73 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {28 00 6e 00 6f 00 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 ?? 00 29 00 00 0f 53 00 45 00 41 00 52 00 43 00 48 00 41 00 00 19 24 00 20 00 55 00 49 00 44 00 20 00 46 00 45 00 54 00 43 00 48 00 20 00 00 25 20 00 42 00 4f 00 44 00 59 00 2e 00 ?? 00 45 00 45 00 4b 00 5b 00 74 00 65 00 78 00 74 00 5d 00 0d 00 0a 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {48 00 62 00 71 00 43 00 39 00 ?? 00 6d 00 56 00 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {30 43 36 46 30 35 33 35 33 34 38 31 ?? 33 45 45 37 39 32 32 36 43 45 34 39 34 30 45 39 45 33 38 34 44 38 36 45 30 30 46 42 34 42 44 33 45 ?? 36 38 45 46 41 35 30 43 36 36 44 31 42 30 44 34 42}  //weight: 1, accuracy: Low
        $x_1_9 = {10 46 00 72 00 6f 00 6d 00 3a 00 20 00 6e 00 5f 00 00 1a 53 00 75 00 62 00 6a 00 ?? 00 63 00 74 00 3a 00 20 00 61 00 5f 00 5f 00 5f 00 00 10 5f 00 72 00 65 00 70 00 6f 00 ?? 00 74 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_10 = {13 24 00 20 00 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 00 09 ?? 00 20 00 4e 00 4f 00 00 05 6e 00 6f 00 00 2d 24 00 20 00 55 00 49 00 44 00 20 00 53 00 45 00 41 00 52 00 43 00 48 00 ?? 00 73 00 75 00 62 00 6a 00 65 00 63 00 74 00 20 00 22 00 00}  //weight: 1, accuracy: Low
        $x_1_11 = {6d 00 6f 00 76 00 65 00 20 00 2f 00 59 00 20 00 69 00 67 00 6d 00 ?? 00 53 00 58 00 2e 00 65 00 78 00 65 00 20 00 22 00 [0-176] 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 69 00 67 00 6d 00 74 00 ?? 00 58 00 2e 00 65 00 78 00 65 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (1 of ($x*))
}

rule Trojan_MSIL_OceanMap_AOC_2147901979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OceanMap.AOC!MTB"
        threat_id = "2147901979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OceanMap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 13 04 2b 38 09 11 04 9a 13 05 11 05 72 ?? 00 00 70 6f ?? 00 00 0a 2d 1e 08 11 05 17 8d ?? 00 00 01 25 16 1f 29 9d 6f ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 0c 11 04 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

