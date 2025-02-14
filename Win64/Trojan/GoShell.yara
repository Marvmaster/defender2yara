rule Trojan_Win64_GoShell_GZX_2147907551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoShell.GZX!MTB"
        threat_id = "2147907551"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 58 30 01 02 58 31 01 02 44 6f 01 02 58 32 01 02 58 33 01 02 50 43 00 02 73 70 00 02 70}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoShell_GA_2147933441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoShell.GA!MTB"
        threat_id = "2147933441"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 0f 57 ff 4c 8b 35 fd 78 5f 00 65 4d 8b 36 4d 8b 36 48 8b 44 24 60 48 89 c1 48 39 44 24 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

