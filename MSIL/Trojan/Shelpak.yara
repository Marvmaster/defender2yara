rule Trojan_MSIL_Shelpak_MBEZ_2147849735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelpak.MBEZ!MTB"
        threat_id = "2147849735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 50 c3 00 00 73 ?? 01 00 0a 0c 07 08 07 6f ?? 01 00 0a 1e 5b 6f ?? 01 00 0a 6f ?? 01 00 0a 00 07 08 07 6f ?? 01 00 0a 1e 5b 6f ?? 01 00 0a 6f ?? 01 00 0a 00 07 1a}  //weight: 1, accuracy: Low
        $x_1_2 = {20 50 c3 00 00 73 ?? 01 00 0a 13 04 09 11 04 09 6f ?? 01 00 0a 1e 5b 6f ?? 01 00 0a 6f ?? 01 00 0a 00 09 11 04 09 6f ?? 01 00 0a 1e 5b}  //weight: 1, accuracy: Low
        $x_10_3 = "9874-e0d385ff3431" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Shelpak_ASE_2147851560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelpak.ASE!MTB"
        threat_id = "2147851560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 0a 16 0b 2b 18 06 07 9a 28 01 00 00 06 0c 12 02 28 10 00 00 0a 2c 02 17 2a 07 17 58 0b 07 06 8e 69 32 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

