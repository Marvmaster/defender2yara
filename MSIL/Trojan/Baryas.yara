rule Trojan_MSIL_Baryas_MBR_2147933459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Baryas.MBR!MTB"
        threat_id = "2147933459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Baryas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 11 36 20 d1 01 00 00 95 5f 11 36 20 9b 0f 00 00 95 61 58 81 0b 00 00 01 11 28 16 9a 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

