rule Ransom_MSIL_PadCrypt_A_2147774319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/PadCrypt.A"
        threat_id = "2147774319"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PadCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PadCrypt 3.0.exe" ascii //weight: 1
        $x_1_2 = "$5a71b358-f025-48f8-9fae-8222ee4ad194" ascii //weight: 1
        $x_1_3 = "_Encrypted$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

