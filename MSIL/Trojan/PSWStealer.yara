rule Trojan_MSIL_PSWStealer_XE_2147823558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.XE!MTB"
        threat_id = "2147823558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_2 = "obj\\Debug\\fudloader.pdb" ascii //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "glybzjepapkisf" ascii //weight: 1
        $x_1_7 = "ToString" ascii //weight: 1
        $x_1_8 = "set_PasswordValue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

rule Trojan_MSIL_PSWStealer_ARA_2147836267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.ARA!MTB"
        threat_id = "2147836267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\VertexSpooferFullSRC.pdb" ascii //weight: 2
        $x_2_2 = "://cdn.discordapp.com/attachments/" wide //weight: 2
        $x_2_3 = "/perm_spoofer.zip" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

rule Trojan_MSIL_PSWStealer_MBFZ_2147850548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.MBFZ!MTB"
        threat_id = "2147850548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2b1df0e1ab8b" ascii //weight: 1
        $x_1_2 = "quanlykho.Properties" ascii //weight: 1
        $x_1_3 = "dangnhap" ascii //weight: 1
        $x_1_4 = "formThemnhap" ascii //weight: 1
        $x_1_5 = "frmHuongDan" ascii //weight: 1
        $x_1_6 = "ketnoi" ascii //weight: 1
        $x_1_7 = "Xuathang" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

rule Trojan_MSIL_PSWStealer_AWA_2147919064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.AWA!MTB"
        threat_id = "2147919064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "directoryTempForCopyLoginDataFiles" ascii //weight: 2
        $x_2_2 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_3 = "\\K-Melon\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_4 = "\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_5 = "curl --ssl-no-revoke -X POST \"https://api.telegram.org/bot" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

