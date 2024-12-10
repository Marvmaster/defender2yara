rule Trojan_Win64_KeyLogger_DB_2147828897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KeyLogger.DB!MTB"
        threat_id = "2147828897"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {f6 54 0d b0 48 ff c1 48 83 f9 1b 72 f3 4c 8d 45 b0}  //weight: 3, accuracy: High
        $x_2_2 = {0f b7 01 41 b9 ff ff 00 00 66 f7 d0 66 41 89 04 08 0f b7 01 48 8d 49 02 66 44 3b c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KeyLogger_NK_2147927972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KeyLogger.NK!MTB"
        threat_id = "2147927972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Windows Atapi x86_64 Driver" ascii //weight: 2
        $x_2_2 = "hacks.txt" wide //weight: 2
        $x_1_3 = "Chave aberta com sucesso" ascii //weight: 1
        $x_1_4 = "Erro ao obter o nome do usu" ascii //weight: 1
        $x_1_5 = "InternetConnectW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

