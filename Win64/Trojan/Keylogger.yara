rule Trojan_Win64_Keylogger_BH_2147844444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.BH!MTB"
        threat_id = "2147844444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[BACKSPACE]" ascii //weight: 1
        $x_1_2 = "[ENTER]" ascii //weight: 1
        $x_1_3 = "[PG UP]" ascii //weight: 1
        $x_1_4 = "[PG DN]" ascii //weight: 1
        $x_1_5 = "[HOME]" ascii //weight: 1
        $x_1_6 = "[RIGHT]" ascii //weight: 1
        $x_1_7 = "[DOWN]" ascii //weight: 1
        $x_1_8 = "[PRINT]" ascii //weight: 1
        $x_1_9 = "[PRT SC]" ascii //weight: 1
        $x_1_10 = "[INSERT]" ascii //weight: 1
        $x_1_11 = "[DELETE]" ascii //weight: 1
        $x_1_12 = "[WIN KEY]" ascii //weight: 1
        $x_1_13 = "[CTRL]" ascii //weight: 1
        $x_1_14 = "Hook procedure has been installed successfully" ascii //weight: 1
        $x_1_15 = "Keylogger is up and running" ascii //weight: 1
        $x_1_16 = "Cannot uninstall the hook procedure" ascii //weight: 1
        $x_1_17 = "Hook procedure has been uninstalled successfully" ascii //weight: 1
        $x_1_18 = "Downloads\\mals\\winkl\\keylogger\\src\\Keylogger\\x64\\Release\\Keylogger.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

rule Trojan_Win64_Keylogger_RR_2147895939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.RR!MTB"
        threat_id = "2147895939"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AFDK\\AFDK\\x64\\Release\\AFDK.pdb" ascii //weight: 2
        $x_1_2 = "3301Kira" ascii //weight: 1
        $x_5_3 = "Software\\def9b6cd3f2b0c43097dfbc918862b82" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

rule Trojan_Win64_Keylogger_RB_2147896980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogger.RB!MTB"
        threat_id = "2147896980"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "3301Kira" ascii //weight: 5
        $x_5_2 = "Software\\def9b6cd3f2b0c43097dfbc918862b82" wide //weight: 5
        $x_1_3 = "keylogger save OK" wide //weight: 1
        $x_1_4 = "Keylogger is up and running" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

