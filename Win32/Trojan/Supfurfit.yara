rule Trojan_Win32_Supfurfit_A_2147638516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Supfurfit.A"
        threat_id = "2147638516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Supfurfit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VIRUS K\\RandiO" wide //weight: 1
        $x_1_2 = "32\\nukeh.exe" wide //weight: 1
        $x_1_3 = "reg_sz /d www.sistemasonix.esp.st" wide //weight: 1
        $x_1_4 = "vampiro_caifanes/nukep.htm" wide //weight: 1
        $x_1_5 = "ftp -s:c:\\windows\\transfer.txt ftp.webcindario.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (4 of ($x*))
}

