rule Trojan_Win32_marte_RDA_2147847773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/marte.RDA!MTB"
        threat_id = "2147847773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qoidaofadefghdasuhg" ascii //weight: 1
        $x_1_2 = "Vokdasfouaoifhdas" ascii //weight: 1
        $x_1_3 = "timeGetTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

