rule HackTool_Win32_PDump_A_2147826620_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PDump.A"
        threat_id = "2147826620"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\GLOBAL??\\KnownDlls" ascii //weight: 1
        $x_1_2 = "DefineDosDeviceW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

