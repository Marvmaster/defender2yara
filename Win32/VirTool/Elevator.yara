rule VirTool_Win32_Elevator_A_2147832008_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Elevator.A"
        threat_id = "2147832008"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Elevator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dinvoke\\src\\" ascii //weight: 1
        $x_1_2 = "rpcclient\\src\\" ascii //weight: 1
        $x_1_3 = "manualmap\\src\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

