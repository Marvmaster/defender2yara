rule VirTool_Win32_OfsBuilz_A_2147780898_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/OfsBuilz.A!MTB"
        threat_id = "2147780898"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "OfsBuilz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OffensivePipeline" ascii //weight: 1
        $x_1_2 = "OffensivePipeline.dll" ascii //weight: 1
        $x_1_3 = "hostfxr.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

