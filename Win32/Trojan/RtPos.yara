rule Trojan_Win32_RtPos_A_2147729931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RtPos.A!MTB"
        threat_id = "2147729931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RtPos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Projects\\rt19\\Release\\rt19.pdb" ascii //weight: 1
        $x_1_2 = "vmtoolsd.exe" wide //weight: 1
        $x_1_3 = "windbg.exe" wide //weight: 1
        $x_1_4 = "ntsd.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

