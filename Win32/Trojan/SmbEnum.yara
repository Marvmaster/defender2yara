rule Trojan_Win32_SmbEnum_A_2147915569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmbEnum.A!MTB"
        threat_id = "2147915569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmbEnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smb/encoder/encoder.go" ascii //weight: 1
        $x_1_2 = "smb/relay.go" ascii //weight: 1
        $x_1_3 = ".NetShare" ascii //weight: 1
        $x_1_4 = "smb.(*Session).NewCreateReq" ascii //weight: 1
        $x_1_5 = "go-smb/smb.(*Connection).send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (uint16(0) == 0x5a4d) and
        (all of ($x*))
}

